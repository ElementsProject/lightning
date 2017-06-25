#include <bitcoin/address.h>
#include <bitcoin/base58.h>
#include <bitcoin/script.h>
#include <ccan/tal/str/str.h>
#include <daemon/bitcoind.h>
#include <daemon/chaintopology.h>
#include <daemon/jsonrpc.h>
#include <errno.h>
#include <lightningd/hsm/gen_hsm_wire.h>
#include <lightningd/hsm_control.h>
#include <lightningd/key_derive.h>
#include <lightningd/lightningd.h>
#include <lightningd/status.h>
#include <lightningd/subd.h>
#include <lightningd/utxo.h>
#include <lightningd/withdraw_tx.h>
#include <permute_tx.h>
#include <wally_bip32.h>
#include <wire/wire_sync.h>

struct withdrawal {
	u64 amount, changesatoshi;
	struct bitcoin_address destination;
	const struct utxo **utxos;
	u64 change_key_index;
	struct command *cmd;
	const char *hextx;
};

/**
 * wallet_extract_owned_outputs - given a tx, extract all of our outputs
 */
static int wallet_extract_owned_outputs(struct wallet *w,
					const struct bitcoin_tx *tx,
					u64 *total_satoshi)
{
	int num_utxos = 0;
	for (size_t output = 0; output < tal_count(tx->output); output++) {
		struct utxo *utxo;
		u32 index;
		bool is_p2sh;

		if (!wallet_can_spend(w, tx->output[output].script, &index, &is_p2sh))
			continue;

		utxo = tal(w, struct utxo);
		utxo->keyindex = index;
		utxo->is_p2sh = is_p2sh;
		utxo->amount = tx->output[output].amount;
		utxo->status = output_state_available;
		bitcoin_txid(tx, &utxo->txid);
		utxo->outnum = output;
		if (!wallet_add_utxo(w, utxo, p2sh_wpkh)) {
			tal_free(utxo);
			return -1;
		}
		*total_satoshi += utxo->amount;
		num_utxos++;
	}
	return num_utxos;
}

/**
 * wallet_withdrawal_broadcast - The tx has been broadcast (or it failed)
 *
 * This is the final step in the withdrawal. We either successfully
 * broadcast the withdrawal transaction or it failed somehow. So we
 * report success or a broadcast failure. Upon success we also mark
 * the used outputs as spent, and add the change output to our pool of
 * available outputs.
 */
static void wallet_withdrawal_broadcast(struct bitcoind *bitcoind,
					int exitstatus, const char *msg,
					struct withdrawal *withdraw)
{
	struct command *cmd = withdraw->cmd;
	struct lightningd *ld = ld_from_dstate(withdraw->cmd->dstate);
	struct bitcoin_tx *tx;
	u64 change_satoshi = 0;

	/* Massage output into shape so it doesn't kill the JSON serialization */
	char *output = tal_strjoin(cmd, tal_strsplit(cmd, msg, "\n", STR_NO_EMPTY), " ", STR_NO_TRAIL);
	if (exitstatus == 0) {
		/* Mark used outputs as spent */
		wallet_confirm_utxos(ld->wallet, withdraw->utxos);

		/* Parse the tx and extract the change output. We
		 * generated the hex tx, so this should always work */
		tx = bitcoin_tx_from_hex(withdraw, withdraw->hextx, strlen(withdraw->hextx));
		assert(tx != NULL);
		wallet_extract_owned_outputs(ld->wallet, tx, &change_satoshi);
		assert(change_satoshi == withdraw->changesatoshi);

		struct json_result *response = new_json_result(cmd);
		json_object_start(response, NULL);
		json_add_string(response, "tx", withdraw->hextx);
		json_add_string(response, "txid", output);
		json_object_end(response);
		command_success(cmd, response);
	} else {
		command_fail(cmd, "Error broadcasting transaction: %s", output);
	}
}

/**
 * json_withdraw - Entrypoint for the withdrawal flow
 *
 * A user has requested a withdrawal over the JSON-RPC, parse the
 * request, select coins and a change key. Then send the request to
 * the HSM to generate the signatures.
 */
static void json_withdraw(struct command *cmd,
			      const char *buffer, const jsmntok_t *params)
{
	struct lightningd *ld = ld_from_dstate(cmd->dstate);
	jsmntok_t *desttok, *sattok;
	struct withdrawal *withdraw;
	bool testnet;
	/* FIXME: Read feerate and dustlimit */
	u32 feerate_per_kw = 15000;
	//u64 dust_limit = 600;
	u64 fee_estimate;
	struct utxo *utxos;
	struct ext_key ext;
	struct pubkey changekey;
	secp256k1_ecdsa_signature *sigs;
	struct bitcoin_tx *tx;

	if (!json_get_params(buffer, params,
			     "destination", &desttok,
			     "satoshi", &sattok,
			     NULL)) {
		command_fail(cmd, "Need destination and satoshi.");
		return;
	}

	withdraw = tal(cmd, struct withdrawal);
	withdraw->cmd = cmd;

	if (!json_tok_u64(buffer, sattok, &withdraw->amount)) {
		command_fail(cmd, "Invalid satoshis");
		return;
	}
	if (!bitcoin_from_base58(&testnet, &withdraw->destination,
				 buffer + desttok->start,
				 desttok->end - desttok->start)) {
		command_fail(cmd, "Could not parse destination address");
		return;
	}

	/* Select the coins */
	withdraw->utxos = wallet_select_coins(cmd, ld->wallet, withdraw->amount,
					      feerate_per_kw, &fee_estimate,
					      &withdraw->changesatoshi);
	if (!withdraw->utxos) {
		command_fail(cmd, "Not enough funds available");
		return;
	}

	/* FIXME(cdecker) Pull this from the daemon config */
	if (withdraw->changesatoshi <= 546)
		withdraw->changesatoshi = 0;

	withdraw->change_key_index = wallet_get_newindex(ld);

	utxos = from_utxoptr_arr(withdraw, withdraw->utxos);
	u8 *msg = towire_hsmctl_sign_withdrawal(cmd,
						withdraw->amount,
						withdraw->changesatoshi,
						withdraw->change_key_index,
						withdraw->destination.addr.u.u8,
						utxos);
	tal_free(utxos);

	if (!wire_sync_write(ld->hsm_fd, take(msg)))
		fatal("Could not write sign_withdrawal to HSM: %s",
		      strerror(errno));

	msg = hsm_sync_read(cmd, ld);

	if (!fromwire_hsmctl_sign_withdrawal_reply(withdraw, msg, NULL, &sigs))
		fatal("HSM gave bad sign_withdrawal_reply %s",
		      tal_hex(withdraw, msg));

	if (bip32_key_from_parent(ld->bip32_base, withdraw->change_key_index,
                               BIP32_FLAG_KEY_PUBLIC, &ext) != WALLY_OK) {
             command_fail(cmd, "Changekey generation failure");
             return;
	}

	pubkey_from_der(ext.pub_key, sizeof(ext.pub_key), &changekey);
	tx = withdraw_tx(withdraw, withdraw->utxos, &withdraw->destination,
			 withdraw->amount, &changekey, withdraw->changesatoshi,
			 ld->bip32_base);

	if (tal_count(sigs) != tal_count(tx->input))
		fatal("HSM gave %zu sigs, needed %zu",
		      tal_count(sigs), tal_count(tx->input));

	/* Create input parts from signatures. */
	for (size_t i = 0; i < tal_count(tx->input); i++) {
		struct pubkey key;

		if (!bip32_pubkey(ld->bip32_base,
				  &key, withdraw->utxos[i]->keyindex))
			fatal("Cannot generate BIP32 key for UTXO %u",
			      withdraw->utxos[i]->keyindex);

		/* P2SH inputs have same witness. */
		tx->input[i].witness
			= bitcoin_witness_p2wpkh(tx, &sigs[i], &key);
	}

	/* Now broadcast the transaction */
	withdraw->hextx = tal_hex(withdraw, linearize_tx(cmd, tx));
	bitcoind_sendrawtx(ld->topology->bitcoind, withdraw->hextx,
			   wallet_withdrawal_broadcast, withdraw);
}

static const struct json_command withdraw_command = {
	"withdraw",
	json_withdraw,
	"Send {satoshi} to the {destination} address via Bitcoin transaction",
	"Returns the withdrawal transaction ID"
};
AUTODATA(json_command, &withdraw_command);

static void json_newaddr(struct command *cmd,
			 const char *buffer, const jsmntok_t *params)
{
	struct json_result *response = new_json_result(cmd);
	struct lightningd *ld = ld_from_dstate(cmd->dstate);
	struct ext_key ext;
	struct sha256 h;
	struct ripemd160 p2sh;
	struct pubkey pubkey;
	u8 *redeemscript;
	s64 keyidx;

	keyidx = wallet_get_newindex(ld);
	if (keyidx < 0) {
		command_fail(cmd, "Keys exhausted ");
		return;
	}

	if (bip32_key_from_parent(ld->bip32_base, keyidx,
				  BIP32_FLAG_KEY_PUBLIC, &ext) != WALLY_OK) {
		command_fail(cmd, "Keys generation failure");
		return;
	}

	if (!secp256k1_ec_pubkey_parse(secp256k1_ctx, &pubkey.pubkey,
				       ext.pub_key, sizeof(ext.pub_key))) {
		command_fail(cmd, "Key parsing failure");
		return;
	}

	redeemscript = bitcoin_redeem_p2sh_p2wpkh(cmd, &pubkey);
	sha256(&h, redeemscript, tal_count(redeemscript));
	ripemd160(&p2sh, h.u.u8, sizeof(h));

	json_object_start(response, NULL);
	json_add_string(response, "address",
			p2sh_to_base58(cmd, cmd->dstate->testnet, &p2sh));
	json_object_end(response);
	command_success(cmd, response);
}

static const struct json_command newaddr_command = {
	"newaddr",
	json_newaddr,
	"Get a new address to fund a channel",
	"Returns {address} a p2sh address"
};
AUTODATA(json_command, &newaddr_command);

static void json_addfunds(struct command *cmd,
			  const char *buffer, const jsmntok_t *params)
{
	struct lightningd *ld = ld_from_dstate(cmd->dstate);
	struct json_result *response = new_json_result(cmd);
	jsmntok_t *txtok;
	struct bitcoin_tx *tx;
	size_t txhexlen;
	int num_utxos = 0;
	u64 total_satoshi = 0;

	if (!json_get_params(buffer, params, "tx", &txtok, NULL)) {
		command_fail(cmd, "Need tx sending to address from newaddr");
		return;
	}

	txhexlen = txtok->end - txtok->start;
	tx = bitcoin_tx_from_hex(cmd, buffer + txtok->start, txhexlen);
	if (!tx) {
		command_fail(cmd, "'%.*s' is not a valid transaction",
			     txtok->end - txtok->start,
			     buffer + txtok->start);
		return;
	}

	/* Find an output we know how to spend. */
	num_utxos =
	    wallet_extract_owned_outputs(ld->wallet, tx, &total_satoshi);
	if (num_utxos < 0) {
		command_fail(cmd, "Could add outputs to wallet");
		return;
	} else if (!num_utxos) {
		command_fail(cmd, "No usable outputs");
		return;
	}

	json_object_start(response, NULL);
	json_add_num(response, "outputs", num_utxos);
	json_add_u64(response, "satoshis", total_satoshi);
	json_object_end(response);
	command_success(cmd, response);
}

static const struct json_command addfunds_command = {
	"addfunds",
	json_addfunds,
	"Add funds for lightningd to spend to create channels, using {tx}",
	"Returns how many {outputs} it can use and total {satoshis}"
};
AUTODATA(json_command, &addfunds_command);
