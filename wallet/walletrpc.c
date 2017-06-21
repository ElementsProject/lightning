#include <bitcoin/address.h>
#include <bitcoin/base58.h>
#include <bitcoin/script.h>
#include <ccan/tal/str/str.h>
#include <daemon/bitcoind.h>
#include <daemon/chaintopology.h>
#include <daemon/jsonrpc.h>
#include <lightningd/hsm/gen_hsm_wire.h>
#include <lightningd/key_derive.h>
#include <lightningd/lightningd.h>
#include <lightningd/subd.h>
#include <lightningd/utxo.h>
#include <lightningd/withdraw_tx.h>
#include <permute_tx.h>
#include <wally_bip32.h>

struct withdrawal {
	u64 amount, changesatoshi;
	struct bitcoin_address destination;
	const struct utxo **utxos;
	u64 change_key_index;
	struct command *cmd;
	const char *hextx;
};

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

	/* Massage output into shape so it doesn't kill the JSON serialization */
	char *output = tal_strjoin(cmd, tal_strsplit(cmd, msg, "\n", STR_NO_EMPTY), " ", STR_NO_TRAIL);
	if (exitstatus == 0) {
		wallet_confirm_utxos(ld->wallet, withdraw->utxos);
		/* TODO(cdecker) Add the change output to the database */
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
 * wallet_withdrawal_signed - The HSM has signed our withdrawal request
 *
 * This is the second step (2/3) of the withdrawal flow. The HSM has
 * returned the necessary signatures for the withdrawal transaction,
 * so now we can assemble the transaction and kick off the broadcast.
 */
static bool wallet_withdrawal_signed(struct subd *hsm, const u8 *reply,
				     const int *fds,
				     struct withdrawal *withdraw)
{
	struct command *cmd = withdraw->cmd;
	struct lightningd *ld = ld_from_dstate(cmd->dstate);
	struct ext_key ext;
	struct pubkey changekey;
	secp256k1_ecdsa_signature *sigs;
	struct bitcoin_tx *tx;

	if (!fromwire_hsmctl_sign_withdrawal_reply(withdraw, reply, NULL, &sigs))
		fatal("HSM gave bad sign_withdrawal_reply %s",
		      tal_hex(withdraw, reply));

	if (bip32_key_from_parent(ld->bip32_base, withdraw->change_key_index,
                               BIP32_FLAG_KEY_PUBLIC, &ext) != WALLY_OK) {
             command_fail(cmd, "Changekey generation failure");
             return true;
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

		if (!bip32_pubkey(hsm->ld->bip32_base,
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
	return true;
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

	withdraw->change_key_index =
	    db_get_intvar(ld->wallet->db, "bip32_max_index", 0) + 1;
	db_set_intvar(ld->wallet->db, "bip32_max_index",
		      withdraw->change_key_index);

	utxos = from_utxoptr_arr(withdraw, withdraw->utxos);
	u8 *msg = towire_hsmctl_sign_withdrawal(cmd,
						withdraw->amount,
						withdraw->changesatoshi,
						withdraw->change_key_index,
						withdraw->destination.addr.u.u8,
						utxos);
	subd_req(cmd, ld->hsm, take(msg), -1, 0, wallet_withdrawal_signed,
		 withdraw);
	tal_free(utxos);
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
	u64 bip32_max_index = db_get_intvar(ld->wallet->db, "bip32_max_index", 0);

	if (bip32_max_index == BIP32_INITIAL_HARDENED_CHILD) {
		command_fail(cmd, "Keys exhausted ");
		return;
	}

	if (bip32_key_from_parent(ld->bip32_base, bip32_max_index,
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

	db_set_intvar(ld->wallet->db, "bip32_max_index", bip32_max_index + 1);

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
