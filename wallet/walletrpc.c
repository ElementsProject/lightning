#include <bitcoin/address.h>
#include <bitcoin/base58.h>
#include <bitcoin/script.h>
#include <ccan/tal/str/str.h>
#include <common/bech32.h>
#include <common/key_derive.h>
#include <common/status.h>
#include <common/utxo.h>
#include <common/withdraw_tx.h>
#include <errno.h>
#include <hsmd/gen_hsm_client_wire.h>
#include <inttypes.h>
#include <lightningd/bitcoind.h>
#include <lightningd/chaintopology.h>
#include <lightningd/hsm_control.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/lightningd.h>
#include <lightningd/log.h>
#include <lightningd/subd.h>
#include <wally_bip32.h>
#include <wire/wire_sync.h>

struct withdrawal {
	u64 amount, changesatoshi;
	u8 *destination;
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
	struct lightningd *ld = withdraw->cmd->ld;
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
 * segwit_addr_net_decode - Try to decode a Bech32 address and detect
 * testnet/mainnet
 *
 * This processes the address and returns true if it is a Bech32
 * address specified by BIP173. If it returns true, then *testnet is
 * set whether it is testnet "tb" address or false if mainnet "bc"
 * address. It does not check, witness version and program size
 * restrictions.
 *
 *  Out: testnet:  Pointer to a bool that will be updated to true if the
 *                 address is testnet, or false if mainnet.
 *       witness_version: Pointer to an int that will be updated to contain
 *                 the witness program version (between 0 and 16 inclusive).
 *       witness_program: Pointer to a buffer of size 40 that will be updated
 *                 to contain the witness program bytes.
 *       witness_program_len: Pointer to a size_t that will be updated to
 *                 contain the length of bytes in witness_program.
 *  In:  addrz:    Pointer to the null-terminated address.
 *  Returns true if successful, false if fail (on fail, none of the out
 *  parameters are modified).
 */
static bool segwit_addr_net_decode(bool *testnet, int *witness_version,
				   uint8_t *witness_program,
				   size_t *witness_program_len,
				   const char *addrz)
{
	/* segwit_addr_decode itself expects a prog buffer (which we pass
	 * witness_program as) of size 40, so segwit_addr_net_decode
	 * inherits that requirement. It will not write to that buffer
	 * if the input address is too long, so no buffer overflow risk. */
	if (segwit_addr_decode(witness_version,
			       witness_program, witness_program_len,
			       "bc", addrz)) {
		*testnet = false;
		return true;
	} else if (segwit_addr_decode(witness_version,
				      witness_program, witness_program_len,
				      "tb", addrz)) {
		*testnet = true;
		return true;
	}
	return false;
}

/**
 * scriptpubkey_from_address - Determine scriptpubkey from a given address
 *
 * This processes the address and returns the equivalent scriptpubkey
 * for the address. If fail to parse the address, return NULL. If can
 * parse address, also sets the testnet flag if address is a testnet
 * address or clears it if mainnet.
 */
static u8 *scriptpubkey_from_address(const tal_t *cxt, bool *testnet,
				     const char *addr, size_t addrlen)
{
	struct bitcoin_address p2pkh_destination;
	struct ripemd160 p2sh_destination;
	int witness_version;
	/* segwit_addr_net_decode requires a buffer of size 40, and will
	 * not write to the buffer if the address is too long, so a buffer
	 * of fixed size 40 will not overflow. */
	uint8_t witness_program[40];
	size_t witness_program_len;
	bool witness_ok;
	u8 *script = NULL;

	char *addrz;
	bool my_testnet;

	if (bitcoin_from_base58(testnet, &p2pkh_destination,
				addr, addrlen)) {
		script = scriptpubkey_p2pkh(cxt, &p2pkh_destination);
	} else if (p2sh_from_base58(testnet, &p2sh_destination,
				    addr, addrlen)) {
		script = scriptpubkey_p2sh_hash(cxt, &p2sh_destination);
	}
	/* Insert other parsers that accept pointer+len here. */

	if (script) return script;

	/* Generate null-terminated address. */
	addrz = tal_dup_arr(cxt, char, addr, addrlen, 1);
	addrz[addrlen] = '\0';

	if (segwit_addr_net_decode(&my_testnet, &witness_version,
				   witness_program, &witness_program_len,
				   addrz)) {
		witness_ok = false;
		if (witness_version == 0 && (witness_program_len == 20 ||
					     witness_program_len == 32)) {
			witness_ok = true;
		}
		/* Insert other witness versions here. */
		if (witness_ok) {
			*testnet = my_testnet;
			script = scriptpubkey_witness_raw(cxt, witness_version,
							  witness_program,
							  witness_program_len);
		}
	}
	/* Insert other parsers that accept null-terminated string here. */

	tal_free(addrz);
	return script;
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
	jsmntok_t *desttok, *sattok;
	struct withdrawal *withdraw;
	bool testnet;
	u32 feerate_per_kw = get_feerate(cmd->ld->topology, FEERATE_NORMAL);
	u64 fee_estimate;
	struct utxo *utxos;
	struct ext_key ext;
	struct pubkey changekey;
	secp256k1_ecdsa_signature *sigs;
	struct bitcoin_tx *tx;
	bool withdraw_all = false;

	if (!json_get_params(buffer, params,
			     "destination", &desttok,
			     "satoshi", &sattok,
			     NULL)) {
		command_fail(cmd, "Need destination and satoshi.");
		return;
	}

	withdraw = tal(cmd, struct withdrawal);
	withdraw->cmd = cmd;

	if (json_tok_streq(buffer, sattok, "all"))
		withdraw_all = true;
	else if (!json_tok_u64(buffer, sattok, &withdraw->amount)) {
		command_fail(cmd, "Invalid satoshis");
		return;
	}

	/* Parse address. */
	withdraw->destination
		= scriptpubkey_from_address(withdraw, &testnet,
					    buffer + desttok->start,
					    desttok->end - desttok->start);

	/* Check that destination address could be understood. */
	if (!withdraw->destination) {
		command_fail(cmd, "Could not parse destination address");
		return;
	}

	/* Check address given is compatible with the chain we are on. */
	if (testnet != get_chainparams(cmd->ld)->testnet) {
		if (testnet) {
			command_fail(cmd,
				    "Use of testnet address on mainnet");
		} else {
			command_fail(cmd,
				    "Use of mainnet address on testnet");
		}
		return;
	}

	/* Select the coins */
	if (withdraw_all) {
		withdraw->utxos = wallet_select_all(cmd, cmd->ld->wallet,
						    feerate_per_kw,
						    tal_len(withdraw->destination),
						    &withdraw->amount,
						    &fee_estimate);
		/* FIXME Pull dust amount from the daemon config */
		if (!withdraw->utxos || withdraw->amount < 546) {
			command_fail(cmd, "Cannot afford fee %"PRIu64,
				     fee_estimate);
			return;
		}
		withdraw->changesatoshi = 0;
	} else {
		withdraw->utxos = wallet_select_coins(cmd, cmd->ld->wallet,
						      withdraw->amount,
						      feerate_per_kw,
						      tal_len(withdraw->destination),
						      &fee_estimate,
						      &withdraw->changesatoshi);
		if (!withdraw->utxos) {
			command_fail(cmd, "Not enough funds available");
			return;
		}
	}

	/* FIXME(cdecker) Pull this from the daemon config */
	if (withdraw->changesatoshi <= 546)
		withdraw->changesatoshi = 0;

	if (withdraw->changesatoshi)
		withdraw->change_key_index = wallet_get_newindex(cmd->ld);
	else
		withdraw->change_key_index = 0;

	utxos = from_utxoptr_arr(withdraw, withdraw->utxos);
	u8 *msg = towire_hsm_sign_withdrawal(cmd,
					     withdraw->amount,
					     withdraw->changesatoshi,
					     withdraw->change_key_index,
					     withdraw->destination,
					     utxos);
	tal_free(utxos);

	if (!wire_sync_write(cmd->ld->hsm_fd, take(msg)))
		fatal("Could not write sign_withdrawal to HSM: %s",
		      strerror(errno));

	msg = hsm_sync_read(cmd, cmd->ld);

	if (!fromwire_hsm_sign_withdrawal_reply(withdraw, msg, NULL, &sigs))
		fatal("HSM gave bad sign_withdrawal_reply %s",
		      tal_hex(withdraw, msg));

	if (withdraw->changesatoshi) {
		if (bip32_key_from_parent(cmd->ld->wallet->bip32_base,
					  withdraw->change_key_index,
					  BIP32_FLAG_KEY_PUBLIC, &ext)
		    != WALLY_OK) {
			command_fail(cmd, "Changekey generation failure");
			return;
		}

		pubkey_from_der(ext.pub_key, sizeof(ext.pub_key), &changekey);
	}
	tx = withdraw_tx(withdraw, withdraw->utxos, withdraw->destination,
			 withdraw->amount, &changekey, withdraw->changesatoshi,
			 cmd->ld->wallet->bip32_base);

	if (tal_count(sigs) != tal_count(tx->input))
		fatal("HSM gave %zu sigs, needed %zu",
		      tal_count(sigs), tal_count(tx->input));

	/* Create input parts from signatures. */
	for (size_t i = 0; i < tal_count(tx->input); i++) {
		struct pubkey key;

		if (!bip32_pubkey(cmd->ld->wallet->bip32_base,
				  &key, withdraw->utxos[i]->keyindex))
			fatal("Cannot generate BIP32 key for UTXO %u",
			      withdraw->utxos[i]->keyindex);

		/* P2SH inputs have same witness. */
		tx->input[i].witness
			= bitcoin_witness_p2wpkh(tx, &sigs[i], &key);
	}

	/* Now broadcast the transaction */
	withdraw->hextx = tal_hex(withdraw, linearize_tx(cmd, tx));
	bitcoind_sendrawtx(cmd->ld->topology->bitcoind, withdraw->hextx,
			   wallet_withdrawal_broadcast, withdraw);
}

static const struct json_command withdraw_command = {
	"withdraw",
	json_withdraw,
	"Send {satoshi} (or 'all') to the {destination} address via Bitcoin transaction",
	"Returns the withdrawal transaction ID"
};
AUTODATA(json_command, &withdraw_command);

static void json_newaddr(struct command *cmd,
			 const char *buffer, const jsmntok_t *params)
{
	struct json_result *response = new_json_result(cmd);
	struct ext_key ext;
	struct sha256 h;
	struct ripemd160 p2sh;
	struct pubkey pubkey;
	u8 *redeemscript;
	s64 keyidx;

	keyidx = wallet_get_newindex(cmd->ld);
	if (keyidx < 0) {
		command_fail(cmd, "Keys exhausted ");
		return;
	}

	if (bip32_key_from_parent(cmd->ld->wallet->bip32_base, keyidx,
				  BIP32_FLAG_KEY_PUBLIC, &ext) != WALLY_OK) {
		command_fail(cmd, "Keys generation failure");
		return;
	}

	if (!secp256k1_ec_pubkey_parse(secp256k1_ctx, &pubkey.pubkey,
				       ext.pub_key, sizeof(ext.pub_key))) {
		command_fail(cmd, "Key parsing failure");
		return;
	}

	txfilter_add_derkey(cmd->ld->owned_txfilter, ext.pub_key);

	redeemscript = bitcoin_redeem_p2sh_p2wpkh(cmd, &pubkey);
	sha256(&h, redeemscript, tal_count(redeemscript));
	ripemd160(&p2sh, h.u.u8, sizeof(h));

	json_object_start(response, NULL);
	json_add_string(response, "address",
			p2sh_to_base58(cmd, get_chainparams(cmd->ld)->testnet,
				       &p2sh));
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
	    wallet_extract_owned_outputs(cmd->ld->wallet, tx, &total_satoshi);
	if (num_utxos < 0) {
		command_fail(cmd, "Could not add outputs to wallet");
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

static void json_listfunds(struct command *cmd, const char *buffer,
			   const jsmntok_t *params)
{
	struct json_result *response = new_json_result(cmd);
	struct utxo **utxos =
	    wallet_get_utxos(cmd, cmd->ld->wallet, output_state_available);
	json_object_start(response, NULL);
	json_array_start(response, "outputs");
	for (int i = 0; i < tal_count(utxos); i++) {
		json_object_start(response, NULL);
		json_add_hex(response, "txid", &utxos[i]->txid,
			     sizeof(struct sha256_double));
		json_add_num(response, "output", utxos[i]->outnum);
		json_add_u64(response, "value", utxos[i]->amount);
		json_object_end(response);
	}
	json_array_end(response);
	json_object_end(response);
	command_success(cmd, response);
}

static const struct json_command listfunds_command = {
    "listfunds", json_listfunds,
    "List funds available to the daemon to open channels",
    "Returns an array of available outputs"};
AUTODATA(json_command, &listfunds_command);
