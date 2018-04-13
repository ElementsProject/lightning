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
#include <lightningd/json.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/lightningd.h>
#include <lightningd/log.h>
#include <lightningd/peer_control.h>
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
static void wallet_withdrawal_broadcast(struct bitcoind *bitcoind UNUSED,
					int exitstatus, const char *msg,
					struct withdrawal *withdraw)
{
	struct command *cmd = withdraw->cmd;
	struct lightningd *ld = withdraw->cmd->ld;
	u64 change_satoshi = 0;

	/* Massage output into shape so it doesn't kill the JSON serialization */
	char *output = tal_strjoin(cmd, tal_strsplit(cmd, msg, "\n", STR_NO_EMPTY), " ", STR_NO_TRAIL);
	if (exitstatus == 0) {
		/* Mark used outputs as spent */
		wallet_confirm_utxos(ld->wallet, withdraw->utxos);

		/* Parse the tx and extract the change output. We
		 * generated the hex tx, so this should always work */
		struct bitcoin_tx *tx = bitcoin_tx_from_hex(withdraw, withdraw->hextx, strlen(withdraw->hextx));
		assert(tx != NULL);
		wallet_extract_owned_outputs(ld->wallet, tx, NULL, &change_satoshi);

		/* Note normally, change_satoshi == withdraw->changesatoshi, but
		 * not if we're actually making a payment to ourselves! */
		assert(change_satoshi >= withdraw->changesatoshi);

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
	jsmntok_t *desttok, *sattok;
	struct withdrawal *withdraw;
	u32 feerate_per_kw = get_feerate(cmd->ld->topology, FEERATE_NORMAL);
	u64 fee_estimate;
	struct bitcoin_tx *tx;
	bool all_funds = false;
	enum address_parse_result addr_parse;

	if (!json_get_params(cmd, buffer, params,
			     "destination", &desttok,
			     "satoshi", &sattok,
			     NULL)) {
		return;
	}

	withdraw = tal(cmd, struct withdrawal);
	withdraw->cmd = cmd;

	if (json_tok_streq(buffer, sattok, "all"))
		all_funds = true;
	else if (!json_tok_u64(buffer, sattok, &withdraw->amount)) {
		command_fail(cmd, "Invalid satoshis");
		return;
	}

	/* Parse address. */
	addr_parse = json_tok_address_scriptpubkey(cmd,
						   get_chainparams(cmd->ld),
						   buffer, desttok,
						   (const u8**)(&withdraw->destination));

	/* Check that destination address could be understood. */
	if (addr_parse == ADDRESS_PARSE_UNRECOGNIZED) {
		command_fail(cmd, "Could not parse destination address");
		return;
	}

	/* Check address given is compatible with the chain we are on. */
	if (addr_parse == ADDRESS_PARSE_WRONG_NETWORK) {
		command_fail(cmd,
			    "Destination address is not on network %s",
			    get_chainparams(cmd->ld)->network_name);
		return;
	}

	/* Select the coins */
	if (all_funds) {
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

	u8 *msg = towire_hsm_sign_withdrawal(cmd,
					     withdraw->amount,
					     withdraw->changesatoshi,
					     withdraw->change_key_index,
					     withdraw->destination,
					     withdraw->utxos);

	if (!wire_sync_write(cmd->ld->hsm_fd, take(msg)))
		fatal("Could not write sign_withdrawal to HSM: %s",
		      strerror(errno));

	msg = hsm_sync_read(cmd, cmd->ld);

	if (!fromwire_hsm_sign_withdrawal_reply(msg, msg, &tx))
		fatal("HSM gave bad sign_withdrawal_reply %s",
		      tal_hex(withdraw, msg));

	/* Now broadcast the transaction */
	withdraw->hextx = tal_hex(withdraw, linearize_tx(cmd, tx));
	bitcoind_sendrawtx(cmd->ld->topology->bitcoind, withdraw->hextx,
			   wallet_withdrawal_broadcast, withdraw);
	command_still_pending(cmd);
}

static const struct json_command withdraw_command = {
	"withdraw",
	json_withdraw,
	"Send to {destination} address {satoshi} (or 'all') amount via Bitcoin transaction",
	false, "Send funds from the internal wallet to the specified address. Either specify a number of satoshis to send or 'all' to sweep all funds in the internal wallet to the address."
};
AUTODATA(json_command, &withdraw_command);

static void json_newaddr(struct command *cmd, const char *buffer UNUSED,
			 const jsmntok_t *params UNUSED)
{
	struct json_result *response = new_json_result(cmd);
	struct ext_key ext;
	struct sha256 h;
	struct ripemd160 h160;
	struct pubkey pubkey;
	jsmntok_t *addrtype;
	bool is_p2wpkh;
	s64 keyidx;
	char *out;

	if (!json_get_params(cmd, buffer, params,
			     "?addresstype", &addrtype, NULL)) {
		return;
	}

	if (!addrtype || json_tok_streq(buffer, addrtype, "p2sh-segwit"))
		is_p2wpkh = false;
	else if (json_tok_streq(buffer, addrtype, "bech32"))
		is_p2wpkh = true;
	else {
		command_fail(cmd,
			     "Invalid address type "
			     "(expected bech32 or p2sh-segwit)");
		return;
	}

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

	if (is_p2wpkh) {
		const char *hrp = get_chainparams(cmd->ld)->bip173_name;
		/* out buffer is 73 + strlen(human readable part). see bech32.h */
		out = tal_arr(cmd, char, 73 + strlen(hrp));
		pubkey_to_hash160(&pubkey, &h160);
		bool ok = segwit_addr_encode(out, hrp, 0, h160.u.u8, sizeof(h160.u.u8));
		if (!ok) {
			command_fail(cmd, "p2wpkh address encoding failure.");
			return;
		}
	}
	else {
		u8 *redeemscript = bitcoin_redeem_p2sh_p2wpkh(cmd, &pubkey);
		sha256(&h, redeemscript, tal_count(redeemscript));
		ripemd160(&h160, h.u.u8, sizeof(h));
		out = p2sh_to_base58(cmd,
				     get_chainparams(cmd->ld)->testnet, &h160);
	}

	json_object_start(response, NULL);
	json_add_string(response, "address", out);
	json_object_end(response);
	command_success(cmd, response);
}

static const struct json_command newaddr_command = {
	"newaddr",
	json_newaddr,
	"Get a new {bech32, p2sh-segwit} address to fund a channel", false,
	"Generates a new address that belongs to the internal wallet. Funds sent to these addresses will be managed by lightningd. Use `withdraw` to withdraw funds to an external wallet."
};
AUTODATA(json_command, &newaddr_command);

static void json_listaddrs(struct command *cmd,
						   const char *buffer, const jsmntok_t *params)
{
	struct json_result *response = new_json_result(cmd);
	struct ext_key ext;
	struct sha256 h;
	struct ripemd160 h160;
	struct pubkey pubkey;
	jsmntok_t *bip32tok;
	u64 bip32_max_index;

	if (!json_get_params(cmd, buffer, params,
			     "?bip32_max_index", &bip32tok,
			     NULL)) {
		return;
	}

	if (!bip32tok || !json_tok_u64(buffer, bip32tok, &bip32_max_index)) {
		bip32_max_index = db_get_intvar(cmd->ld->wallet->db, "bip32_max_index", 0);
	}
	json_object_start(response, NULL);
	json_array_start(response, "addresses");

	for (s64 keyidx = 0; keyidx <= bip32_max_index; keyidx++) {

		if(keyidx == BIP32_INITIAL_HARDENED_CHILD){
			break;
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

		// p2sh
		u8 *redeemscript = bitcoin_redeem_p2sh_p2wpkh(cmd, &pubkey);
		sha256(&h, redeemscript, tal_count(redeemscript));
		ripemd160(&h160, h.u.u8, sizeof(h));
		char *out_p2sh = p2sh_to_base58(cmd,
								  get_chainparams(cmd->ld)->testnet, &h160);

		// bech32 : p2wpkh
		const char *hrp = get_chainparams(cmd->ld)->bip173_name;
		/* out buffer is 73 + strlen(human readable part). see bech32.h */
		char *out_p2wpkh = tal_arr(cmd, char, 73 + strlen(hrp));
		pubkey_to_hash160(&pubkey, &h160);
		bool ok = segwit_addr_encode(out_p2wpkh, hrp, 0, h160.u.u8, sizeof(h160.u.u8));
		if (!ok) {
			command_fail(cmd, "p2wpkh address encoding failure.");
			return;
		}

		// outputs
		json_object_start(response, NULL);
		json_add_u64(response, "keyidx", keyidx);
		json_add_pubkey(response, "pubkey", &pubkey);
		json_add_string(response, "p2sh", out_p2sh);
		json_add_hex(response, "p2sh_redeemscript", redeemscript, tal_count(redeemscript));
		json_add_string(response, "bech32", out_p2wpkh);
		json_add_hex(response, "bech32_redeemscript", &h160.u.u8, sizeof(struct ripemd160));
		json_object_end(response);
	}
	json_array_end(response);
	json_object_end(response);
	command_success(cmd, response);
}

static const struct json_command listaddrs_command = {
	"dev-listaddrs",
	json_listaddrs,
	"Show addresses list up to derivation {index} (default is the last bip32 index)", false,
	"Show addresses of your internal wallet. Use `newaddr` to generate a new address."
};
AUTODATA(json_command, &listaddrs_command);

static void json_listfunds(struct command *cmd, const char *buffer UNUSED,
			   const jsmntok_t *params UNUSED)
{
	struct json_result *response = new_json_result(cmd);
	struct peer *p;
	struct utxo **utxos =
	    wallet_get_utxos(cmd, cmd->ld->wallet, output_state_available);
	char* out;
	struct ripemd160 h160;
	struct pubkey funding_pubkey;
	json_object_start(response, NULL);
	json_array_start(response, "outputs");
	for (size_t i = 0; i < tal_count(utxos); i++) {
		json_object_start(response, NULL);
		json_add_txid(response, "txid", &utxos[i]->txid);
		json_add_num(response, "output", utxos[i]->outnum);
		json_add_u64(response, "value", utxos[i]->amount);

		/* @close_info is for outputs that are not yet claimable */
		if (utxos[i]->close_info == NULL) {
			bip32_pubkey(cmd->ld->wallet->bip32_base, &funding_pubkey,
				     utxos[i]->keyindex);
			pubkey_to_hash160(&funding_pubkey, &h160);
			if (utxos[i]->is_p2sh) {
					out = p2sh_to_base58(cmd,
					get_chainparams(cmd->ld)->testnet, &h160);
			} else {
				const char *hrp = get_chainparams(cmd->ld)->bip173_name;
				/* out buffer is 73 + strlen(human readable part). see bech32.h */
				out = tal_arr(cmd, char, 73 + strlen(hrp));
				bool ok = segwit_addr_encode(out, hrp, 0, h160.u.u8, sizeof(h160.u.u8));
				if (!ok) {
					command_fail(cmd, "p2wpkh address encoding failure.");
					return;
				}
			}
		        json_add_string(response, "address", out);
		}
		if (utxos[i]->spendheight)
			json_add_string(response, "status", "spent");
		else if (utxos[i]->blockheight)
			json_add_string(response, "status", "confirmed");
		else
			json_add_string(response, "status", "unconfirmed");

		json_object_end(response);
	}
	json_array_end(response);

	/* Add funds that are allocated to channels */
	json_array_start(response, "channels");
	list_for_each(&cmd->ld->peers, p, list) {
		struct channel *c;
		list_for_each(&p->channels, c, list) {
			json_object_start(response, NULL);
			json_add_pubkey(response, "peer_id", &p->id);
			if (c->scid)
				json_add_short_channel_id(response,
							  "short_channel_id",
							  c->scid);

			/* Poor man's rounding to satoshis to match the unit for outputs */
			json_add_u64(response, "channel_sat",
				     (c->our_msatoshi + 500)/1000);
			json_add_u64(response, "channel_total_sat",
				     c->funding_satoshi);
			json_add_txid(response, "funding_txid",
				      &c->funding_txid);
			json_object_end(response);
		}
	}
	json_array_end(response);
	json_object_end(response);

	command_success(cmd, response);
}

static const struct json_command listfunds_command = {
	"listfunds",
	json_listfunds,
	"Show available funds from the internal wallet", false,
	"Returns a list of funds (outputs) that can be used by the internal wallet to open new channels or can be withdrawn, using the `withdraw` command, to another wallet."
};
AUTODATA(json_command, &listfunds_command);

struct txo_rescan {
	struct command *cmd;
	struct utxo **utxos;
	struct json_result *response;
};

static void process_utxo_result(struct bitcoind *bitcoind,
				const struct bitcoin_tx_output *txout,
				void *arg)
{
	struct txo_rescan *rescan = arg;
	struct json_result *response = rescan->response;
	struct utxo *u = rescan->utxos[0];
	enum output_status newstate =
	    txout == NULL ? output_state_spent : output_state_available;

	json_object_start(rescan->response, NULL);
	json_add_txid(response, "txid", &u->txid);
	json_add_num(response, "output", u->outnum);
	json_add_num(response, "oldstate", u->status);
	json_add_num(response, "newstate", newstate);
	json_object_end(rescan->response);
	wallet_update_output_status(bitcoind->ld->wallet, &u->txid, u->outnum,
				    u->status, newstate);

	/* Remove the utxo we just resolved */
	rescan->utxos[0] = rescan->utxos[tal_count(rescan->utxos) - 1];
	tal_resize(&rescan->utxos, tal_count(rescan->utxos) - 1);

	if (tal_count(rescan->utxos) == 0) {
		/* Complete the response */
		json_array_end(rescan->response);
		json_object_end(rescan->response);
		command_success(rescan->cmd, rescan->response);
	} else {
		bitcoind_gettxout(
		    bitcoind->ld->topology->bitcoind, &rescan->utxos[0]->txid,
		    rescan->utxos[0]->outnum, process_utxo_result, rescan);
	}
}

static void json_dev_rescan_outputs(struct command *cmd,
				    const char *buffer UNUSED,
				    const jsmntok_t *params UNUSED)
{
	struct txo_rescan *rescan = tal(cmd, struct txo_rescan);
	rescan->response = new_json_result(cmd);
	rescan->cmd = cmd;

	/* Open the result structure so we can incrementally add results */
	json_object_start(rescan->response, NULL);
	json_array_start(rescan->response, "outputs");
	rescan->utxos = wallet_get_utxos(rescan, cmd->ld->wallet, output_state_any);
	if (tal_count(rescan->utxos) == 0) {
		json_array_end(rescan->response);
		json_object_end(rescan->response);
		command_success(cmd, rescan->response);
		return;
	}
	bitcoind_gettxout(cmd->ld->topology->bitcoind, &rescan->utxos[0]->txid,
			  rescan->utxos[0]->outnum, process_utxo_result,
			  rescan);
	command_still_pending(cmd);
}

static const struct json_command dev_rescan_output_command = {
    "dev-rescan-outputs", json_dev_rescan_outputs,
    "Synchronize the state of our funds with bitcoind", false,
    "For each output stored in the internal wallet ask `bitcoind` whether we are in sync with its state (spent vs. unspent)"
};
AUTODATA(json_command, &dev_rescan_output_command);
