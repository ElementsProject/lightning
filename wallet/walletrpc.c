#include <bitcoin/address.h>
#include <bitcoin/base58.h>
#include <bitcoin/script.h>
#include <ccan/tal/str/str.h>
#include <common/addr.h>
#include <common/bech32.h>
#include <common/json_command.h>
#include <common/json_helpers.h>
#include <common/jsonrpc_errors.h>
#include <common/key_derive.h>
#include <common/param.h>
#include <common/status.h>
#include <common/utxo.h>
#include <common/wallet_tx.h>
#include <common/withdraw_tx.h>
#include <errno.h>
#include <hsmd/gen_hsm_wire.h>
#include <inttypes.h>
#include <lightningd/bitcoind.h>
#include <lightningd/chaintopology.h>
#include <lightningd/channel.h>
#include <lightningd/channel_state.h>
#include <lightningd/hsm_control.h>
#include <lightningd/json.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/lightningd.h>
#include <lightningd/log.h>
#include <lightningd/options.h>
#include <lightningd/peer_control.h>
#include <lightningd/subd.h>
#include <wallet/wallet.h>
#include <wally_bip32.h>
#include <wire/wire_sync.h>

struct withdrawal {
	struct command *cmd;
	struct wallet_tx *wtx;
	u8 *destination;
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
					struct unreleased_tx *utx)
{
	struct command *cmd = utx->wtx->cmd;
	struct lightningd *ld = cmd->ld;
	struct amount_sat change = AMOUNT_SAT(0);

	/* FIXME: This won't be necessary once we use ccan/json_out! */
	/* Massage output into shape so it doesn't kill the JSON serialization */
	char *output = tal_strjoin(cmd, tal_strsplit(cmd, msg, "\n", STR_NO_EMPTY), " ", STR_NO_TRAIL);
	if (exitstatus == 0) {
		/* Mark used outputs as spent */
		wallet_confirm_utxos(ld->wallet, utx->wtx->utxos);

		/* Extract the change output and add it to the DB */
		wallet_extract_owned_outputs(ld->wallet, utx->tx, NULL, &change);

		/* Note normally, change_satoshi == withdraw->wtx->change, but
		 * not if we're actually making a payment to ourselves! */
		assert(amount_sat_greater_eq(change, utx->wtx->change));

		struct json_stream *response = json_stream_success(cmd);
		json_add_tx(response, "tx", utx->tx);
		json_add_string(response, "txid", output);
		was_pending(command_success(cmd, response));
	} else {
		was_pending(command_fail(cmd, LIGHTNINGD,
					 "Error broadcasting transaction: %s",
					 output));
	}
}

static struct command_result *param_bitcoin_address(struct command *cmd,
						    const char *name,
						    const char *buffer,
						    const jsmntok_t *tok,
						    const u8 **scriptpubkey)
{
	/* Parse address. */
	switch (json_tok_address_scriptpubkey(cmd,
					      get_chainparams(cmd->ld),
					      buffer, tok,
					      scriptpubkey)) {
	case ADDRESS_PARSE_UNRECOGNIZED:
		return command_fail(cmd, LIGHTNINGD,
				    "Could not parse destination address");
	case ADDRESS_PARSE_WRONG_NETWORK:
		return command_fail(cmd, LIGHTNINGD,
				    "Destination address is not on network %s",
				    get_chainparams(cmd->ld)->network_name);
	case ADDRESS_PARSE_SUCCESS:
		return NULL;
	}
	abort();
}

/* Signs the tx, broadcasts it: broadcast calls wallet_withdrawal_broadcast */
static struct command_result *broadcast_and_wait(struct command *cmd,
						 struct unreleased_tx *utx)
{
	struct bitcoin_tx *signed_tx;
	struct bitcoin_txid signed_txid;

	/* FIXME: hsm will sign almost anything, but it should really
	 * fail cleanly (not abort!) and let us report the error here. */
	u8 *msg = towire_hsm_sign_withdrawal(cmd,
					     utx->wtx->amount,
					     utx->wtx->change,
					     utx->wtx->change_key_index,
					     utx->destination,
					     utx->wtx->utxos);

	if (!wire_sync_write(cmd->ld->hsm_fd, take(msg)))
		fatal("Could not write sign_withdrawal to HSM: %s",
		      strerror(errno));

	msg = wire_sync_read(cmd, cmd->ld->hsm_fd);

	if (!fromwire_hsm_sign_withdrawal_reply(utx, msg, &signed_tx))
		fatal("HSM gave bad sign_withdrawal_reply %s",
		      tal_hex(tmpctx, msg));

	/* Sanity check */
	bitcoin_txid(signed_tx, &signed_txid);
	if (!bitcoin_txid_eq(&signed_txid, &utx->txid))
		fatal("HSM changed txid: unsigned %s, signed %s",
		      tal_hex(tmpctx, linearize_tx(tmpctx, utx->tx)),
		      tal_hex(tmpctx, linearize_tx(tmpctx, signed_tx)));

	/* Replace unsigned tx by signed tx. */
	tal_free(utx->tx);
	utx->tx = signed_tx;

	/* Now broadcast the transaction */
	bitcoind_sendrawtx(cmd->ld->topology->bitcoind,
			   tal_hex(tmpctx, linearize_tx(tmpctx, signed_tx)),
			   wallet_withdrawal_broadcast, utx);

	return command_still_pending(cmd);
}

/* Common code for withdraw and txprepare.
 *
 * Returns NULL on success, and fills in wtx, destination and
 * maybe changekey (owned by cmd).  Otherwise, cmd has failed, so don't
 * access it! (It's been freed). */
static struct command_result *json_prepare_tx(struct command *cmd,
					      const char *buffer,
					      const jsmntok_t *params,
					      struct unreleased_tx **utx)
{
	u32 *feerate_per_kw;
	struct command_result *res;
	u32 *minconf, maxheight;
	struct pubkey *changekey;

	*utx = tal(cmd, struct unreleased_tx);
	(*utx)->wtx = tal(*utx, struct wallet_tx);
	wtx_init(cmd, (*utx)->wtx, AMOUNT_SAT(-1ULL));

	if (!param(cmd, buffer, params,
		   p_req("destination", param_bitcoin_address,
			 &(*utx)->destination),
		   p_req("satoshi", param_wtx, (*utx)->wtx),
		   p_opt("feerate", param_feerate, &feerate_per_kw),
		   p_opt_def("minconf", param_number, &minconf, 1),
		   NULL))
		return command_param_failed();

	/* Destination is owned by cmd: change that to be owned by utx. */
	tal_steal(*utx, (*utx)->destination);

	if (!feerate_per_kw) {
		res = param_feerate_estimate(cmd, &feerate_per_kw,
					     FEERATE_NORMAL);
		if (res)
			return res;
	}

	maxheight = minconf_to_maxheight(*minconf, cmd->ld);
	res = wtx_select_utxos((*utx)->wtx, *feerate_per_kw,
			       tal_count((*utx)->destination), maxheight);
	if (res)
		return res;

	if (!amount_sat_eq((*utx)->wtx->change, AMOUNT_SAT(0))) {
		changekey = tal(tmpctx, struct pubkey);
		if (!bip32_pubkey(cmd->ld->wallet->bip32_base, changekey,
				  (*utx)->wtx->change_key_index))
			return command_fail(cmd, LIGHTNINGD, "Keys generation failure");
	}

	(*utx)->tx = withdraw_tx(*utx, (*utx)->wtx->utxos,
				 (*utx)->destination, (*utx)->wtx->amount,
				 changekey, (*utx)->wtx->change,
				 cmd->ld->wallet->bip32_base,
				 &(*utx)->change_outnum);
	bitcoin_txid((*utx)->tx, &(*utx)->txid);

	return NULL;
}

static struct command_result *json_txprepare(struct command *cmd,
					     const char *buffer,
					     const jsmntok_t *obj UNNEEDED,
					     const jsmntok_t *params)
{
	struct unreleased_tx *utx;
	struct command_result *res;
	struct json_stream *response;

	res = json_prepare_tx(cmd, buffer, params, &utx);
	if (res)
		return res;

	/* utx will persist past this command. */
	tal_steal(cmd->ld->wallet, utx);
	add_unreleased_tx(cmd->ld->wallet, utx);

	response = json_stream_success(cmd);
	json_add_tx(response, "unsigned_tx", utx->tx);
	json_add_txid(response, "txid", &utx->txid);
	return command_success(cmd, response);
}
static const struct json_command txprepare_command = {
	"txprepare",
	"bitcoin",
	json_txprepare,
	"Create a transaction, with option to spend in future (either txsend and txdiscard)",
	false
};
AUTODATA(json_command, &txprepare_command);

static struct command_result *param_unreleased_txid(struct command *cmd,
						    const char *name,
						    const char *buffer,
						    const jsmntok_t *tok,
						    struct unreleased_tx **utx)
{
	struct command_result *res;
	struct bitcoin_txid *txid;

	res = param_txid(cmd, name, buffer, tok, &txid);
	if (res)
		return res;

	*utx = find_unreleased_tx(cmd->ld->wallet, txid);
	if (!*utx)
		return command_fail(cmd, LIGHTNINGD,
				    "%s not an unreleased txid",
				    type_to_string(cmd, struct bitcoin_txid,
						   txid));
	tal_free(txid);
	return NULL;
}

static struct command_result *json_txsend(struct command *cmd,
					  const char *buffer,
					  const jsmntok_t *obj UNNEEDED,
					  const jsmntok_t *params)
{
	struct unreleased_tx *utx;

	if (!param(cmd, buffer, params,
		   p_req("txid", param_unreleased_txid, &utx),
		   NULL))
		return command_param_failed();

	/* We delete from list now, and this command owns it. */
	remove_unreleased_tx(utx);
	tal_steal(cmd, utx);

	/* We're the owning cmd now. */
	utx->wtx->cmd = cmd;

	return broadcast_and_wait(cmd, utx);
}

static const struct json_command txsend_command = {
	"txsend",
	"bitcoin",
	json_txsend,
	"Sign and broadcast a transaction created by txprepare",
	false
};
AUTODATA(json_command, &txsend_command);

static struct command_result *json_txdiscard(struct command *cmd,
					     const char *buffer,
					     const jsmntok_t *obj UNNEEDED,
					     const jsmntok_t *params)
{
	struct unreleased_tx *utx;
	struct json_stream *response;

	if (!param(cmd, buffer, params,
		   p_req("txid", param_unreleased_txid, &utx),
		   NULL))
		return command_param_failed();

	/* Free utx with this command */
	tal_steal(cmd, utx);

	response = json_stream_success(cmd);
	json_add_tx(response, "unsigned_tx", utx->tx);
	json_add_txid(response, "txid", &utx->txid);
	return command_success(cmd, response);
}

static const struct json_command txdiscard_command = {
	"txdiscard",
	"bitcoin",
	json_txdiscard,
	"Abandon a transaction created by txprepare",
	false
};
AUTODATA(json_command, &txdiscard_command);

/**
 * json_withdraw - Entrypoint for the withdrawal flow
 *
 * A user has requested a withdrawal over the JSON-RPC, parse the
 * request, select coins and a change key. Then send the request to
 * the HSM to generate the signatures.
 */
static struct command_result *json_withdraw(struct command *cmd,
					    const char *buffer,
					    const jsmntok_t *obj UNNEEDED,
					    const jsmntok_t *params)
{
	struct unreleased_tx *utx;
	struct command_result *res;
	struct bitcoin_txid txid;

	res = json_prepare_tx(cmd, buffer, params, &utx);
	if (res)
		return res;

	/* Store the transaction in the DB and annotate it as a withdrawal */
	bitcoin_txid(utx->tx, &txid);
	wallet_transaction_add(cmd->ld->wallet, utx->tx, 0, 0);
	wallet_transaction_annotate(cmd->ld->wallet, &txid,
				    TX_WALLET_WITHDRAWAL, 0);

	return broadcast_and_wait(cmd, utx);
}

static const struct json_command withdraw_command = {
	"withdraw",
	"bitcoin",
	json_withdraw,
	"Send to {destination} address {satoshi} (or 'all') amount via Bitcoin "
	"transaction, at optional {feerate}",
	false,
	"Send funds from the internal wallet to the specified address. Either "
	"specify a number of satoshis to send or 'all' to sweep all funds in the "
	"internal wallet to the address. Only use outputs that have at least "
	"{minconf} confirmations."
};
AUTODATA(json_command, &withdraw_command);

/* May return NULL if encoding error occurs. */
static char *
encode_pubkey_to_addr(const tal_t *ctx,
		      const struct lightningd *ld,
		      const struct pubkey *pubkey,
		      bool is_p2sh_p2wpkh,
		      /* Output: redeemscript to use to redeem outputs
		       * paying to the address.
		       * May be NULL if redeemscript is do not care. */
		      u8 **out_redeemscript)
{
	char *out;
	const char *hrp;
	struct sha256 h;
	struct ripemd160 h160;
	u8 *redeemscript;
	bool ok;

	if (is_p2sh_p2wpkh) {
		redeemscript = bitcoin_redeem_p2sh_p2wpkh(ctx, pubkey);
		sha256(&h, redeemscript, tal_count(redeemscript));
		ripemd160(&h160, h.u.u8, sizeof(h));
		out = p2sh_to_base58(ctx,
				     get_chainparams(ld),
				     &h160);
	} else {
		hrp = get_chainparams(ld)->bip173_name;

		/* out buffer is 73 + strlen(human readable part),
		 * see common/bech32.h*/
		out = tal_arr(ctx, char, 73 + strlen(hrp));
		pubkey_to_hash160(pubkey, &h160);
		/* I am uncertain why this is so for direct SegWit
		 * outputs, but this is how listaddrs worked prior to
		 * this code being refactored. */
		redeemscript = tal_dup_arr(ctx, u8,
					   (u8 *) &h160, sizeof(h160),
					   0);

		ok = segwit_addr_encode(out, hrp, 0, h160.u.u8, sizeof(h160));
		if (!ok)
			out = tal_free(out);
	}

	if (out_redeemscript)
		*out_redeemscript = redeemscript;
	else
		tal_free(redeemscript);

	return out;
}

enum addrtype {
	ADDR_P2SH_SEGWIT = 1,
	ADDR_BECH32 = 2,
	ADDR_ALL = (ADDR_P2SH_SEGWIT + ADDR_BECH32)
};

/* Extract  bool indicating "p2sh-segwit" or "bech32" */
static struct command_result *param_newaddr(struct command *cmd,
					    const char *name,
					    const char *buffer,
					    const jsmntok_t *tok,
					    enum addrtype **addrtype)
{
	*addrtype = tal(cmd, enum addrtype);
	if (json_tok_streq(buffer, tok, "p2sh-segwit"))
		**addrtype = ADDR_P2SH_SEGWIT;
	else if (json_tok_streq(buffer, tok, "bech32"))
		**addrtype = ADDR_BECH32;
	else if (json_tok_streq(buffer, tok, "all"))
		**addrtype = ADDR_ALL;
	else
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "'%s' should be 'bech32', 'p2sh-segwit' or 'all', not '%.*s'",
				    name, tok->end - tok->start, buffer + tok->start);
	return NULL;
}

static struct command_result *json_newaddr(struct command *cmd,
					   const char *buffer,
					   const jsmntok_t *obj UNNEEDED,
					   const jsmntok_t *params)
{
	struct json_stream *response;
	struct pubkey pubkey;
	enum addrtype *addrtype;
	s64 keyidx;
	char *p2sh, *bech32;
	u8 *b32script;

	if (!param(cmd, buffer, params,
		   p_opt_def("addresstype", param_newaddr, &addrtype, ADDR_BECH32),
		   NULL))
		return command_param_failed();

	keyidx = wallet_get_newindex(cmd->ld);
	if (keyidx < 0) {
		return command_fail(cmd, LIGHTNINGD, "Keys exhausted ");
	}

	if (!bip32_pubkey(cmd->ld->wallet->bip32_base, &pubkey, keyidx))
		return command_fail(cmd, LIGHTNINGD, "Keys generation failure");

	b32script = scriptpubkey_p2wpkh(tmpctx, &pubkey);
	if (*addrtype & ADDR_BECH32)
		txfilter_add_scriptpubkey(cmd->ld->owned_txfilter, b32script);
	if (*addrtype & ADDR_P2SH_SEGWIT)
		txfilter_add_scriptpubkey(cmd->ld->owned_txfilter,
					  scriptpubkey_p2sh(tmpctx, b32script));

	p2sh = encode_pubkey_to_addr(cmd, cmd->ld, &pubkey, true, NULL);
	bech32 = encode_pubkey_to_addr(cmd, cmd->ld, &pubkey, false, NULL);
	if (!p2sh || !bech32) {
		return command_fail(cmd, LIGHTNINGD,
				    "p2wpkh address encoding failure.");
	}

	response = json_stream_success(cmd);
	if (deprecated_apis && *addrtype != ADDR_ALL)
		json_add_string(response, "address",
				*addrtype & ADDR_BECH32 ? bech32 : p2sh);
	if (*addrtype & ADDR_BECH32)
		json_add_string(response, "bech32", bech32);
	if (*addrtype & ADDR_P2SH_SEGWIT)
		json_add_string(response, "p2sh-segwit", p2sh);
	return command_success(cmd, response);
}

static const struct json_command newaddr_command = {
	"newaddr",
	"bitcoin",
	json_newaddr,
	"Get a new {bech32, p2sh-segwit} (or all) address to fund a channel (default is bech32)", false,
	"Generates a new address (or both) that belongs to the internal wallet. Funds sent to these addresses will be managed by lightningd. Use `withdraw` to withdraw funds to an external wallet."
};
AUTODATA(json_command, &newaddr_command);

static struct command_result *json_listaddrs(struct command *cmd,
					     const char *buffer,
					     const jsmntok_t *obj UNNEEDED,
					     const jsmntok_t *params)
{
	struct json_stream *response;
	struct pubkey pubkey;
	u64 *bip32_max_index;

	if (!param(cmd, buffer, params,
		   p_opt("bip32_max_index", param_u64, &bip32_max_index),
		   NULL))
		return command_param_failed();

	if (!bip32_max_index) {
		bip32_max_index = tal(cmd, u64);
		*bip32_max_index = db_get_intvar(cmd->ld->wallet->db,
						 "bip32_max_index", 0);
	}
	response = json_stream_success(cmd);
	json_array_start(response, "addresses");

	for (s64 keyidx = 0; keyidx <= *bip32_max_index; keyidx++) {

		if(keyidx == BIP32_INITIAL_HARDENED_CHILD){
			break;
		}

		if (!bip32_pubkey(cmd->ld->wallet->bip32_base, &pubkey, keyidx))
			abort();

		// p2sh
		u8 *redeemscript_p2sh;
		char *out_p2sh = encode_pubkey_to_addr(cmd, cmd->ld,
						       &pubkey,
						       true,
						       &redeemscript_p2sh);

		// bech32 : p2wpkh
		u8 *redeemscript_p2wpkh;
		char *out_p2wpkh = encode_pubkey_to_addr(cmd, cmd->ld,
							 &pubkey,
							 false,
							 &redeemscript_p2wpkh);
		if (!out_p2wpkh) {
			abort();
		}

		// outputs
		json_object_start(response, NULL);
		json_add_u64(response, "keyidx", keyidx);
		json_add_pubkey(response, "pubkey", &pubkey);
		json_add_string(response, "p2sh", out_p2sh);
		json_add_hex_talarr(response, "p2sh_redeemscript",
				    redeemscript_p2sh);
		json_add_string(response, "bech32", out_p2wpkh);
		json_add_hex_talarr(response, "bech32_redeemscript",
				    redeemscript_p2wpkh);
		json_object_end(response);
	}
	json_array_end(response);
	return command_success(cmd, response);
}

static const struct json_command listaddrs_command = {
	"dev-listaddrs",
	"developer",
	json_listaddrs,
	"Show addresses list up to derivation {index} (default is the last bip32 index)",
	false,
	"Show addresses of your internal wallet. Use `newaddr` to generate a new address."
};
AUTODATA(json_command, &listaddrs_command);

static void json_add_channel_state(struct json_stream *response,
			       const char *fieldname,
			       const enum channel_state state)
{
	json_add_member(response, fieldname, true, "%s", channel_state_str(state));
}

static void json_add_channel_meta_data(struct json_stream *response, const struct channel *c, const struct peer *p)
{
	json_object_start(response, NULL);
	json_add_node_id(response, "peer_id", &p->id);
	if (c->state != CHANNELD_NORMAL || !c->connected){
		json_add_channel_state(response, "state",c->state);
		json_add_bool(response, "connected", false);
	}

	if (c->scid)
		json_add_short_channel_id(response,
					  "short_channel_id",
					  c->scid);

	json_add_amount_sat_compat(response,
				   amount_msat_to_sat_round_down(c->our_msat),
				   "channel_sat",
				   "our_amount_msat");
	json_add_amount_sat_compat(response, c->funding,
				   "channel_total_sat",
				   "amount_msat");
	json_add_txid(response, "funding_txid",
		      &c->funding_txid);
	json_add_num(response, "funding_output",
		     c->funding_outnum);
	json_object_end(response);
}

static struct command_result *json_listfunds(struct command *cmd,
					     const char *buffer,
					     const jsmntok_t *obj UNNEEDED,
					     const jsmntok_t *params)
{
	struct json_stream *response;
	struct peer *p;
	struct utxo **utxos;
	char* out;
	struct pubkey funding_pubkey;

	if (!param(cmd, buffer, params, NULL))
		return command_param_failed();

	utxos = wallet_get_utxos(cmd, cmd->ld->wallet, output_state_available);
	response = json_stream_success(cmd);
	json_array_start(response, "outputs");
	for (size_t i = 0; i < tal_count(utxos); i++) {
		json_object_start(response, NULL);
		json_add_txid(response, "txid", &utxos[i]->txid);
		json_add_num(response, "output", utxos[i]->outnum);
		json_add_amount_sat_compat(response, utxos[i]->amount,
					   "value", "amount_msat");

		/* @close_info is for outputs that are not yet claimable */
		if (utxos[i]->close_info == NULL) {
			bip32_pubkey(cmd->ld->wallet->bip32_base, &funding_pubkey,
				     utxos[i]->keyindex);
			out = encode_pubkey_to_addr(cmd, cmd->ld,
						    &funding_pubkey,
						    utxos[i]->is_p2sh,
						    NULL);
			if (!out) {
				return command_fail(cmd, LIGHTNINGD,
						    "p2wpkh address encoding failure.");
			}
		        json_add_string(response, "address", out);
		} else if (utxos[i]->scriptPubkey != NULL) {
			out = encode_scriptpubkey_to_addr(
			    cmd, get_chainparams(cmd->ld)->bip173_name,
			    utxos[i]->scriptPubkey);
			if (out)
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
 			if (c->state != CHANNELD_NORMAL || !c->connected)
				continue;
			json_add_channel_meta_data(response, c, p);
		}
	}
	json_array_end(response);

	json_array_start(response, "non operational channels");
	list_for_each(&cmd->ld->peers, p, list) {
		struct channel *c;
		list_for_each(&p->channels, c, list) {
 			if (c->state == CHANNELD_NORMAL && c->connected)
				continue;
			json_add_channel_meta_data(response, c, p);
		}
	}
	json_array_end(response);

	return command_success(cmd, response);
}

static const struct json_command listfunds_command = {
	"listfunds",
	"utility",
	json_listfunds,
	"Show available funds from the internal wallet",
	false,
	"Returns a list of funds (outputs) that can be used by the internal wallet to open new channels or can be withdrawn, using the `withdraw` command, to another wallet."
};
AUTODATA(json_command, &listfunds_command);

struct txo_rescan {
	struct command *cmd;
	struct utxo **utxos;
	struct json_stream *response;
};

static void process_utxo_result(struct bitcoind *bitcoind,
				const struct bitcoin_tx_output *txout,
				void *arg)
{
	struct txo_rescan *rescan = arg;
	struct json_stream *response = rescan->response;
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
		was_pending(command_success(rescan->cmd, rescan->response));
	} else {
		bitcoind_gettxout(
		    bitcoind->ld->topology->bitcoind, &rescan->utxos[0]->txid,
		    rescan->utxos[0]->outnum, process_utxo_result, rescan);
	}
}

static struct command_result *json_dev_rescan_outputs(struct command *cmd,
						      const char *buffer,
						      const jsmntok_t *obj UNNEEDED,
						      const jsmntok_t *params)
{
	struct txo_rescan *rescan = tal(cmd, struct txo_rescan);

	if (!param(cmd, buffer, params, NULL))
		return command_param_failed();

	rescan->response = json_stream_success(cmd);
	rescan->cmd = cmd;

	/* Open the outputs structure so we can incrementally add results */
	json_array_start(rescan->response, "outputs");
	rescan->utxos = wallet_get_utxos(rescan, cmd->ld->wallet, output_state_any);
	if (tal_count(rescan->utxos) == 0) {
		json_array_end(rescan->response);
		return command_success(cmd, rescan->response);
	}
	bitcoind_gettxout(cmd->ld->topology->bitcoind, &rescan->utxos[0]->txid,
			  rescan->utxos[0]->outnum, process_utxo_result,
			  rescan);
	return command_still_pending(cmd);
}

static const struct json_command dev_rescan_output_command = {
	"dev-rescan-outputs",
	"developer",
	json_dev_rescan_outputs,
	"Synchronize the state of our funds with bitcoind",
	false,
	"For each output stored in the internal wallet ask `bitcoind` whether we are in sync with its state (spent vs. unspent)"
};
AUTODATA(json_command, &dev_rescan_output_command);

#if EXPERIMENTAL_FEATURES
struct {
	enum wallet_tx_type t;
	const char *name;
} wallet_tx_type_display_names[] = {
    {TX_THEIRS, "theirs"},
    {TX_WALLET_DEPOSIT, "deposit"},
    {TX_WALLET_WITHDRAWAL, "withdraw"},
    {TX_CHANNEL_FUNDING, "channel_funding"},
    {TX_CHANNEL_CLOSE, "channel_mutual_close"},
    {TX_CHANNEL_UNILATERAL, "channel_unilateral_close"},
    {TX_CHANNEL_SWEEP, "channel_sweep"},
    {TX_CHANNEL_HTLC_SUCCESS, "channel_htlc_success"},
    {TX_CHANNEL_HTLC_TIMEOUT, "channel_htlc_timeout"},
    {TX_CHANNEL_PENALTY, "channel_penalty"},
    {TX_CHANNEL_CHEAT, "channel_unilateral_cheat"},
    {0, NULL}
};

static void json_add_txtypes(struct json_stream *result, const char *fieldname, enum wallet_tx_type value)
{
	json_array_start(result, fieldname);
	for (size_t i=0; wallet_tx_type_display_names[i].name != NULL; i++) {
		if (value & wallet_tx_type_display_names[i].t)
			json_add_string(result, NULL, wallet_tx_type_display_names[i].name);
	}
	json_array_end(result);
}

static struct command_result *json_listtransactions(struct command *cmd,
						      const char *buffer,
						      const jsmntok_t *obj UNNEEDED,
						      const jsmntok_t *params)
{
	struct json_stream *response;
	struct wallet_transaction *txs;

	if (!param(cmd, buffer, params, NULL))
		return command_param_failed();

	txs = wallet_transactions_get(cmd->ld->wallet, cmd);

	response = json_stream_success(cmd);
	json_array_start(response, "transactions");
	for (size_t i=0; i<tal_count(txs); i++) {
		json_object_start(response, NULL);
		json_add_txid(response, "hash", &txs[i].id);
		json_add_hex_talarr(response, "rawtx", txs[i].rawtx);
		json_add_u64(response, "blockheight", txs[i].blockheight);
		json_add_num(response, "txindex", txs[i].txindex);
		json_add_txtypes(response, "type", txs[i].type);
		if (txs[i].channel_id != 0) {
			json_add_num(response, "channel_id", txs[i].channel_id);
		} else {
			json_add_null(response, "channel_id");
		}
		json_object_end(response);
	}
	json_array_end(response);
	return command_success(cmd, response);
}

static const struct json_command listtransactions_command = {
    "listtransactions",
    "payment",
    json_listtransactions,
    "List transactions that we stored in the wallet",
    false,
    "Returns transactions tracked in the wallet. This includes deposits, "
    "withdrawals and transactions related to channels. A transaction may have "
    "multiple types, e.g., a transaction may both be a close and a deposit if "
    "it closes the channel and returns funds to the wallet."
};
AUTODATA(json_command, &listtransactions_command);
#endif
