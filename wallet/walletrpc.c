#include "config.h"
#include <bitcoin/script.h>
#include <common/addr.h>
#include <common/base64.h>
#include <common/bech32.h>
#include <common/json_command.h>
#include <common/psbt_keypath.h>
#include <common/psbt_open.h>
#include <db/exec.h>
#include <errno.h>
#include <hsmd/hsmd_wiregen.h>
#include <lightningd/channel.h>
#include <lightningd/hsm_control.h>
#include <lightningd/notification.h>
#include <wallet/txfilter.h>
#include <wallet/walletrpc.h>
#include <wire/wire_sync.h>

/* May return NULL if encoding error occurs. */
static char *
encode_pubkey_to_addr(const tal_t *ctx,
		      const struct pubkey *pubkey,
		      enum addrtype addrtype,
		      /* Output: redeemscript to use to redeem outputs
		       * paying to the address.
		       * May be NULL if redeemscript is do not care. */
		      u8 **out_redeemscript)
{
	char *out;
	const char *hrp;
	struct ripemd160 h160;
	u8 *redeemscript;
	bool ok;

	switch (addrtype) {
	case ADDR_BECH32:
		hrp = chainparams->onchain_hrp;

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
		goto done;

	case ADDR_P2TR: {
		u8 *p2tr_spk = scriptpubkey_p2tr(ctx, pubkey);
		u8 *x_key = p2tr_spk + 2;
		hrp = chainparams->onchain_hrp;

		redeemscript = NULL;

		/* out buffer is 73 + strlen(human readable part),
		 * see common/bech32.h*/
		out = tal_arr(ctx, char, 73 + strlen(hrp));

		ok = segwit_addr_encode(out, hrp, /* witver */ 1, x_key, 32);
		goto done;
	}

	case ADDR_P2SH_SEGWIT:
	case ADDR_ALL:
		abort();
	}
	abort();


done:
	if (!ok)
		out = tal_free(out);

	if (out_redeemscript)
		*out_redeemscript = redeemscript;
	else
		tal_free(redeemscript);

	return out;
}

static struct command_result *param_newaddr(struct command *cmd,
					    const char *name,
					    const char *buffer,
					    const jsmntok_t *tok,
					    enum addrtype **addrtype)
{
	*addrtype = tal(cmd, enum addrtype);
	if (json_tok_streq(buffer, tok, "bech32"))
		**addrtype = ADDR_BECH32;
	else if (!chainparams->is_elements && json_tok_streq(buffer, tok, "p2tr"))
		**addrtype = ADDR_P2TR;
	else if (json_tok_streq(buffer, tok, "all"))
		**addrtype = ADDR_ALL;
	else
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "'%s' should be 'p2tr', 'bech32', or 'all', not '%.*s'",
				    name, tok->end - tok->start, buffer + tok->start);
	return NULL;
}

bool WARN_UNUSED_RESULT newaddr_inner(struct command *cmd, struct pubkey *pubkey, enum addrtype addrtype)
{
	s64 keyidx;
	u8 *b32script;
	u8 *p2tr_script;
	bool use_bip86_base = (cmd->ld->bip86_base != NULL);

	/* Get new index - wallet_get_newindex now handles both BIP32 and BIP86 */
	keyidx = wallet_get_newindex(cmd->ld, addrtype);
	if (keyidx < 0) return false;

	/* Choose derivation method based on wallet type */
	if (use_bip86_base) {
		/* Wallet has mnemonic - use BIP86 derivation */
		bip86_pubkey(cmd->ld, pubkey, keyidx);
	} else {
		/* Legacy wallet - use BIP32 derivation */
		bip32_pubkey(cmd->ld, pubkey, keyidx);
	}

	/* Generate scripts from pubkey (same logic for both wallet types) */
	b32script = scriptpubkey_p2wpkh(tmpctx, pubkey);
	p2tr_script = scriptpubkey_p2tr(tmpctx, pubkey);

	/* Add scripts to filter based on requested address type */
	if (addrtype & ADDR_BECH32)
		txfilter_add_scriptpubkey(cmd->ld->owned_txfilter, b32script);
	if (addrtype & ADDR_P2TR)
		txfilter_add_scriptpubkey(cmd->ld->owned_txfilter, p2tr_script);

	return true;
}


static struct command_result *json_newaddr(struct command *cmd,
					   const char *buffer,
					   const jsmntok_t *obj UNNEEDED,
					   const jsmntok_t *params)
{
	struct json_stream *response;
	struct pubkey pubkey;
	enum addrtype *addrtype;
	char *bech32, *p2tr;

	if (!param(cmd, buffer, params,
		   p_opt("addresstype", param_newaddr, &addrtype),
		   NULL))
		return command_param_failed();

	if (!addrtype) {
		addrtype = tal(cmd, enum addrtype);
		if (command_deprecated_in_ok(cmd, "addresstype.defaultbech32",
					     "v25.12", "v26.12"))
			*addrtype = ADDR_ALL;
		else
			*addrtype = ADDR_P2TR;
	}

	if (!newaddr_inner(cmd, &pubkey, *addrtype)) {
		return command_fail(cmd, LIGHTNINGD, "Keys exhausted ");
	};

	response = json_stream_success(cmd);

	/* Generate addresses based on requested type */
	bech32 = encode_pubkey_to_addr(cmd, &pubkey, ADDR_BECH32, NULL);
	p2tr = encode_pubkey_to_addr(cmd, &pubkey, ADDR_P2TR, NULL);
	if (!bech32 || !p2tr) {
		return command_fail(cmd, LIGHTNINGD,
				    "p2wpkh address encoding failure.");
	}

	if (*addrtype & ADDR_BECH32)
		json_add_string(response, "bech32", bech32);
	if (*addrtype & ADDR_P2TR)
		json_add_string(response, "p2tr", p2tr);
	return command_success(cmd, response);
}

static const struct json_command newaddr_command = {
	"newaddr",
	json_newaddr,
};
AUTODATA(json_command, &newaddr_command);

static void json_add_address_details(struct json_stream *response,
				 const u64 keyidx,
				 const char *out_p2wpkh,
				 const char *out_p2tr,
				 enum addrtype addrtype)
{
	json_object_start(response, NULL);
	json_add_u64(response, "keyidx", keyidx);
	if (!streq(out_p2wpkh, "")) {
		json_add_string(response, "bech32", out_p2wpkh);
	}
	if (!streq(out_p2tr,"")) {
		json_add_string(response, "p2tr", out_p2tr);
	}
	json_object_end(response);
}

static struct command_result *json_listaddresses(struct command *cmd,
					     const char *buffer,
					     const jsmntok_t *obj UNNEEDED,
					     const jsmntok_t *params)
{
	struct json_stream *response;
	struct pubkey pubkey;
	const u8 *scriptpubkey;
	u64 *liststart;
	u32 *listlimit;
	char *addr = NULL;

	if (!param(cmd, buffer, params,
			 p_opt("address", param_bitcoin_address, &scriptpubkey),
			 p_opt_def("start", param_u64, &liststart, 1),
			 p_opt("limit", param_u32, &listlimit),
			 NULL))
		return command_param_failed();

	addr = encode_scriptpubkey_to_addr(tmpctx, chainparams, scriptpubkey);

	if (*liststart == 0) {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
						"Starting keyidx is 1; Cannot {start} with 0");
	}
	struct issued_address_type *listaddrtypes = wallet_list_addresses(tmpctx, cmd->ld->wallet, *liststart, listlimit);
	response = json_stream_success(cmd);
	json_array_start(response, "addresses");
	for (size_t i = 0; i < tal_count(listaddrtypes); i++) {
		if (listaddrtypes[i].keyidx == BIP32_INITIAL_HARDENED_CHILD){
			break;
		}
		/* Use appropriate derivation based on wallet type */
		if (cmd->ld->bip86_base) {
			/* Mnemonic wallet - use BIP86 derivation */
			bip86_pubkey(cmd->ld, &pubkey, listaddrtypes[i].keyidx);
		} else {
			/* Legacy wallet - use BIP32 derivation */
			bip32_pubkey(cmd->ld, &pubkey, listaddrtypes[i].keyidx);
		}
		char *out_p2wpkh = "";
		char *out_p2tr = "";
		if (listaddrtypes[i].addrtype == ADDR_BECH32 || listaddrtypes[i].addrtype == ADDR_ALL) {
			u8 *redeemscript_p2wpkh;
			out_p2wpkh = encode_pubkey_to_addr(cmd,
								&pubkey,
								ADDR_BECH32,
								&redeemscript_p2wpkh);
			if (!out_p2wpkh) {
				abort();
			}
		}
		if (listaddrtypes[i].addrtype == ADDR_P2TR || listaddrtypes[i].addrtype == ADDR_ALL) {
			out_p2tr = encode_pubkey_to_addr(cmd,
								&pubkey,
								ADDR_P2TR,
								/* out_redeemscript */ NULL);
			if (!out_p2tr) {
				abort();
			}
		}
		if (!addr || streq(addr, out_p2wpkh) || streq(addr, out_p2tr)) {
			json_add_address_details(response, listaddrtypes[i].keyidx, out_p2wpkh, out_p2tr, listaddrtypes[i].addrtype);
			if (addr) {
				break;
			}
		}
	}
	json_array_end(response);
	return command_success(cmd, response);
}

static const struct json_command listaddresses_command = {
	"listaddresses",
	json_listaddresses
};
AUTODATA(json_command, &listaddresses_command);

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

	for (s64 keyidx = 1; keyidx <= *bip32_max_index; keyidx++) {

		if (keyidx == BIP32_INITIAL_HARDENED_CHILD){
			break;
		}

		bip32_pubkey(cmd->ld, &pubkey, keyidx);

		// bech32 : p2wpkh
		u8 *redeemscript_p2wpkh;
		char *out_p2wpkh = encode_pubkey_to_addr(cmd,
							 &pubkey,
							 ADDR_BECH32,
							 &redeemscript_p2wpkh);
		if (!out_p2wpkh) {
			abort();
		}

		// p2tr
		char *out_p2tr = encode_pubkey_to_addr(cmd,
						       &pubkey,
						       ADDR_P2TR,
						       /* out_redeemscript */ NULL);
		if (!out_p2tr) {
			abort();
		}

		// outputs
		json_object_start(response, NULL);
		json_add_u64(response, "keyidx", keyidx);
		json_add_pubkey(response, "pubkey", &pubkey);
		json_add_string(response, "bech32", out_p2wpkh);
		json_add_hex_talarr(response, "bech32_redeemscript",
				    redeemscript_p2wpkh);
		json_add_string(response, "p2tr", out_p2tr);
		json_object_end(response);
	}
	json_array_end(response);
	return command_success(cmd, response);
}

static const struct json_command listaddrs_command = {
	"dev-listaddrs",
	json_listaddrs,
	.dev_only = true,
};
AUTODATA(json_command, &listaddrs_command);

static void json_add_utxo(struct json_stream *response,
			  const char *fieldname,
			  struct wallet *wallet,
			  const struct utxo *utxo)
{
	const char *out;
	bool reserved;
	u32 current_height = get_block_height(wallet->ld->topology);

	json_object_start(response, fieldname);
	json_add_txid(response, "txid", &utxo->outpoint.txid);
	json_add_num(response, "output", utxo->outpoint.n);
	json_add_amount_sat_msat(response, "amount_msat", utxo->amount);

	if (utxo->utxotype == UTXO_P2SH_P2WPKH) {
		struct pubkey key;
		bip32_pubkey(wallet->ld, &key, utxo->keyindex);

		json_add_hex_talarr(response, "redeemscript",
				    bitcoin_redeem_p2sh_p2wpkh(tmpctx, &key));
	}

	json_add_hex_talarr(response, "scriptpubkey", utxo->scriptPubkey);
	out = encode_scriptpubkey_to_addr(tmpctx, chainparams,
					  utxo->scriptPubkey);
	if (!out)
		log_broken(wallet->log,
			   "Could not encode utxo %s%s!",
			   fmt_bitcoin_outpoint(tmpctx,
						&utxo->outpoint),
			   utxo->close_info ? " (has close_info)" : "");
	else
		json_add_string(response, "address", out);

	if (utxo->spendheight)
		json_add_string(response, "status", "spent");
	else if (utxo->blockheight) {
		json_add_string(response, "status",
				utxo_is_immature(utxo, current_height)
				    ? "immature"
				    : "confirmed");

		json_add_num(response, "blockheight", *utxo->blockheight);
	} else
		json_add_string(response, "status", "unconfirmed");

	reserved = utxo_is_reserved(utxo, current_height);
	json_add_bool(response, "reserved", reserved);
	if (reserved)
		json_add_num(response, "reserved_to_block",
			     utxo->reserved_til);
	if (utxo->close_info && utxo->close_info->csv > 1) {
		json_add_num(response, "csv_lock", utxo->close_info->csv);

		if (utxo->blockheight)
			json_add_u32(response, "spendable_at",
				     *utxo->blockheight + utxo->close_info->csv);
	}

	json_object_end(response);
}

static void json_add_utxos(struct json_stream *response,
			   struct wallet *wallet,
			   struct utxo **utxos)
{
	for (size_t i = 0; i < tal_count(utxos); i++)
		json_add_utxo(response, NULL, wallet, utxos[i]);
}

static struct command_result *json_listfunds(struct command *cmd,
					     const char *buffer,
					     const jsmntok_t *obj UNNEEDED,
					     const jsmntok_t *params)
{
	struct json_stream *response;
	struct peer *p;
	struct peer_node_id_map_iter it;
	struct utxo **utxos;
	bool *spent;

	if (!param(cmd, buffer, params,
		   p_opt_def("spent", param_bool, &spent, false),
		   NULL))
		return command_param_failed();

	response = json_stream_success(cmd);

	if (*spent)
		utxos = wallet_get_all_utxos(cmd, cmd->ld->wallet);
	else
		utxos = wallet_get_unspent_utxos(cmd, cmd->ld->wallet);

	json_array_start(response, "outputs");
	json_add_utxos(response, cmd->ld->wallet, utxos);
	json_array_end(response);

	/* Add funds that are allocated to channels */
	json_array_start(response, "channels");
	for (p = peer_node_id_map_first(cmd->ld->peers, &it);
	     p;
	     p = peer_node_id_map_next(cmd->ld->peers, &it)) {
		struct channel *c;
		list_for_each(&p->channels, c, list) {
			/* We don't print out uncommitted channels */
			if (channel_state_uncommitted(c->state))
				continue;
			json_object_start(response, NULL);
			json_add_node_id(response, "peer_id", &p->id);
			json_add_bool(response, "connected",
				      channel_is_connected(c));
			json_add_string(response, "state",
					channel_state_name(c));
			json_add_channel_id(response, "channel_id", &c->cid);
			if (c->scid)
				json_add_short_channel_id(response,
							  "short_channel_id",
							  *c->scid);

			json_add_amount_msat(response,
					     "our_amount_msat",
					     c->our_msat);
			json_add_amount_sat_msat(response,
						 "amount_msat",
						 c->funding_sats);
			json_add_txid(response, "funding_txid",
				      &c->funding.txid);
			json_add_num(response, "funding_output",
				      c->funding.n);
			json_object_end(response);
		}
	}
	json_array_end(response);

	return command_success(cmd, response);
}

static const struct json_command listfunds_command = {
	"listfunds",
	json_listfunds,
};
AUTODATA(json_command, &listfunds_command);

struct txo_rescan {
	struct command *cmd;
	struct utxo **utxos;
	struct json_stream *response;
};

static void process_utxo_result(struct bitcoind *bitcoind,
				const struct bitcoin_tx_output *txout,
				struct txo_rescan *rescan)
{
	struct json_stream *response = rescan->response;
	struct utxo *u = rescan->utxos[0];
	enum output_status newstate =
	    txout == NULL ? OUTPUT_STATE_SPENT : OUTPUT_STATE_AVAILABLE;

	json_object_start(rescan->response, NULL);
	json_add_txid(response, "txid", &u->outpoint.txid);
	json_add_num(response, "output", u->outpoint.n);
	json_add_num(response, "oldstate", u->status);
	json_add_num(response, "newstate", newstate);
	json_object_end(rescan->response);
	wallet_update_output_status(bitcoind->ld->wallet, &u->outpoint,
				    u->status, newstate);

	/* Remove the utxo we just resolved */
	rescan->utxos[0] = rescan->utxos[tal_count(rescan->utxos) - 1];
	tal_resize(&rescan->utxos, tal_count(rescan->utxos) - 1);

	if (tal_count(rescan->utxos) == 0) {
		/* Complete the response */
		json_array_end(rescan->response);
		was_pending(command_success(rescan->cmd, rescan->response));
	} else {
		bitcoind_getutxout(bitcoind, bitcoind,
				   &rescan->utxos[0]->outpoint,
				   process_utxo_result, rescan);
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
	rescan->utxos = wallet_get_all_utxos(rescan, cmd->ld->wallet);
	if (tal_count(rescan->utxos) == 0) {
		json_array_end(rescan->response);
		return command_success(cmd, rescan->response);
	}
	bitcoind_getutxout(rescan, cmd->ld->topology->bitcoind,
			   &rescan->utxos[0]->outpoint,
			   process_utxo_result,
			   rescan);
	return command_still_pending(cmd);
}

static const struct json_command dev_rescan_output_command = {
	"dev-rescan-outputs",
	json_dev_rescan_outputs,
	.dev_only = true,
};
AUTODATA(json_command, &dev_rescan_output_command);

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
};

static void json_transaction_details(struct json_stream *response,
				     const struct wallet_transaction *tx)
{
	struct wally_tx *wtx = tx->tx->wtx;

		json_object_start(response, NULL);
		json_add_txid(response, "hash", &tx->id);
		json_add_hex_talarr(response, "rawtx", tx->rawtx);
		json_add_num(response, "blockheight", tx->blockheight);
		json_add_num(response, "txindex", tx->txindex);
		json_add_u32(response, "locktime", wtx->locktime);
		json_add_u32(response, "version", wtx->version);

		json_array_start(response, "inputs");
		for (size_t i = 0; i < wtx->num_inputs; i++) {
			struct bitcoin_txid prevtxid;
			struct wally_tx_input *in = &wtx->inputs[i];
			bitcoin_tx_input_get_txid(tx->tx, i, &prevtxid);

			json_object_start(response, NULL);
			json_add_txid(response, "txid", &prevtxid);
			json_add_u32(response, "index", in->index);
			json_add_u32(response, "sequence", in->sequence);
			json_object_end(response);
		}
		json_array_end(response);

		json_array_start(response, "outputs");
		for (size_t i = 0; i < wtx->num_outputs; i++) {
			struct wally_tx_output *out = &wtx->outputs[i];
			struct amount_asset amt = bitcoin_tx_output_get_amount(tx->tx, i);
			struct amount_sat sat;

			/* TODO We should eventually handle non-bitcoin assets as well. */
			if (amount_asset_is_main(&amt))
				sat = amount_asset_to_sat(&amt);
			else
				sat = AMOUNT_SAT(0);

			json_object_start(response, NULL);

			json_add_u32(response, "index", i);
			json_add_amount_sat_msat(response, "amount_msat", sat);

			json_add_hex(response, "scriptPubKey", out->script, out->script_len);

			json_object_end(response);
		}
		json_array_end(response);

		json_object_end(response);
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

	txs = wallet_transactions_get(cmd, cmd->ld->wallet);

	response = json_stream_success(cmd);
	json_array_start(response, "transactions");
	for (size_t i = 0; i < tal_count(txs); i++)
		json_transaction_details(response, &txs[i]);

	json_array_end(response);
	return command_success(cmd, response);
}

static const struct json_command listtransactions_command = {
    "listtransactions",
    json_listtransactions,
};
AUTODATA(json_command, &listtransactions_command);

static bool in_only_inputs(const u32 *only_inputs, u32 this)
{
	for (size_t i = 0; i < tal_count(only_inputs); i++)
		if (only_inputs[i] == this)
			return true;
	return false;
}

static struct command_result *match_psbt_inputs_to_utxos(struct command *cmd,
							 struct wally_psbt *psbt,
							 const u32 *only_inputs,
							 struct utxo ***utxos)
{
	*utxos = tal_arr(cmd, struct utxo *, 0);
	for (size_t i = 0; i < psbt->num_inputs; i++) {
		struct utxo *utxo;
		struct bitcoin_outpoint outpoint;

		if (only_inputs && !in_only_inputs(only_inputs, i))
			continue;

		wally_psbt_input_get_outpoint(&psbt->inputs[i], &outpoint);
		utxo = wallet_utxo_get(*utxos, cmd->ld->wallet, &outpoint);
		if (!utxo) {
			if (only_inputs)
				return command_fail(cmd, LIGHTNINGD,
						    "Aborting PSBT signing. UTXO %s is unknown (and specified by signonly)",
						    fmt_bitcoin_outpoint(tmpctx,
									 &outpoint));
			continue;
		}

		/* Oops we haven't reserved this utxo yet! */
		if (!utxo_is_reserved(utxo, get_block_height(cmd->ld->topology)))
			return command_fail(cmd, LIGHTNINGD,
					    "Aborting PSBT signing. UTXO %s is not reserved",
					    fmt_bitcoin_outpoint(tmpctx,
								 &utxo->outpoint));

		/* If the psbt doesn't have the UTXO info yet, add it.
		 * We only add the witness_utxo for this */
		if (!psbt->inputs[i].utxo && !psbt->inputs[i].witness_utxo) {
			u8 *scriptPubKey;

			if (utxo->utxotype == UTXO_P2SH_P2WPKH) {
				struct pubkey key;
				u8 *redeemscript;
				int wally_err;

				bip32_pubkey(cmd->ld, &key, utxo->keyindex);
				redeemscript = bitcoin_redeem_p2sh_p2wpkh(tmpctx, &key);
				scriptPubKey = scriptpubkey_p2sh(tmpctx, redeemscript);

				tal_wally_start();
				wally_err = wally_psbt_input_set_redeem_script(&psbt->inputs[i],
									       redeemscript,
									       tal_bytelen(redeemscript));
				assert(wally_err == WALLY_OK);
				tal_wally_end(psbt);
			} else
				scriptPubKey = utxo->scriptPubkey;

			psbt_input_set_wit_utxo(psbt, i, scriptPubKey, utxo->amount);
		}
		tal_arr_expand(utxos, utxo);
	}

	return NULL;
}

static bool match_psbt_outputs_to_wallet(struct wally_psbt *psbt,
				  struct wallet *w)
{
	bool ok = true;

	tal_wally_start();
	for (size_t outndx = 0; outndx < psbt->num_outputs; ++outndx) {
		struct ext_key ext;
		const u8 *script = psbt->outputs[outndx].script;
		const size_t script_len = psbt->outputs[outndx].script_len;
		u32 index;

		if (!wallet_can_spend(w, script, script_len, &index, NULL))
			continue;

		if (bip32_key_from_parent(
			    w->ld->bip32_base, index, BIP32_FLAG_KEY_PUBLIC, &ext) != WALLY_OK) {
			abort();
		}

		if (!psbt_output_set_keypath(index, &ext,
					     is_p2tr(script, script_len, NULL),
					     &psbt->outputs[outndx])) {
			ok = false;
			break;
		}
	}
	tal_wally_end(psbt);

	return ok;
}

static struct command_result *param_input_numbers(struct command *cmd,
						  const char *name,
						  const char *buffer,
						  const jsmntok_t *tok,
						  u32 **input_nums)
{
	struct command_result *res;
	const jsmntok_t *arr, *t;
	size_t i;

	res = param_array(cmd, name, buffer, tok, &arr);
	if (res)
		return res;

	*input_nums = tal_arr(cmd, u32, arr->size);
	json_for_each_arr(i, t, arr) {
		u32 *num;
		res = param_number(cmd, name, buffer, t, &num);
		if (res)
			return res;
		(*input_nums)[i] = *num;
		tal_free(num);
	}
	return NULL;
}

static struct command_result *json_signpsbt(struct command *cmd,
					    const char *buffer,
					    const jsmntok_t *obj UNNEEDED,
					    const jsmntok_t *params)
{
	struct command_result *res;
	struct json_stream *response;
	struct wally_psbt *psbt, *signed_psbt;
	struct utxo **utxos;
	const struct hsm_utxo **hsm_utxos;
	u32 *input_nums;
	u32 psbt_version;

	if (!param_check(cmd, buffer, params,
			 p_req("psbt", param_psbt, &psbt),
			 p_opt("signonly", param_input_numbers, &input_nums),
			 NULL))
		return command_param_failed();

	/* We internally deal with v2 only but we want to return V2 if given */
	psbt_version = psbt->version;
	if (!psbt_set_version(psbt, 2)) {
		return command_fail(cmd, LIGHTNINGD,
				    "Could not set PSBT version: %s",
					 fmt_wally_psbt(tmpctx, psbt));
	}

	/* Sanity check! */
	for (size_t i = 0; i < tal_count(input_nums); i++) {
		if (input_nums[i] >= psbt->num_inputs)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "signonly[%zu]: %u out of range",
					    i, input_nums[i]);
	}

	/* We have to find/locate the utxos that are ours on this PSBT,
	 * so that the HSM knows how/what to sign for (it's possible some of
	 * our utxos require more complicated data to sign for e.g.
	 * closeinfo outputs */
	res = match_psbt_inputs_to_utxos(cmd, psbt, input_nums, &utxos);
	if (res)
		return res;

	if (tal_count(utxos) == 0)
		return command_fail(cmd, LIGHTNINGD,
				    "No wallet inputs to sign. Are you sure you"
				    " added inputs to this PSBT? If not, then"
				    " there is no need to sign it.");

	if (command_check_only(cmd))
		return command_check_done(cmd);

	/* Update the keypaths on any outputs that are in our wallet (change addresses). */
	if (!match_psbt_outputs_to_wallet(psbt, cmd->ld->wallet))
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Could not add keypaths to PSBT?");

	/* FIXME: hsm will sign almost anything, but it should really
	 * fail cleanly (not abort!) and let us report the error here. */
	hsm_utxos = utxos_to_hsm_utxos(tmpctx, utxos);
	u8 *msg = towire_hsmd_sign_withdrawal(cmd, hsm_utxos, psbt);

	if (!wire_sync_write(cmd->ld->hsm_fd, take(msg)))
		fatal("Could not write sign_withdrawal to HSM: %s",
		      strerror(errno));

	msg = wire_sync_read(cmd, cmd->ld->hsm_fd);

	if (!fromwire_hsmd_sign_withdrawal_reply(cmd, msg, &signed_psbt))
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "HSM gave bad sign_withdrawal_reply %s",
				    tal_hex(tmpctx, msg));

	/* Some signers (VLS) prune the input.utxo data as it's used
	 * because it is too large to store in the signer. We can
	 * restore this metadata by combining the signed psbt back
	 * into a clone of the original psbt. */
	struct wally_psbt *combined_psbt;
	combined_psbt = combine_psbt(cmd, psbt, signed_psbt);
	if (!combined_psbt) {
		return command_fail(cmd, LIGHTNINGD,
				    "Unable to combine signed psbt: %s",
				    fmt_wally_psbt(tmpctx, signed_psbt));
	}

	if (!psbt_set_version(combined_psbt, psbt_version)) {
		return command_fail(cmd, LIGHTNINGD,
				    "Signed PSBT unable to have version set: %s",
					 fmt_wally_psbt(tmpctx, combined_psbt));
	}

	response = json_stream_success(cmd);
	json_add_psbt(response, "signed_psbt", combined_psbt);
	return command_success(cmd, response);
}

static const struct json_command signpsbt_command = {
	"signpsbt",
	json_signpsbt,
	false
};

AUTODATA(json_command, &signpsbt_command);

static struct command_result *json_setpsbtversion(struct command *cmd,
                        const char *buffer,
					    const jsmntok_t *obj UNNEEDED,
                        const jsmntok_t *params)
{
    struct json_stream *response;
    unsigned int *version;
    struct wally_psbt *psbt;

    if (!param_check(cmd, buffer, params,
           p_req("psbt", param_psbt, &psbt),
           p_req("version", param_number, &version),
           NULL))
        return command_param_failed();

    if (!psbt_set_version(psbt, *version)) {
        return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
                    "Could not set PSBT version");
    }
    if (command_check_only(cmd))
	    return command_check_done(cmd);

    response = json_stream_success(cmd);
    json_add_psbt(response, "psbt", psbt);

    return command_success(cmd, response);
}

static const struct json_command setpsbtversion_command = {
	"setpsbtversion",
	json_setpsbtversion,
	false
};

AUTODATA(json_command, &setpsbtversion_command);

struct sending_psbt {
	struct command *cmd;
	struct utxo **utxos;
	struct wally_tx *wtx;
	/* Hold onto b/c has data about
	 * which are to external addresses */
	struct wally_psbt *psbt;
	u32 reserve_blocks;
};

static void maybe_notify_new_external_send(struct lightningd *ld,
					   struct bitcoin_txid *txid,
					   u32 outnum,
					   struct wally_psbt *psbt)
{
	struct chain_coin_mvt *mvt;
	struct bitcoin_outpoint outpoint;
	struct amount_sat amount;
	u32 index;
	const u8 *script;

	/* If it's not going to an external address, ignore */
	if (!psbt_output_to_external(&psbt->outputs[outnum]))
		return;

	/* If it's going to our wallet, ignore */
	script = wally_psbt_output_get_script(tmpctx,
					      &psbt->outputs[outnum]);
	if (wallet_can_spend(ld->wallet, script, tal_bytelen(script), &index, NULL))
		return;

	outpoint.txid = *txid;
	outpoint.n = outnum;
	amount = psbt_output_get_amount(psbt, outnum);

	mvt = new_coin_external_deposit(NULL, &outpoint,
					0, amount,
					mk_mvt_tags(MVT_DEPOSIT));

	mvt->originating_acct = new_mvt_account_id(mvt,  NULL, ACCOUNT_NAME_WALLET);

	wallet_save_chain_mvt(ld, take(mvt));
}

static void sendpsbt_done(struct bitcoind *bitcoind UNUSED,
			  bool success, const char *msg,
			  struct sending_psbt *sending)
{
	struct lightningd *ld = sending->cmd->ld;
	struct json_stream *response;
	struct bitcoin_txid txid;

	if (!success) {
		/* Unreserve the inputs again. */
		for (size_t i = 0; i < tal_count(sending->utxos); i++) {
			wallet_unreserve_utxo(ld->wallet,
					      sending->utxos[i],
					      get_block_height(ld->topology),
					      sending->reserve_blocks);
		}

		was_pending(command_fail(sending->cmd, LIGHTNINGD,
					 "Error broadcasting transaction: %s."
					 " Unsent tx discarded %s",
					 msg,
					 fmt_wally_tx(tmpctx, sending->wtx)));
		return;
	}

	/* Internal-only after, set to v2 */
	if (!psbt_set_version(sending->psbt, 2)) {
		abort(); // Send succeeded but later calls may fail
	}

	wallet_transaction_add(ld->wallet, sending->wtx, 0, 0);
	wally_txid(sending->wtx, &txid);

	/* Extract the change output and add it to the DB */
	if (wallet_extract_owned_outputs(ld->wallet, sending->wtx, false, NULL) == 0) {
		/* If we're not watching it for selfish reasons (i.e. pure send to
		 * others), make sure we're watching it so we can update depth in db */
		watch_unconfirmed_txid(ld, ld->topology, &txid);
	}

	for (size_t i = 0; i < sending->psbt->num_outputs; i++)
		maybe_notify_new_external_send(ld, &txid, i, sending->psbt);

	response = json_stream_success(sending->cmd);
	json_add_hex_talarr(response, "tx", linearize_wtx(tmpctx, sending->wtx));
	json_add_txid(response, "txid", &txid);
	was_pending(command_success(sending->cmd, response));
}

static struct command_result *json_dev_finalizepsbt(struct command *cmd,
						    const char *buffer,
						    const jsmntok_t *obj,
						    const jsmntok_t *params)
{
	struct wally_psbt *psbt;
	struct wally_tx *wtx;
	struct bitcoin_txid txid;
	struct json_stream *response;

	if (!param_check(cmd, buffer, params,
			 p_req("psbt", param_psbt, &psbt),
			 NULL))
		return command_param_failed();

	if (!psbt_finalize(psbt))
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "PSBT not finalizeable");

	wtx = psbt_final_tx(cmd, psbt);
	wally_txid(wtx, &txid);

	response = json_stream_success(cmd);
	json_add_psbt(response, "psbt", psbt);
	json_add_hex_talarr(response, "tx", linearize_wtx(tmpctx, wtx));
	json_add_txid(response, "txid", &txid);
	return command_success(cmd, response);
}

static const struct json_command dev_finalizepsbt_command = {
	"dev-finalizepsbt",
	json_dev_finalizepsbt,
	true,
};
AUTODATA(json_command, &dev_finalizepsbt_command);

static struct command_result *json_sendpsbt(struct command *cmd,
					    const char *buffer,
					    const jsmntok_t *obj,
					    const jsmntok_t *params)
{
	struct command_result *res;
	struct sending_psbt *sending;
	struct wally_psbt *psbt;
	struct lightningd *ld = cmd->ld;
	u32 *reserve_blocks;

	if (!param_check(cmd, buffer, params,
			 p_req("psbt", param_psbt, &psbt),
			 p_opt_def("reserve", param_number, &reserve_blocks, 12 * 6),
			 NULL))
		return command_param_failed();

	sending = tal(cmd, struct sending_psbt);
	sending->cmd = cmd;
	sending->reserve_blocks = *reserve_blocks;

	psbt_finalize(psbt);
	sending->wtx = psbt_final_tx(sending, psbt);

	/* psbt contains info about which outputs are to external,
	 * and thus need a coin_move issued for them. We only
	 * notify if the transaction broadcasts */
	sending->psbt = tal_steal(sending, psbt);

	if (!sending->wtx)
		return command_fail(cmd, LIGHTNINGD,
				    "PSBT not finalizeable %s",
				    fmt_wally_psbt(tmpctx, psbt));

	/* We have to find/locate the utxos that are ours on this PSBT,
	 * so that we know who to mark as used.
	 */
	res = match_psbt_inputs_to_utxos(cmd, psbt, NULL, &sending->utxos);
	if (res)
		return res;

	if (command_check_only(cmd))
		return command_check_done(cmd);

	for (size_t i = 0; i < tal_count(sending->utxos); i++) {
		if (!wallet_reserve_utxo(ld->wallet, sending->utxos[i],
					 get_block_height(ld->topology),
					 sending->reserve_blocks))
			fatal("UTXO not reservable?");
	}

	/* Now broadcast the transaction */
	bitcoind_sendrawtx(sending, cmd->ld->topology->bitcoind,
			   cmd->id,
			   tal_hex(tmpctx,
				   linearize_wtx(tmpctx, sending->wtx)),
			   false, sendpsbt_done, sending);

	return command_still_pending(cmd);
}

static const struct json_command sendpsbt_command = {
	"sendpsbt",
	json_sendpsbt,
	false
};

AUTODATA(json_command, &sendpsbt_command);

static struct command_result *
json_signmessagewithkey(struct command *cmd, const char *buffer,
			const jsmntok_t *obj UNNEEDED, const jsmntok_t *params)
{
	/* decoding the address */
	const u8 *scriptpubkey;
	const char *message;

	/* from wallet BIP32 */
	struct pubkey pubkey;

	if (!param(
		cmd, buffer, params,
                p_req("message", param_string, &message),
		p_req("address", param_bitcoin_address, &scriptpubkey),
                NULL))
		return command_param_failed();

	const size_t script_len = tal_bytelen(scriptpubkey);

	/* FIXME: we already had the address from the input */
	char *addr;
	addr = encode_scriptpubkey_to_addr(tmpctx, chainparams, scriptpubkey);

	if (!is_p2wpkh(scriptpubkey, script_len, NULL)) {
		/* FIXME add support for BIP 322 */
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Address is not p2wpkh and "
				    "it is not supported for signing");
	}

	if (!hsm_capable(cmd->ld, WIRE_HSMD_BIP137_SIGN_MESSAGE)) {
		return command_fail(
		    cmd, JSONRPC2_INVALID_PARAMS,
		    "HSM does not support signing BIP137 signing.");
	}

	const u32 bip32_max_index =
	    db_get_intvar(cmd->ld->wallet->db, "bip32_max_index", 0);
        bool match_found = false;
	u32 keyidx;
        enum addrtype addrtype;

	/* loop over all generated keys, find a matching key */
	for (keyidx = 1; keyidx <= bip32_max_index; keyidx++) {
		bip32_pubkey(cmd->ld, &pubkey, keyidx);
		u8 *redeemscript_p2wpkh;
		char *out_p2wpkh = encode_pubkey_to_addr(
		    cmd, &pubkey, ADDR_BECH32, &redeemscript_p2wpkh);
		if (!out_p2wpkh) {
			abort();
		}
		/* wallet_get_addrtype fails for entries prior to v24.11, all
		 * address types are assumed in that case. */
		if (!wallet_get_addrtype(cmd->ld->wallet, keyidx, &addrtype))
			addrtype = ADDR_ALL;
		if (streq(addr, out_p2wpkh) &&
		    (addrtype == ADDR_BECH32 || addrtype == ADDR_ALL)) {
			match_found = true;
			break;
		}
	}

	if (!match_found) {
		return command_fail(
		    cmd, JSONRPC2_INVALID_PARAMS,
		    "Address is not found in the wallet's database");
	}

	/* wire to hsmd a sign request */
	u8 *msg = towire_hsmd_bip137_sign_message(
	    cmd, tal_dup_arr(tmpctx, u8, (u8 *)message, strlen(message), 0),
	    keyidx);
	if (!wire_sync_write(cmd->ld->hsm_fd, take(msg))) {
		fatal("Could not write sign_with_key to HSM: %s",
		      strerror(errno));
	}

	/* read form hsmd a sign reply */
	msg = wire_sync_read(cmd, cmd->ld->hsm_fd);

	int recid;
	u8 sig[65];
	secp256k1_ecdsa_recoverable_signature rsig;

	if (!fromwire_hsmd_bip137_sign_message_reply(msg, &rsig)) {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "HSM gave bad sign_with_key_reply %s",
				    tal_hex(tmpctx, msg));
	}

	secp256k1_ecdsa_recoverable_signature_serialize_compact(
	    secp256k1_ctx, sig + 1, &recid, &rsig);
        /* this is the header value for P2WPKH specified in BIP137 */
	sig[0] = recid + 39;

	/* FIXME: Given the fact that we plan to extend support for BIP322
         * signature in the future making a pubkey output here makes less sense. */
	struct json_stream *response;
	response = json_stream_success(cmd);
	json_add_string(response, "address", addr);
	json_add_pubkey(response, "pubkey", &pubkey);
	json_add_hex(response, "signature", sig, sizeof(sig));
	json_add_string(response, "base64",
			b64_encode(tmpctx, sig, sizeof(sig)));
	return command_success(cmd, response);
}

static const struct json_command signmessagewithkey_command = {
	"signmessagewithkey",
	json_signmessagewithkey
};
AUTODATA(json_command, &signmessagewithkey_command);

static struct command_result *
json_listnetworkevents(struct command *cmd,
		       const char *buffer,
		       const jsmntok_t *obj UNNEEDED,
		       const jsmntok_t *params)
{
	struct node_id *specific_id;
	enum wait_index *listindex;
	u64 *liststart;
	u32 *listlimit;
	struct db_stmt *stmt;
	struct json_stream *response;

	if (!param(cmd, buffer, params,
		   p_opt("id", param_node_id, &specific_id),
		   p_opt("index", param_index, &listindex),
		   p_opt_def("start", param_u64, &liststart, 0),
		   p_opt("limit", param_u32, &listlimit),
		   NULL))
		return command_param_failed();

	response = json_stream_success(cmd);
	json_array_start(response, "networkevents");
	stmt = wallet_network_events_first(cmd->ld->wallet,
					   specific_id,
					   *liststart,
					   listlimit);
	while (stmt) {
		u64 id;
		struct node_id peer_id;
		enum network_event etype;
		const char *reason;
		u64 timestamp, duration_nsec;
		bool connect_attempted;

		wallet_network_events_extract(tmpctx, stmt,
					      &id, &peer_id, &timestamp, &etype,
					      &reason, &duration_nsec,
					      &connect_attempted);
		json_object_start(response, NULL);
		json_add_u64(response, "created_index", id);
		json_add_node_id(response, "peer_id", &peer_id);
		json_add_string(response, "type", network_event_name(etype));
		json_add_u64(response, "timestamp", timestamp);
		if (reason)
			json_add_string(response, "reason", reason);
		if (duration_nsec)
			json_add_u64(response, "duration_nsec", duration_nsec);
		if (etype == NETWORK_EVENT_CONNECTFAIL)
			json_add_bool(response, "connect_attempted", connect_attempted);
		json_object_end(response);
		stmt = wallet_network_events_next(cmd->ld->wallet, stmt);
	}
	json_array_end(response);
	return command_success(cmd, response);
}

static const struct json_command listnetworkevents_cmd = {
	"listnetworkevents",
	json_listnetworkevents
};
AUTODATA(json_command, &listnetworkevents_cmd);

static struct command_result *json_delnetworkevent(struct command *cmd,
						   const char *buffer,
						   const jsmntok_t *obj UNNEEDED,
						   const jsmntok_t *params)
{
	u64 *created_index;

	if (!param(cmd, buffer, params,
		   p_req("created_index", param_u64, &created_index),
		   NULL))
		return command_param_failed();

	if (!wallet_network_event_delete(cmd->ld->wallet, *created_index))
		return command_fail(cmd, DELNETWORKEVENT_NOT_FOUND,
				    "Could not find that networkevent");

	return command_success(cmd, json_stream_success(cmd));
}

static const struct json_command delnetworkevent_command = {
	"delnetworkevent",
	json_delnetworkevent,
};
AUTODATA(json_command, &delnetworkevent_command);
