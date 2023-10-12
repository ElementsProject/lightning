#include "config.h"
#include <bitcoin/base58.h>
#include <bitcoin/script.h>
#include <ccan/array_size/array_size.h>
#include <ccan/cast/cast.h>
#include <common/addr.h>
#include <common/bech32.h>
#include <common/configdir.h>
#include <common/json_command.h>
#include <common/json_param.h>
#include <common/key_derive.h>
#include <common/psbt_keypath.h>
#include <common/psbt_open.h>
#include <common/type_to_string.h>
#include <db/exec.h>
#include <errno.h>
#include <hsmd/hsmd_wiregen.h>
#include <lightningd/chaintopology.h>
#include <lightningd/channel.h>
#include <lightningd/coin_mvts.h>
#include <lightningd/hsm_control.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/lightningd.h>
#include <lightningd/peer_control.h>
#include <wallet/txfilter.h>
#include <wallet/walletrpc.h>
#include <wally_psbt.h>
#include <wire/wire_sync.h>

enum addrtype {
	/* Deprecated! */
	ADDR_P2SH_SEGWIT = 1,
	ADDR_BECH32 = 2,
	ADDR_P2TR = 4,
	ADDR_ALL = (ADDR_P2SH_SEGWIT + ADDR_BECH32 + ADDR_P2TR)
};

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
	struct sha256 h;
	struct ripemd160 h160;
	u8 *redeemscript;
	bool ok;

	assert(addrtype != ADDR_ALL);

	if (addrtype == ADDR_P2SH_SEGWIT) {
		redeemscript = bitcoin_redeem_p2sh_p2wpkh(ctx, pubkey);
		sha256(&h, redeemscript, tal_count(redeemscript));
		ripemd160(&h160, h.u.u8, sizeof(h));
		out = p2sh_to_base58(ctx,
				     chainparams,
				     &h160);
	} else if (addrtype == ADDR_BECH32) {
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
		if (!ok)
			out = tal_free(out);
	} else {
		assert(addrtype == ADDR_P2TR);
		u8 *p2tr_spk = scriptpubkey_p2tr(ctx, pubkey);
		u8 *x_key = p2tr_spk + 2;
		hrp = chainparams->onchain_hrp;

		redeemscript = NULL;

		/* out buffer is 73 + strlen(human readable part),
		 * see common/bech32.h*/
		out = tal_arr(ctx, char, 73 + strlen(hrp));

		ok = segwit_addr_encode(out, hrp, /* witver */ 1, x_key, 32);
		if (!ok)
			out = tal_free(out);
	}

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
	if (cmd->ld->deprecated_apis
	    && json_tok_streq(buffer, tok, "p2sh-segwit"))
		**addrtype = ADDR_P2SH_SEGWIT;
	else if (json_tok_streq(buffer, tok, "bech32"))
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

static struct command_result *json_newaddr(struct command *cmd,
					   const char *buffer,
					   const jsmntok_t *obj UNNEEDED,
					   const jsmntok_t *params)
{
	struct json_stream *response;
	struct pubkey pubkey;
	enum addrtype *addrtype;
	s64 keyidx;
	char *p2sh, *bech32, *p2tr;
	u8 *b32script;
	u8 *p2tr_script;

	if (!param(cmd, buffer, params,
		   p_opt_def("addresstype", param_newaddr, &addrtype, ADDR_BECH32),
		   NULL))
		return command_param_failed();

	keyidx = wallet_get_newindex(cmd->ld);
	if (keyidx < 0) {
		return command_fail(cmd, LIGHTNINGD, "Keys exhausted ");
	}

	bip32_pubkey(cmd->ld, &pubkey, keyidx);

	b32script = scriptpubkey_p2wpkh(tmpctx, &pubkey);
	p2tr_script = scriptpubkey_p2tr(tmpctx, &pubkey);
	if (*addrtype & ADDR_BECH32)
		txfilter_add_scriptpubkey(cmd->ld->owned_txfilter, b32script);
	if (*addrtype & ADDR_P2TR)
		txfilter_add_scriptpubkey(cmd->ld->owned_txfilter, p2tr_script);
	if (cmd->ld->deprecated_apis && (*addrtype & ADDR_P2SH_SEGWIT))
		txfilter_add_scriptpubkey(cmd->ld->owned_txfilter,
					  scriptpubkey_p2sh(tmpctx, b32script));

	p2sh = encode_pubkey_to_addr(cmd, &pubkey, ADDR_P2SH_SEGWIT, NULL);
	bech32 = encode_pubkey_to_addr(cmd, &pubkey, ADDR_BECH32, NULL);
	p2tr = encode_pubkey_to_addr(cmd, &pubkey, ADDR_P2TR, NULL);
	if (!p2sh || !bech32 || !p2tr) {
		return command_fail(cmd, LIGHTNINGD,
				    "p2wpkh address encoding failure.");
	}

	response = json_stream_success(cmd);
	if (*addrtype & ADDR_BECH32)
		json_add_string(response, "bech32", bech32);
	if (*addrtype & ADDR_P2TR)
		json_add_string(response, "p2tr", p2tr);
	if (cmd->ld->deprecated_apis && (*addrtype & ADDR_P2SH_SEGWIT))
		json_add_string(response, "p2sh-segwit", p2sh);
	return command_success(cmd, response);
}

static const struct json_command newaddr_command = {
	"newaddr",
	"bitcoin",
	json_newaddr,
	"Get a new {bech32} (or all) address to fund a channel",
	.verbose = "Generates a new address that belongs to the internal wallet. Funds sent to these addresses will be managed by lightningd. Use `withdraw` to withdraw funds to an external wallet."
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

		if (keyidx == BIP32_INITIAL_HARDENED_CHILD){
			break;
		}

		bip32_pubkey(cmd->ld, &pubkey, keyidx);

		// p2sh
		u8 *redeemscript_p2sh;
		char *out_p2sh = encode_pubkey_to_addr(cmd,
						       &pubkey,
						       ADDR_P2SH_SEGWIT,
						       &redeemscript_p2sh);

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
		json_add_string(response, "p2sh", out_p2sh);
		json_add_hex_talarr(response, "p2sh_redeemscript",
				    redeemscript_p2sh);
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
	"developer",
	json_listaddrs,
	"Show addresses list up to derivation {index} (default is the last bip32 index)",
	.verbose = "Show addresses of your internal wallet. Use `newaddr` to generate a new address.",
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

	if (utxo->is_p2sh) {
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
			   type_to_string(tmpctx,
					  struct bitcoin_outpoint,
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
	struct utxo **utxos, **reserved_utxos, **spent_utxos;
	bool *spent;

	if (!param(cmd, buffer, params,
		   p_opt_def("spent", param_bool, &spent, false),
		   NULL))
		return command_param_failed();

	response = json_stream_success(cmd);

	utxos = wallet_get_utxos(cmd, cmd->ld->wallet, OUTPUT_STATE_AVAILABLE);
	reserved_utxos = wallet_get_utxos(cmd, cmd->ld->wallet, OUTPUT_STATE_RESERVED);

	json_array_start(response, "outputs");
	json_add_utxos(response, cmd->ld->wallet, utxos);
	json_add_utxos(response, cmd->ld->wallet, reserved_utxos);

	if (*spent) {
		spent_utxos = wallet_get_utxos(cmd, cmd->ld->wallet, OUTPUT_STATE_SPENT);
		json_add_utxos(response, cmd->ld->wallet, spent_utxos);
	}

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
							  c->scid);

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
	"utility",
	json_listfunds,
	"Show available funds from the internal wallet",
	.verbose = "Returns a list of funds (outputs) that can be used "
	"by the internal wallet to open new channels "
	"or can be withdrawn, using the `withdraw` command, to another wallet. "
	"Includes spent outputs if {spent} is set to true."
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
		bitcoind_getutxout(bitcoind->ld->topology->bitcoind,
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
	rescan->utxos = wallet_get_utxos(rescan, cmd->ld->wallet, OUTPUT_STATE_ANY);
	if (tal_count(rescan->utxos) == 0) {
		json_array_end(rescan->response);
		return command_success(cmd, rescan->response);
	}
	bitcoind_getutxout(cmd->ld->topology->bitcoind,
			   &rescan->utxos[0]->outpoint,
			   process_utxo_result,
			   rescan);
	return command_still_pending(cmd);
}

static const struct json_command dev_rescan_output_command = {
	"dev-rescan-outputs",
	"developer",
	json_dev_rescan_outputs,
	"Synchronize the state of our funds with bitcoind",
	.verbose = "For each output stored in the internal wallet ask `bitcoind` whether we are in sync with its state (spent vs. unspent)",
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

	txs = wallet_transactions_get(cmd->ld->wallet, cmd);

	response = json_stream_success(cmd);
	json_array_start(response, "transactions");
	for (size_t i = 0; i < tal_count(txs); i++)
		json_transaction_details(response, &txs[i]);

	json_array_end(response);
	return command_success(cmd, response);
}

static const struct json_command listtransactions_command = {
    "listtransactions",
    "payment",
    json_listtransactions,
    "List transactions that we stored in the wallet",
    .verbose = "Returns transactions tracked in the wallet. This includes deposits, "
    "withdrawals and transactions related to channels. A transaction may have "
    "multiple types, e.g., a transaction may both be a close and a deposit if "
    "it closes the channel and returns funds to the wallet."
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
						    type_to_string(tmpctx, struct bitcoin_outpoint,
								   &outpoint));
			continue;
		}

		/* Oops we haven't reserved this utxo yet! */
		if (!utxo_is_reserved(utxo, get_block_height(cmd->ld->topology)))
			return command_fail(cmd, LIGHTNINGD,
					    "Aborting PSBT signing. UTXO %s is not reserved",
					    type_to_string(tmpctx, struct bitcoin_outpoint,
							   &utxo->outpoint));

		/* If the psbt doesn't have the UTXO info yet, add it.
		 * We only add the witness_utxo for this */
		if (!psbt->inputs[i].utxo && !psbt->inputs[i].witness_utxo) {
			u8 *scriptPubKey;

			if (utxo->is_p2sh) {
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

static void match_psbt_outputs_to_wallet(struct wally_psbt *psbt,
				  struct wallet *w)
{
	tal_wally_start();
	for (size_t outndx = 0; outndx < psbt->num_outputs; ++outndx) {
		u32 index;
		bool is_p2sh;
		const u8 *script;
		struct ext_key ext;

		script = wally_psbt_output_get_script(tmpctx,
						    &psbt->outputs[outndx]);
		if (!script)
			continue;

		if (!wallet_can_spend(w, script, &index, &is_p2sh))
			continue;

		if (bip32_key_from_parent(
			    w->ld->bip32_base, index, BIP32_FLAG_KEY_PUBLIC, &ext) != WALLY_OK) {
			abort();
		}

		psbt_output_set_keypath(index, &ext, is_p2tr(script, NULL),
					&psbt->outputs[outndx]);
	}
	tal_wally_end(psbt);
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
	u32 *input_nums;
	u32 psbt_version;

	if (!param(cmd, buffer, params,
		   p_req("psbt", param_psbt, &psbt),
		   p_opt("signonly", param_input_numbers, &input_nums),
		   NULL))
		return command_param_failed();

	/* We internally deal with v2 only but we want to return V2 if given */
	psbt_version = psbt->version;
	if (!psbt_set_version(psbt, 2)) {
		return command_fail(cmd, LIGHTNINGD,
				    "Could not set PSBT version: %s",
					 type_to_string(tmpctx, struct wally_psbt,
					 	psbt));
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
				    "No wallet inputs to sign");

	/* Update the keypaths on any outputs that are in our wallet (change addresses). */
	match_psbt_outputs_to_wallet(psbt, cmd->ld->wallet);

	/* FIXME: hsm will sign almost anything, but it should really
	 * fail cleanly (not abort!) and let us report the error here. */
	u8 *msg = towire_hsmd_sign_withdrawal(cmd,
					     cast_const2(const struct utxo **, utxos),
					     psbt);

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
				    type_to_string(tmpctx, struct wally_psbt,
						   signed_psbt));
	}

	if (!psbt_set_version(combined_psbt, psbt_version)) {
		return command_fail(cmd, LIGHTNINGD,
				    "Signed PSBT unable to have version set: %s",
					 type_to_string(tmpctx, struct wally_psbt,
					 	combined_psbt));
	}

	response = json_stream_success(cmd);
	json_add_psbt(response, "signed_psbt", combined_psbt);
	return command_success(cmd, response);
}

static const struct json_command signpsbt_command = {
	"signpsbt",
	"bitcoin",
	json_signpsbt,
	"Sign this wallet's inputs on a provided PSBT.",
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

    if (!param(cmd, buffer, params,
           p_req("psbt", param_psbt, &psbt),
           p_req("version", param_number, &version),
           NULL))
        return command_param_failed();

    if (!psbt_set_version(psbt, *version)) {
        return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
                    "Could not set PSBT version");
    }

    response = json_stream_success(cmd);
    json_add_psbt(response, "psbt", psbt);

    return command_success(cmd, response);
}

static const struct json_command setpsbtversion_command = {
	"setpsbtversion",
	"bitcoin",
	json_setpsbtversion,
	"Convert a given PSBT to the {version} requested (v0 or v2)",
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
	bool is_p2sh;
	const u8 *script;

	/* If it's not going to an external address, ignore */
	if (!psbt_output_to_external(&psbt->outputs[outnum]))
		return;

	/* If it's going to our wallet, ignore */
	script = wally_psbt_output_get_script(tmpctx,
					    &psbt->outputs[outnum]);
	if (wallet_can_spend(ld->wallet, script, &index, &is_p2sh))
		return;

	outpoint.txid = *txid;
	outpoint.n = outnum;
	amount = psbt_output_get_amount(psbt, outnum);

	mvt = new_coin_external_deposit(NULL, &outpoint,
					0, amount,
					DEPOSIT);

	mvt->originating_acct = WALLET;
	notify_chain_mvt(ld, mvt);
	tal_free(mvt);
}


static void sendpsbt_done(struct bitcoind *bitcoind UNUSED,
			  bool success, const char *msg,
			  struct sending_psbt *sending)
{
	struct lightningd *ld = sending->cmd->ld;
	struct json_stream *response;
	struct bitcoin_txid txid;
	struct amount_sat change;

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
					 type_to_string(tmpctx, struct wally_tx,
							sending->wtx)));
		return;
	}

	/* Internal-only after, set to v2 */
	if (!psbt_set_version(sending->psbt, 2)) {
		abort(); // Send succeeded but later calls may fail
	}

	wallet_transaction_add(ld->wallet, sending->wtx, 0, 0);

	/* Extract the change output and add it to the DB */
	wallet_extract_owned_outputs(ld->wallet, sending->wtx, false, NULL, &change);
	wally_txid(sending->wtx, &txid);

	for (size_t i = 0; i < sending->psbt->num_outputs; i++)
		maybe_notify_new_external_send(ld, &txid, i, sending->psbt);

	response = json_stream_success(sending->cmd);
	json_add_hex_talarr(response, "tx", linearize_wtx(tmpctx, sending->wtx));
	json_add_txid(response, "txid", &txid);
	was_pending(command_success(sending->cmd, response));
}

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

	if (!param(cmd, buffer, params,
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
				    type_to_string(tmpctx, struct wally_psbt,
						   psbt));

	/* We have to find/locate the utxos that are ours on this PSBT,
	 * so that we know who to mark as used.
	 */
	res = match_psbt_inputs_to_utxos(cmd, psbt, NULL, &sending->utxos);
	if (res)
		return res;

	for (size_t i = 0; i < tal_count(sending->utxos); i++) {
		if (!wallet_reserve_utxo(ld->wallet, sending->utxos[i],
					 get_block_height(ld->topology),
					 sending->reserve_blocks))
			fatal("UTXO not reservable?");
	}

	/* Now broadcast the transaction */
	bitcoind_sendrawtx(cmd->ld->topology->bitcoind,
			   cmd->id,
			   tal_hex(tmpctx,
				   linearize_wtx(tmpctx, sending->wtx)),
			   false, sendpsbt_done, sending);

	return command_still_pending(cmd);
}

static const struct json_command sendpsbt_command = {
	"sendpsbt",
	"bitcoin",
	json_sendpsbt,
	"Finalize, extract and send a PSBT.",
	false
};

AUTODATA(json_command, &sendpsbt_command);
