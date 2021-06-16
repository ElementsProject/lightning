#include <bitcoin/address.h>
#include <bitcoin/base58.h>
#include <bitcoin/script.h>
#include <bitcoin/tx.h>
#include <ccan/cast/cast.h>
#include <ccan/tal/str/str.h>
#include <common/addr.h>
#include <common/bech32.h>
#include <common/json_command.h>
#include <common/json_helpers.h>
#include <common/jsonrpc_errors.h>
#include <common/key_derive.h>
#include <common/param.h>
#include <common/pseudorand.h>
#include <common/status.h>
#include <common/utils.h>
#include <common/utxo.h>
#include <errno.h>
#include <hsmd/hsmd_wiregen.h>
#include <inttypes.h>
#include <lightningd/bitcoind.h>
#include <lightningd/chaintopology.h>
#include <lightningd/hsm_control.h>
#include <lightningd/json.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/lightningd.h>
#include <lightningd/log.h>
#include <lightningd/options.h>
#include <lightningd/peer_control.h>
#include <lightningd/subd.h>
#include <wallet/wallet.h>
#include <wallet/walletrpc.h>
#include <wally_bip32.h>
#include <wire/wire_sync.h>

/* May return NULL if encoding error occurs. */
static char *
encode_pubkey_to_addr(const tal_t *ctx,
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
				     chainparams,
				     &h160);
	} else {
		hrp = chainparams->bip173_name;

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

	p2sh = encode_pubkey_to_addr(cmd, &pubkey, true, NULL);
	bech32 = encode_pubkey_to_addr(cmd, &pubkey, false, NULL);
	if (!p2sh || !bech32) {
		return command_fail(cmd, LIGHTNINGD,
				    "p2wpkh address encoding failure.");
	}

	response = json_stream_success(cmd);
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

		if (keyidx == BIP32_INITIAL_HARDENED_CHILD){
			break;
		}

		if (!bip32_pubkey(cmd->ld->wallet->bip32_base, &pubkey, keyidx))
			abort();

		// p2sh
		u8 *redeemscript_p2sh;
		char *out_p2sh = encode_pubkey_to_addr(cmd,
						       &pubkey,
						       true,
						       &redeemscript_p2sh);

		// bech32 : p2wpkh
		u8 *redeemscript_p2wpkh;
		char *out_p2wpkh = encode_pubkey_to_addr(cmd,
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

static void json_add_utxo(struct json_stream *response,
			  const char *fieldname,
			  struct wallet *wallet,
			  const struct utxo *utxo)
{
	const char *out;
	bool reserved;

	json_object_start(response, fieldname);
	json_add_txid(response, "txid", &utxo->txid);
	json_add_num(response, "output", utxo->outnum);
	json_add_amount_sat_compat(response, utxo->amount,
				   "value", "amount_msat");

	if (utxo->is_p2sh) {
		struct pubkey key;
		bip32_pubkey(wallet->bip32_base, &key, utxo->keyindex);

		json_add_hex_talarr(response, "redeemscript",
				    bitcoin_redeem_p2sh_p2wpkh(tmpctx, &key));
	}

	json_add_hex_talarr(response, "scriptpubkey", utxo->scriptPubkey);
	out = encode_scriptpubkey_to_addr(tmpctx, chainparams,
					  utxo->scriptPubkey);
	if (!out)
		log_broken(wallet->log,
			   "Could not encode utxo %s:%u%s!",
			   type_to_string(tmpctx,
					  struct bitcoin_txid,
					  &utxo->txid),
			   utxo->outnum,
			   utxo->close_info ? " (has close_info)" : "");
	else
		json_add_string(response, "address", out);

	if (utxo->spendheight)
		json_add_string(response, "status", "spent");
	else if (utxo->blockheight) {
		json_add_string(response, "status", "confirmed");
		json_add_num(response, "blockheight", *utxo->blockheight);
	} else
		json_add_string(response, "status", "unconfirmed");

	reserved = utxo_is_reserved(utxo,
				    get_block_height(wallet->ld->topology));
	json_add_bool(response, "reserved", reserved);
	if (reserved)
		json_add_num(response, "reserved_to_block",
			     utxo->reserved_til);
	json_object_end(response);
}

void json_add_utxos(struct json_stream *response,
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
	list_for_each(&cmd->ld->peers, p, list) {
		struct channel *c;
		list_for_each(&p->channels, c, list) {
			/* We don't print out uncommitted channels */
			if (channel_unsaved(c))
				continue;
			json_object_start(response, NULL);
			json_add_node_id(response, "peer_id", &p->id);
			/* Mirrors logic in listpeers */
			json_add_bool(response, "connected",
				      channel_active(c) && c->connected);
			json_add_string(response, "state",
					channel_state_name(c));
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
	"Returns a list of funds (outputs) that can be used "
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
		bitcoind_getutxout(
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
	rescan->utxos = wallet_get_utxos(rescan, cmd->ld->wallet, OUTPUT_STATE_ANY);
	if (tal_count(rescan->utxos) == 0) {
		json_array_end(rescan->response);
		return command_success(cmd, rescan->response);
	}
	bitcoind_getutxout(cmd->ld->topology->bitcoind, &rescan->utxos[0]->txid,
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

#if EXPERIMENTAL_FEATURES
static const char *txtype_to_string(enum wallet_tx_type t)
{
	for (size_t i = 0; wallet_tx_type_display_names[i].name != NULL; i++)
		if (t == wallet_tx_type_display_names[i].t)
			return wallet_tx_type_display_names[i].name;
	return NULL;
}

static void json_add_txtypes(struct json_stream *result, const char *fieldname, enum wallet_tx_type value)
{
	json_array_start(result, fieldname);
	for (size_t i = 0; wallet_tx_type_display_names[i].name != NULL; i++) {
		if (value & wallet_tx_type_display_names[i].t)
			json_add_string(result, NULL, wallet_tx_type_display_names[i].name);
	}
	json_array_end(result);
}
#endif
static void json_transaction_details(struct json_stream *response,
				     const struct wallet_transaction *tx)
{
	struct wally_tx *wtx = tx->tx->wtx;

		json_object_start(response, NULL);
		json_add_txid(response, "hash", &tx->id);
		json_add_hex_talarr(response, "rawtx", tx->rawtx);
		json_add_num(response, "blockheight", tx->blockheight);
		json_add_num(response, "txindex", tx->txindex);
#if EXPERIMENTAL_FEATURES
		if (tx->annotation.type != 0)
			json_add_txtypes(response, "type", tx->annotation.type);

		if (tx->annotation.channel.u64 != 0)
			json_add_short_channel_id(response, "channel", &tx->annotation.channel);
#endif
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
#if EXPERIMENTAL_FEATURES
			struct tx_annotation *ann = &tx->input_annotations[i];
			const char *txtype = txtype_to_string(ann->type);
			if (txtype != NULL)
				json_add_string(response, "type", txtype);
			if (ann->channel.u64 != 0)
				json_add_short_channel_id(response, "channel", &ann->channel);
#endif

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
			if (deprecated_apis)
				json_add_amount_sat_only(response, "satoshis", sat);
			json_add_amount_sat_only(response, "msat", sat);

#if EXPERIMENTAL_FEATURES
			struct tx_annotation *ann = &tx->output_annotations[i];
			const char *txtype = txtype_to_string(ann->type);
			if (txtype != NULL)
				json_add_string(response, "type", txtype);

			if (ann->channel.u64 != 0)
				json_add_short_channel_id(response, "channel", &ann->channel);
#endif
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
    false,
    "Returns transactions tracked in the wallet. This includes deposits, "
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
	for (size_t i = 0; i < psbt->tx->num_inputs; i++) {
		struct utxo *utxo;
		struct bitcoin_txid txid;

		if (only_inputs && !in_only_inputs(only_inputs, i))
			continue;

		wally_tx_input_get_txid(&psbt->tx->inputs[i], &txid);
		utxo = wallet_utxo_get(*utxos, cmd->ld->wallet,
				       &txid, psbt->tx->inputs[i].index);
		if (!utxo) {
			if (only_inputs)
				return command_fail(cmd, LIGHTNINGD,
						    "Aborting PSBT signing. UTXO %s:%u is unknown (and specified by signonly)",
						    type_to_string(tmpctx, struct bitcoin_txid,
								   &txid),
						    psbt->tx->inputs[i].index);
			continue;
		}

		/* Oops we haven't reserved this utxo yet! */
		if (!utxo_is_reserved(utxo, get_block_height(cmd->ld->topology)))
			return command_fail(cmd, LIGHTNINGD,
					    "Aborting PSBT signing. UTXO %s:%u is not reserved",
					    type_to_string(tmpctx, struct bitcoin_txid,
							   &utxo->txid),
					    utxo->outnum);
		tal_arr_expand(utxos, utxo);
	}

	return NULL;
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

	if (!param(cmd, buffer, params,
		   p_req("psbt", param_psbt, &psbt),
		   p_opt("signonly", param_input_numbers, &input_nums),
		   NULL))
		return command_param_failed();

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
		fatal("HSM gave bad sign_withdrawal_reply %s",
		      tal_hex(tmpctx, msg));

	response = json_stream_success(cmd);
	json_add_psbt(response, "signed_psbt", signed_psbt);
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

struct sending_psbt {
	struct command *cmd;
	struct utxo **utxos;
	struct wally_tx *wtx;
	u32 reserve_blocks;
};

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

	wallet_transaction_add(ld->wallet, sending->wtx, 0, 0);

	/* Extract the change output and add it to the DB */
	wallet_extract_owned_outputs(ld->wallet, sending->wtx, NULL, &change);

	response = json_stream_success(sending->cmd);
	wally_txid(sending->wtx, &txid);
	json_add_hex_talarr(response, "tx", linearize_wtx(tmpctx, sending->wtx));
	json_add_txid(response, "txid", &txid);
	was_pending(command_success(sending->cmd, response));
}

static struct command_result *json_sendpsbt(struct command *cmd,
					    const char *buffer,
					    const jsmntok_t *obj UNNEEDED,
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
			   tal_hex(tmpctx,
				   linearize_wtx(tmpctx, sending->wtx)),
			   sendpsbt_done, sending);

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
