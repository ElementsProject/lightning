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
#include <common/wallet_tx.h>
#include <common/withdraw_tx.h>
#include <errno.h>
#include <hsmd/gen_hsm_wire.h>
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

struct tx_broadcast {
	struct command *cmd;
	const struct utxo **utxos;
	const struct wally_tx *wtx;
	struct amount_sat *expected_change;
};

static struct tx_broadcast *unreleased_tx_to_broadcast(const tal_t *ctx,
						       struct command *cmd,
						       struct unreleased_tx *utx)
{
	struct tx_broadcast *txb = tal(ctx, struct tx_broadcast);
	struct amount_sat *change = tal(txb, struct amount_sat);

	txb->cmd = cmd;
	txb->utxos = utx->wtx->utxos;
	txb->wtx = utx->tx->wtx;
	*change = utx->wtx->change;
	txb->expected_change = change;
	return txb;
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
static void wallet_withdrawal_broadcast(struct bitcoind *bitcoind UNUSED,
					bool success, const char *msg,
					struct tx_broadcast *txb)
{
	struct command *cmd = txb->cmd;
	struct lightningd *ld = cmd->ld;

	/* FIXME: This won't be necessary once we use ccan/json_out! */
	/* Massage output into shape so it doesn't kill the JSON serialization */
	char *output = tal_strjoin(cmd, tal_strsplit(cmd, msg, "\n", STR_NO_EMPTY), " ", STR_NO_TRAIL);
	if (success) {
		struct bitcoin_txid txid;
		struct amount_sat change = AMOUNT_SAT(0);

		/* Mark used outputs as spent */
		wallet_confirm_utxos(ld->wallet, txb->utxos);

		/* Extract the change output and add it to the DB */
		wallet_extract_owned_outputs(ld->wallet, txb->wtx, NULL, &change);

		/* Note normally, change_satoshi == withdraw->wtx->change, but
		 * not if we're actually making a payment to ourselves! */
		if (txb->expected_change)
			assert(amount_sat_greater_eq(change, *txb->expected_change));

		struct json_stream *response = json_stream_success(cmd);
		wally_txid(txb->wtx, &txid);
		json_add_hex_talarr(response, "tx",
				    linearize_wtx(tmpctx, txb->wtx));
		json_add_txid(response, "txid", &txid);
		was_pending(command_success(cmd, response));
	} else {
		was_pending(command_fail(cmd, LIGHTNINGD,
					 "Error broadcasting transaction: %s. Unsent tx discarded %s",
					 output,
					 type_to_string(tmpctx, struct wally_tx, txb->wtx)));
	}
}

/* Signs the tx, broadcasts it: broadcast calls wallet_withdrawal_broadcast */
static struct command_result *broadcast_and_wait(struct command *cmd,
						 struct unreleased_tx *utx)
{
	struct wally_psbt *signed_psbt;
	struct wally_tx *signed_wtx;
	struct bitcoin_txid signed_txid;

	/* FIXME: hsm will sign almost anything, but it should really
	 * fail cleanly (not abort!) and let us report the error here. */
	u8 *msg = towire_hsm_sign_withdrawal(cmd, utx->wtx->utxos, utx->tx->psbt);

	if (!wire_sync_write(cmd->ld->hsm_fd, take(msg)))
		fatal("Could not write sign_withdrawal to HSM: %s",
		      strerror(errno));

	msg = wire_sync_read(cmd, cmd->ld->hsm_fd);

	if (!fromwire_hsm_sign_withdrawal_reply(utx, msg, &signed_psbt))
		fatal("HSM gave bad sign_withdrawal_reply %s",
		      tal_hex(tmpctx, msg));

	signed_wtx = psbt_finalize(signed_psbt, true);

	if (!signed_wtx) {
		/* Have the utx persist past this command */
		tal_steal(cmd->ld->wallet, utx);
		add_unreleased_tx(cmd->ld->wallet, utx);
		return command_fail(cmd, LIGHTNINGD,
				    "PSBT is not finalized %s",
				    type_to_string(tmpctx,
						   struct wally_psbt,
						   signed_psbt));
	}

	/* Sanity check */
	wally_txid(signed_wtx, &signed_txid);
	if (!bitcoin_txid_eq(&signed_txid, &utx->txid))
		fatal("HSM changed txid: unsigned %s, signed %s",
		      tal_hex(tmpctx, linearize_tx(tmpctx, utx->tx)),
		      tal_hex(tmpctx, linearize_wtx(tmpctx, signed_wtx)));

	/* Replace unsigned tx by signed tx. */
	wally_tx_free(utx->tx->wtx);
	utx->tx->wtx = tal_steal(utx->tx, signed_wtx);
	tal_free(utx->tx->psbt);
	utx->tx->psbt = tal_steal(utx->tx, signed_psbt);

	/* Now broadcast the transaction */
	bitcoind_sendrawtx(cmd->ld->topology->bitcoind,
			   tal_hex(tmpctx, linearize_tx(tmpctx, utx->tx)),
			   wallet_withdrawal_broadcast,
			   unreleased_tx_to_broadcast(cmd, cmd, utx));

	return command_still_pending(cmd);
}

/* Common code for withdraw and txprepare.
 *
 * Returns NULL on success, and fills in wtx, output and
 * maybe changekey (owned by cmd).  Otherwise, cmd has failed, so don't
 * access it! (It's been freed). */
static struct command_result *json_prepare_tx(struct command *cmd,
					      const char *buffer,
					      const jsmntok_t *params,
					      bool for_withdraw,
					      struct unreleased_tx **utx,
					      u32 *feerate)
{
	u32 *feerate_per_kw = NULL;
	struct command_result *result;
	u32 *minconf, maxheight;
	struct pubkey *changekey;
	struct bitcoin_tx_output **outputs;
	const jsmntok_t *outputstok = NULL, *t;
	const u8 *destination = NULL;
	size_t out_len, i;
	const struct utxo **chosen_utxos = NULL;
	u32 locktime;

	*utx = tal(cmd, struct unreleased_tx);
	(*utx)->wtx = tal(*utx, struct wallet_tx);
	wtx_init(cmd, (*utx)->wtx, AMOUNT_SAT(-1ULL));

	if (!for_withdraw) {
		/* From v0.7.3, the new style for *txprepare* use array of outputs
		 * to replace original 'destination' and 'satoshi' parameters.*/
		/* For generating help, give new-style. */
		if (!params || !deprecated_apis) {
			if (!param(cmd, buffer, params,
				   p_req("outputs", param_array, &outputstok),
				   p_opt("feerate", param_feerate, &feerate_per_kw),
				   p_opt_def("minconf", param_number, &minconf, 1),
				   p_opt("utxos", param_utxos, &chosen_utxos),
				   NULL))
				return command_param_failed();
		} else if (params->type == JSMN_ARRAY) {
			const jsmntok_t *firsttok, *secondtok, *thirdtok, *fourthtok;

			/* FIXME: This change completely destroyes the support for `check`. */
			if (!param(cmd, buffer, params,
				   p_req("outputs_or_destination", param_tok, &firsttok),
				   p_opt("feerate_or_sat", param_tok, &secondtok),
				   p_opt("minconf_or_feerate", param_tok, &thirdtok),
				   p_opt("utxos_or_minconf", param_tok, &fourthtok),
				   NULL))
				return command_param_failed();

			if (firsttok->type == JSMN_ARRAY) {
				/* New style:
				 * *txprepare* 'outputs' ['feerate'] ['minconf'] ['utxos'] */

				/* outputs (required) */
				outputstok = firsttok;

				/* feerate (optional) */
				if (secondtok) {
					result = param_feerate(cmd, "feerate", buffer,
							       secondtok, &feerate_per_kw);
					if (result)
						return result;
				}

				/* minconf (optional) */
				if (thirdtok) {
					result = param_number(cmd, "minconf", buffer,
							      thirdtok, &minconf);
					if (result)
						return result;
				} else {
					minconf = tal(cmd, u32);
					*minconf = 1;
				}

				/* utxos (optional) */
				if (fourthtok) {
					result = param_utxos(cmd, "utxos", buffer,
							     fourthtok, &chosen_utxos);
					if (result)
						return result;
				}
			} else {
				/* Old style:
				 * *txprepare* 'destination' 'satoshi' ['feerate'] ['minconf'] */

				/* destination (required) */
				result = param_bitcoin_address(cmd, "destination", buffer,
							       firsttok, &destination);
				if (result)
					return result;

				/* satoshi (required) */
				if (!secondtok)
					return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
							    "Need set 'satoshi' field.");
				result = param_wtx(cmd, "satoshi", buffer,
						   secondtok, (*utx)->wtx);
				if (result)
					return result;

				/* feerate (optional) */
				if (thirdtok) {
					result = param_feerate(cmd, "feerate", buffer,
							       thirdtok, &feerate_per_kw);
					if (result)
						return result;
				}

				/* minconf (optional) */
				if (fourthtok) {
					result = param_number(cmd, "minconf", buffer,
							      fourthtok, &minconf);
					if (result)
						return result;
				} else {
					minconf = tal(cmd, u32);
					*minconf = 1;
				}
			}
		} else {
			const jsmntok_t *satoshitok = NULL;
			if (!param(cmd, buffer, params,
				   p_opt("outputs", param_array, &outputstok),
				   p_opt("destination", param_bitcoin_address,
					 &destination),
				   p_opt("satoshi", param_tok, &satoshitok),
				   p_opt("feerate", param_feerate, &feerate_per_kw),
				   p_opt_def("minconf", param_number, &minconf, 1),
				   p_opt("utxos", param_utxos, &chosen_utxos),
				   NULL))
				/* If the parameters mixed the new style and the old style,
				 * fail it. */
				return command_param_failed();

			if (!outputstok) {
				if (!destination || !satoshitok)
					return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
							    "Need set 'outputs' field.");

				result = param_wtx(cmd, "satoshi", buffer,
						   satoshitok, (*utx)->wtx);
				if (result)
					return result;
			}
		}
	} else {
		/* *withdraw* command still use 'destination' and 'satoshi' as parameters. */
		if (!param(cmd, buffer, params,
			   p_req("destination", param_bitcoin_address,
				 &destination),
			   p_req("satoshi", param_wtx, (*utx)->wtx),
			   p_opt("feerate", param_feerate, &feerate_per_kw),
			   p_opt_def("minconf", param_number, &minconf, 1),
			   p_opt("utxos", param_utxos, &chosen_utxos),
			   NULL))
			return command_param_failed();
	}

	/* Setting the locktime to the next block to be mined has multiple
	 * benefits:
	 * - anti fee-snipping (even if not yet likely)
	 * - less distinguishable transactions (with this we create
	 *   general-purpose transactions which looks like bitcoind:
	 *   native segwit, nlocktime set to tip, and sequence set to
	 *   0xFFFFFFFE by default. Other wallets are likely to implement
	 *   this too).
	 */
	locktime = cmd->ld->topology->tip->height;
	/* Eventually fuzz it too. */
	if (pseudorand(10) == 0)
		locktime -= (u32)pseudorand(100);

	if (!feerate_per_kw) {
		/* We mainly use `txprepare` for opening transactions, and FEERATE_OPENING
		 * is kind of the new FEERATE_NORMAL so it fits well `withdraw` too. */
		result = param_feerate_estimate(cmd, &feerate_per_kw,
						FEERATE_OPENING);
		if (result)
			return result;
	}

	maxheight = minconf_to_maxheight(*minconf, cmd->ld);

	/* *withdraw* command or old *txprepare* command.
	 * Support only one output. */
	if (destination) {
		outputs = tal_arr(tmpctx, struct bitcoin_tx_output *, 1);
		outputs[0] = new_tx_output(outputs, (*utx)->wtx->amount,
					   destination);
		out_len = tal_count(outputs[0]->script);

		goto create_tx;
	}

	if (outputstok->size == 0)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS, "Empty outputs");

	outputs = tal_arr(tmpctx, struct bitcoin_tx_output *, outputstok->size);
	out_len = 0;
	(*utx)->wtx->all_funds = false;
	(*utx)->wtx->amount = AMOUNT_SAT(0);
	json_for_each_arr(i, t, outputstok) {
		struct amount_sat *amount;
		const u8 *destination;
		enum address_parse_result res;

		/* output format: {destination: amount} */
		if (t->type != JSMN_OBJECT)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "The output format must be "
					    "{destination: amount}");

		res = json_to_address_scriptpubkey(cmd,
						   chainparams,
						   buffer, &t[1],
						   &destination);
		if (res == ADDRESS_PARSE_UNRECOGNIZED)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Could not parse destination address");
		else if (res == ADDRESS_PARSE_WRONG_NETWORK)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Destination address is not on network %s",
					    chainparams->network_name);

		amount = tal(tmpctx, struct amount_sat);
		if (!json_to_sat_or_all(buffer, &t[2], amount))
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "'%.*s' is a invalid satoshi amount",
					    t[2].end - t[2].start, buffer + t[2].start);

		outputs[i] = new_tx_output(outputs, *amount,
					   cast_const(u8 *, destination));
		out_len += tal_count(destination);

		/* In fact, the maximum amount of bitcoin satoshi is 2.1e15.
		 * It can't be equal to/bigger than 2^64.
		 * On the hand, the maximum amount of litoshi is 8.4e15,
		 * which also can't overflow. */
		/* This means this destination need "all" satoshi we have. */
		if (amount_sat_eq(*amount, AMOUNT_SAT(-1ULL))) {
			if (outputstok->size > 1)
				return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
						    "outputs[%zi]: this destination wants"
						    " all satoshi. The count of outputs"
						    " can't be more than 1. ", i);
			(*utx)->wtx->all_funds = true;
			/* `AMOUNT_SAT(-1ULL)` is the max permissible for `wallet_select_all`. */
			(*utx)->wtx->amount = *amount;
			break;
		}

		if (!amount_sat_add(&(*utx)->wtx->amount, (*utx)->wtx->amount, *amount))
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "outputs: The sum of first %zi outputs"
					    " overflow. ", i);
	}

create_tx:
	if (chosen_utxos)
		result = wtx_from_utxos((*utx)->wtx, *feerate_per_kw,
					out_len, maxheight,
					chosen_utxos);
	else
		result = wtx_select_utxos((*utx)->wtx, *feerate_per_kw,
					  out_len, maxheight);

	if (result)
		return result;

	/* Because of the max limit of AMOUNT_SAT(-1ULL),
	 * `(*utx)->wtx->all_funds` won't change in `wtx_select_utxos()` */
	if ((*utx)->wtx->all_funds)
		outputs[0]->amount = (*utx)->wtx->amount;

	/* Add the change as the last output */
	if (!amount_sat_eq((*utx)->wtx->change, AMOUNT_SAT(0))) {
		struct bitcoin_tx_output *change_output;

		changekey = tal(tmpctx, struct pubkey);
		if (!bip32_pubkey(cmd->ld->wallet->bip32_base, changekey,
				  (*utx)->wtx->change_key_index))
			return command_fail(cmd, LIGHTNINGD, "Keys generation failure");

		change_output = new_tx_output(outputs, (*utx)->wtx->change,
					      scriptpubkey_p2wpkh(tmpctx, changekey));
		tal_arr_expand(&outputs, change_output);
	}

	(*utx)->outputs = tal_steal(*utx, outputs);
	(*utx)->tx = withdraw_tx(*utx, chainparams,
				 (*utx)->wtx->utxos,
				 (*utx)->outputs,
				 cmd->ld->wallet->bip32_base,
				 /* FIXME: Should probably be
				  * struct abs_locktime.
				  */
				 locktime);

	bitcoin_txid((*utx)->tx, &(*utx)->txid);

	if (feerate)
		*feerate = *feerate_per_kw;
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

	res = json_prepare_tx(cmd, buffer, params, false, &utx, NULL);
	if (res)
		return res;

	/* utx will persist past this command. */
	tal_steal(cmd->ld->wallet, utx);
	add_unreleased_tx(cmd->ld->wallet, utx);

	response = json_stream_success(cmd);
	json_add_tx(response, "unsigned_tx", utx->tx);
	json_add_txid(response, "txid", &utx->txid);
	json_add_psbt(response, "psbt", utx->tx->psbt);
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

	wallet_transaction_add(cmd->ld->wallet, utx->tx, 0, 0);
	wallet_transaction_annotate(cmd->ld->wallet, &utx->txid,
				    TX_UNKNOWN, 0);

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

	res = json_prepare_tx(cmd, buffer, params, true, &utx, NULL);
	if (res)
		return res;

	/* Store the transaction in the DB and annotate it as a withdrawal */
	wallet_transaction_add(cmd->ld->wallet, utx->tx, 0, 0);
	wallet_transaction_annotate(cmd->ld->wallet, &utx->txid,
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

bool is_reserved(const struct utxo *utxo, u32 current_height)
{
	if (utxo->status != output_state_reserved)
		return false;

	/* FIXME: Eventually this will always be set! */
	if (!utxo->reserved_til)
		return true;

	return *utxo->reserved_til > current_height;
}


static void json_add_utxo(struct json_stream *response,
			  const char *fieldname,
			  struct wallet *wallet,
			  const struct utxo *utxo)
{
	const char *out;

	json_object_start(response, fieldname);
	json_add_txid(response, "txid", &utxo->txid);
	json_add_num(response, "output", utxo->outnum);
	json_add_amount_sat_compat(response, utxo->amount,
				   "value", "amount_msat");

	if (utxo->scriptPubkey != NULL) {
		json_add_hex_talarr(response, "scriptpubkey", utxo->scriptPubkey);
		out = encode_scriptpubkey_to_addr(
			tmpctx, chainparams,
			utxo->scriptPubkey);
	} else {
		out = NULL;
#ifdef COMPAT_V072
		/* scriptpubkey was introduced in v0.7.3.
		 * We could handle close_info via HSM to get address,
		 * but who cares?  We'll print a warning though. */
		if (utxo->close_info == NULL) {
			struct pubkey funding_pubkey;
			bip32_pubkey(wallet->bip32_base,
				     &funding_pubkey,
				     utxo->keyindex);
			out = encode_pubkey_to_addr(tmpctx,
						    &funding_pubkey,
						    utxo->is_p2sh,
						    NULL);
		}
#endif
	}
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

	json_add_bool(response, "reserved",
		      is_reserved(utxo,
				  get_block_height(wallet->ld->topology)));
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
	struct utxo **utxos, **reserved_utxos;

	if (!param(cmd, buffer, params, NULL))
		return command_param_failed();

	response = json_stream_success(cmd);

	utxos = wallet_get_utxos(cmd, cmd->ld->wallet, output_state_available);
	reserved_utxos = wallet_get_utxos(cmd, cmd->ld->wallet, output_state_reserved);
	json_array_start(response, "outputs");
	json_add_utxos(response, cmd->ld->wallet, utxos);
	json_add_utxos(response, cmd->ld->wallet, reserved_utxos);
	json_array_end(response);

	/* Add funds that are allocated to channels */
	json_array_start(response, "channels");
	list_for_each(&cmd->ld->peers, p, list) {
		struct channel *c;
		list_for_each(&p->channels, c, list) {
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
	rescan->utxos = wallet_get_utxos(rescan, cmd->ld->wallet, output_state_any);
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
		json_add_u64(response, "blockheight", tx->blockheight);
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
			json_add_amount_sat_only(response, "satoshis", sat);

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

struct command_result *param_psbt(struct command *cmd,
				  const char *name,
				  const char *buffer,
				  const jsmntok_t *tok,
				  struct wally_psbt **psbt)
{
	/* Pull out the token into a string, then pass to
	 * the PSBT parser; PSBT parser can't handle streaming
	 * atm as it doesn't accept a len value */
	char *psbt_buff = json_strdup(cmd, buffer, tok);
	if (psbt_from_b64(psbt_buff, psbt))
		return NULL;

	return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			    "'%s' should be a PSBT, not '%.*s'",
			    name, json_tok_full_len(tok),
			    json_tok_full(buffer, tok));
}

static struct command_result *match_psbt_inputs_to_utxos(struct command *cmd,
							 struct wally_psbt *psbt,
							 struct utxo ***utxos)
{
	*utxos = tal_arr(cmd, struct utxo *, 0);
	for (size_t i = 0; i < psbt->tx->num_inputs; i++) {
		struct utxo *utxo;
		struct bitcoin_txid txid;

		wally_tx_input_get_txid(&psbt->tx->inputs[i], &txid);
		utxo = wallet_utxo_get(*utxos, cmd->ld->wallet,
				       &txid, psbt->tx->inputs[i].index);
		if (!utxo)
			continue;

		/* Oops we haven't reserved this utxo yet! */
		if (!is_reserved(utxo, get_block_height(cmd->ld->topology)))
			return command_fail(cmd, LIGHTNINGD,
					    "Aborting PSBT signing. UTXO %s:%u is not reserved",
					    type_to_string(tmpctx, struct bitcoin_txid,
							   &utxo->txid),
					    utxo->outnum);
		tal_arr_expand(utxos, utxo);
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

	if (!param(cmd, buffer, params,
		   p_req("psbt", param_psbt, &psbt),
		   NULL))
		return command_param_failed();

	/* We have to find/locate the utxos that are ours on this PSBT,
	 * so that the HSM knows how/what to sign for (it's possible some of
	 * our utxos require more complicated data to sign for e.g.
	 * closeinfo outputs */
	res = match_psbt_inputs_to_utxos(cmd, psbt, &utxos);
	if (res)
		return res;

	if (tal_count(utxos) == 0)
		return command_fail(cmd, LIGHTNINGD,
				    "No wallet inputs to sign");

	/* FIXME: hsm will sign almost anything, but it should really
	 * fail cleanly (not abort!) and let us report the error here. */
	u8 *msg = towire_hsm_sign_withdrawal(cmd,
					     cast_const2(const struct utxo **, utxos),
					     psbt);

	if (!wire_sync_write(cmd->ld->hsm_fd, take(msg)))
		fatal("Could not write sign_withdrawal to HSM: %s",
		      strerror(errno));

	msg = wire_sync_read(cmd, cmd->ld->hsm_fd);

	if (!fromwire_hsm_sign_withdrawal_reply(cmd, msg, &signed_psbt))
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

static struct command_result *json_sendpsbt(struct command *cmd,
					    const char *buffer,
					    const jsmntok_t *obj UNNEEDED,
					    const jsmntok_t *params)
{
	struct command_result *res;
	struct wally_psbt *psbt;
	struct wally_tx *w_tx;
	struct tx_broadcast *txb;
	struct utxo **utxos;

	if (!param(cmd, buffer, params,
		   p_req("psbt", param_psbt, &psbt),
		   NULL))
		return command_param_failed();

	w_tx = psbt_finalize(psbt, true);
	if (!w_tx)
		return command_fail(cmd, LIGHTNINGD,
				    "PSBT not finalizeable %s",
				    type_to_string(tmpctx, struct wally_psbt,
						   psbt));

	/* We have to find/locate the utxos that are ours on this PSBT,
	 * so that we know who to mark as used.
	 */
	res = match_psbt_inputs_to_utxos(cmd, psbt, &utxos);
	if (res)
		return res;

	txb = tal(cmd, struct tx_broadcast);
	txb->utxos = cast_const2(const struct utxo **,
				tal_steal(txb, utxos));
	txb->wtx = tal_steal(txb, w_tx);
	txb->cmd = cmd;
	txb->expected_change = NULL;

	/* Now broadcast the transaction */
	bitcoind_sendrawtx(cmd->ld->topology->bitcoind,
			   tal_hex(tmpctx, linearize_wtx(tmpctx, w_tx)),
			   wallet_withdrawal_broadcast, txb);

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
