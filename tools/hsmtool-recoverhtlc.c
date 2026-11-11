#include "config.h"
#include <bitcoin/chainparams.h>
#include <bitcoin/feerate.h>
#include <bitcoin/locktime.h>
#include <bitcoin/script.h>
#include <bitcoin/signature.h>
#include <bitcoin/varint.h>
#include <ccan/array_size/array_size.h>
#include <ccan/crypto/ripemd160/ripemd160.h>
#include <ccan/err/err.h>
#include <ccan/mem/mem.h>
#include <ccan/str/str.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/tal/str/str.h>
#include <common/addr.h>
#include <common/derive_basepoints.h>
#include <common/hsm_secret.h>
#include <common/htlc_tx.h>
#include <common/json_parse.h>
#include <common/key_derive.h>
#include <common/keyset.h>
#include <common/node_id.h>
#include <common/utils.h>
#include <string.h>
#include <tools/hsmtool-recoverhtlc.h>
#include <tools/lightning-hsmtool.h>

static bool derive_channel_basepoints(
	const struct node_id *peer_id,
	u64 channel_dbid,
	const char *hsm_secret_path,
	struct recoverhtlc_keys *keys,
	struct secret *htlc_basepoint_secret)
{
	struct secret hsm_secret, channel_seed;
	struct hsm_secret *hsms
		= hsmtool_load_hsm_secret(tmpctx, hsm_secret_path);

	/* Channel derivation always uses the first 32 bytes. */
	memcpy(hsm_secret.data, hsms->secret_data, sizeof(hsm_secret.data));
	derive_channel_seed(&channel_seed, hsm_secret.data,
			    peer_id, channel_dbid);

	if (!derive_htlc_basepoint(&channel_seed, &keys->our_htlc_basepoint,
				   htlc_basepoint_secret))
		return false;
	return derive_revocation_basepoint(&channel_seed,
					   &keys->our_revocation_basepoint,
					   NULL);
}

/* Derive keys to spend our HTLC outputs on the peer's commitment. */
bool hsmtool_recoverhtlc_derive_keys(
	const struct node_id *peer_id,
	u64 channel_dbid,
	const struct pubkey *commitment_point,
	const struct pubkey *remote_htlc_basepoint,
	const char *hsm_secret_path,
	struct recoverhtlc_keys *keys)
{
	struct secret htlc_basepoint_secret;

	if (!derive_channel_basepoints(peer_id, channel_dbid, hsm_secret_path,
				       keys, &htlc_basepoint_secret))
		return false;

	/* BOLT #3:
	 *
	 * pubkey = basepoint
	 *	    + SHA256(per_commitment_point || basepoint) * G
	 */
	if (!derive_simple_privkey(&htlc_basepoint_secret,
				   &keys->our_htlc_basepoint,
				   commitment_point,
				   &keys->our_htlc_privkey)
	    || !derive_simple_key(&keys->our_htlc_basepoint,
				  commitment_point,
				  &keys->our_htlc_key)
	    || !derive_simple_key(remote_htlc_basepoint,
				  commitment_point,
				  &keys->their_htlc_key))
		return false;

	/* Peer commitment: our basepoint, their commitment point. */
	return derive_revocation_key(&keys->our_revocation_basepoint,
				     commitment_point,
				     &keys->revocation_key);
}

/* Rebuild an HTLC witness script from the peer's commitment. */
static u8 *recovery_wscript(
	const tal_t *ctx,
	enum recoverhtlc_kind kind,
	bool anchors,
	const struct recoverhtlc_keys *keys,
	const struct ripemd160 *payment_ripemd,
	u32 cltv_expiry)
{
	struct abs_locktime expiry;
	struct keyset keyset = {
		.self_revocation_key = keys->revocation_key,
		.self_htlc_key = keys->their_htlc_key,
		.other_htlc_key = keys->our_htlc_key,
	};

	switch (kind) {
	/* The peer offered it, so this is their offered HTLC script. */
	case HTLC_THEY_OFFERED:
		return htlc_offered_wscript(ctx, payment_ripemd, &keyset,
					   anchors, false);

	/* We offered it, so this is the peer's received HTLC script. */
	case HTLC_WE_OFFERED:
		if (!blocks_to_abs_locktime(cltv_expiry, &expiry))
			return NULL;
		return htlc_received_wscript(ctx, payment_ripemd, &expiry,
					    &keyset, anchors, false);
	}
	abort();
}

/* Collect every output with this witness script, including identical MPPs. */
struct recoverhtlc_match *hsmtool_recoverhtlc_match_script(
	const tal_t *ctx,
	const struct bitcoin_tx *tx,
	enum recoverhtlc_kind kind,
	bool anchors,
	const u8 *wscript)
{
	struct recoverhtlc_match *match = tal(ctx, struct recoverhtlc_match);
	/* Commitment outputs contain the P2WSH hash, not the witness script. */
	const u8 *scriptpubkey = scriptpubkey_p2wsh(tmpctx, wscript);

	match->kind = kind;
	match->anchors = anchors;
	match->wscript = tal_dup_arr(match, u8, wscript, tal_bytelen(wscript), 0);
	match->outnums = tal_arr(match, size_t, 0);

	for (size_t i = 0; i < tx->wtx->num_outputs; i++) {
		const struct wally_tx_output *output = &tx->wtx->outputs[i];

		if (!memeq(output->script, output->script_len,
			   scriptpubkey, tal_bytelen(scriptpubkey)))
			continue;
		tal_arr_expand(&match->outnums, i);
	}

	if (tal_count(match->outnums) == 0)
		return tal_free(match);
	return match;
}

/* Find the requested HTLC without requiring its channel type. */
struct recoverhtlc_match *hsmtool_recoverhtlc_find_outputs(
	const tal_t *ctx,
	const struct bitcoin_tx *tx,
	enum recoverhtlc_kind kind,
	const struct recoverhtlc_keys *keys,
	const struct sha256 *payment_hash,
	u32 cltv_expiry)
{
	struct ripemd160 payment_ripemd;

	ripemd160(&payment_ripemd,
		  payment_hash->u.u8, sizeof(payment_hash->u.u8));

	/* Anchors append `1 CSV DROP`, changing the P2WSH hash.  Try both
	 * forms; only the negotiated form can match a commitment output. */
	for (int anchors = 0; anchors <= 1; anchors++) {
		struct recoverhtlc_match *match;
		const u8 *wscript = recovery_wscript(
			tmpctx, kind, anchors, keys,
			&payment_ripemd, cltv_expiry);

		if (!wscript)
			return NULL;
		match = hsmtool_recoverhtlc_match_script(
			ctx, tx, kind, anchors, wscript);
		/* A match also records which anchor form was used. */
		if (match)
			return match;
	}
	return NULL;
}

static void validate_recovery_inputs(
	const struct recoverhtlc_bundle *bundle,
	const char *destination,
	const char *hsm_secret_path,
	struct bitcoin_tx **commitment_tx,
	u8 **destination_script,
	struct recoverhtlc_keys *keys)
{
	chainparams = chainparams_for_network(bundle->network);
	if (!chainparams || chainparams->is_elements)
		errx(ERROR_USAGE, "Unsupported recovery network '%s'",
		     bundle->network);
	if (!decode_scriptpubkey_from_addr(tmpctx, chainparams, destination,
					   destination_script))
		errx(ERROR_USAGE, "Invalid destination for network '%s'",
		     bundle->network);
	*commitment_tx = bitcoin_tx_from_hex(
		tmpctx, bundle->commitment_tx_hex,
		strlen(bundle->commitment_tx_hex));
	if (!*commitment_tx)
		errx(ERROR_USAGE, "Recovery bundle has an invalid commitment_tx");
	if (!hsmtool_recoverhtlc_derive_keys(
		    bundle->peer_id, bundle->channel_dbid,
		    &bundle->commitment_point, &bundle->remote_htlc_basepoint,
		    hsm_secret_path, keys))
		errx(ERROR_KEYDERIV, "Could not derive HTLC recovery keys");
}

/* Say when the transaction becomes valid, and when that is too late. */
static void print_recovery_timing(const struct recoverhtlc_match *match,
				  u32 cltv_expiry)
{
	/* Anchor outputs carry a one-block relative delay. */
	const char *confirmed = match->anchors
		? "the commitment transaction has one confirmation" : NULL;

	/* nLockTime keeps our timeout out until the HTLC has expired. */
	if (match->kind == HTLC_WE_OFFERED) {
		printf("valid        : once block %u is mined%s%s\n",
		       cltv_expiry,
		       confirmed ? " and " : "", confirmed ? confirmed : "");
		return;
	}

	printf("valid        : %s%s\n",
	       confirmed ? "once " : "now", confirmed ? confirmed : "");
	/* After expiry the peer's own timeout races our preimage claim. */
	if (cltv_expiry)
		printf("deadline     : the peer can take this back once"
		       " block %u is mined\n", cltv_expiry);
	else
		printf("deadline     : the peer can take this back once"
		       " the HTLC expires\n");
}

static void print_recovery_tx(
	const char *destination,
	const struct bitcoin_tx *commitment_tx,
	const struct recoverhtlc_match *match,
	u32 cltv_expiry,
	const struct bitcoin_tx *tx,
	const struct recoverhtlc_amounts *amounts)
{
	struct bitcoin_txid commitment_txid, txid;
	size_t weight = bitcoin_tx_weight(tx);
	u32 feerate;

	bitcoin_txid(commitment_tx, &commitment_txid);
	bitcoin_txid(tx, &txid);
	if (!amount_feerate(&feerate, amounts->fee, weight))
		feerate = 0;

	printf("kind         : %s\n",
	       match->kind == HTLC_THEY_OFFERED
	       ? "claim with preimage" : "reclaim after CLTV");
	printf("channel type : %s\n", match->anchors ? "anchors" : "no anchors");
	for (size_t i = 0; i < tal_count(match->outnums); i++) {
		struct amount_sat amount = bitcoin_tx_output_get_amount_sat(
			commitment_tx, match->outnums[i]);

		printf("input[%zu]     : %s:%zu (%s)\n", i,
		       fmt_bitcoin_txid(tmpctx, &commitment_txid),
		       match->outnums[i], fmt_amount_sat(tmpctx, amount));
	}
	printf("output       : %s (%s)\n", destination,
	       fmt_amount_sat(tmpctx, amounts->output));
	printf("fee          : %s (%zu weight, %u sat/kw)\n",
	       fmt_amount_sat(tmpctx, amounts->fee), weight, feerate);
	printf("txid         : %s\n", fmt_bitcoin_txid(tmpctx, &txid));
	print_recovery_timing(match, cltv_expiry);
	printf("\n"
	       "Verify with `bitcoin-cli decoderawtransaction` and"
	       " `bitcoin-cli testmempoolaccept '[\"<tx>\"]'`.\n"
	       "Broadcast with `bitcoin-cli sendrawtransaction <tx>`.\n\n");
	printf("%s\n\n", fmt_bitcoin_tx(tmpctx, tx));
}

/* Parts of one payment share a script: the first claim sweeps them all. */
static bool claim_already_swept(const struct recoverhtlc_claim *claims,
				size_t n)
{
	for (size_t i = 0; i < n; i++) {
		if (claims[i].kind != claims[n].kind
		    || !sha256_eq(&claims[i].payment_hash,
				  &claims[n].payment_hash))
			continue;
		/* Only the script of an HTLC we offered has its expiry. */
		if (claims[n].kind == HTLC_THEY_OFFERED
		    || claims[i].cltv_expiry == claims[n].cltv_expiry)
			return true;
	}
	return false;
}

/* Sign and print one claim, or return why it has to be left out. */
static const char *recover_claim(const struct recoverhtlc_bundle *bundle,
				 const struct recoverhtlc_claim *claim,
				 const struct bitcoin_tx *commitment_tx,
				 const struct recoverhtlc_keys *keys,
				 const char *destination,
				 const u8 *destination_script)
{
	const struct preimage *preimage
		= claim->kind == HTLC_THEY_OFFERED ? &claim->preimage : NULL;
	struct recoverhtlc_match *match;
	struct recoverhtlc_amounts amounts;
	struct bitcoin_tx *tx;

	match = hsmtool_recoverhtlc_find_outputs(
		tmpctx, commitment_tx, claim->kind, keys,
		&claim->payment_hash, claim->cltv_expiry);
	/* An HTLC below the peer's dust limit never had an output. */
	if (!match)
		return "no commitment output matches it";
	tx = hsmtool_recoverhtlc_sign(
		tmpctx, commitment_tx, match, keys, destination_script,
		bundle->feerate_perkw, claim->cltv_expiry, preimage, &amounts);
	if (!tx)
		return "its value does not cover the fee";
	if (amount_sat_less(amounts.output, chainparams->dust_limit))
		return "its value after the fee is below the dust limit";
	if (amount_sat_greater(amounts.fee, amount_sat_div(amounts.input, 4))
	    && !bundle->allow_high_fee)
		return "fee exceeds a quarter of the recovered amount"
			" (set allow_high_fee to true to override)";
	if (amount_sat_greater(amounts.fee, amount_sat_div(amounts.input, 4)))
		fprintf(stderr,
			"Warning: fee %s exceeds a quarter of the"
			" recovered amount\n",
			fmt_amount_sat(tmpctx, amounts.fee));
	print_recovery_tx(destination, commitment_tx, match,
			  claim->cltv_expiry, tx, &amounts);
	return NULL;
}

void hsmtool_recoverhtlc(const char *bundle_path,
			 const char *destination,
			 const char *hsm_secret_path)
{
	struct recoverhtlc_bundle bundle;
	struct recoverhtlc_keys keys;
	struct bitcoin_tx *commitment_tx;
	const char *err;
	u8 *destination_script;
	size_t num_recovered = 0;

	err = hsmtool_recoverhtlc_parse_bundle(tmpctx, bundle_path, &bundle);
	if (err)
		errx(ERROR_USAGE, "%s", err);

	validate_recovery_inputs(&bundle, destination, hsm_secret_path,
				 &commitment_tx, &destination_script, &keys);
	if (bundle.feerate_perkw < FEERATE_FLOOR)
		fprintf(stderr,
			"Warning: feerate %u sat/kw is below the usual"
			" relay minimum of %u sat/kw\n",
			bundle.feerate_perkw, FEERATE_FLOOR);

	/* One bad or trimmed HTLC must not block recovery of the others. */
	for (size_t i = 0; i < tal_count(bundle.claims); i++) {
		const struct recoverhtlc_claim *claim = &bundle.claims[i];

		if (claim_already_swept(bundle.claims, i))
			continue;
		err = recover_claim(&bundle, claim, commitment_tx, &keys,
				    destination, destination_script);
		if (!err) {
			num_recovered++;
			continue;
		}
		fprintf(stderr, "Skipping HTLC %zu (payment_hash %s): %s\n", i,
			tal_hexstr(tmpctx, &claim->payment_hash,
				   sizeof(claim->payment_hash)),
			err);
	}
	if (num_recovered == 0)
		errx(ERROR_USAGE,
		     "No HTLC could be recovered.  If no output matched,"
		     " check the bundle's commitment_point,"
		     " remote_htlc_basepoint, peer_id and channel_dbid");
}

/* Witness stack count, signature, selector, and witness script. */
static size_t recovery_witness_weight(const struct recoverhtlc_match *match)
{
	size_t wscript_len = tal_bytelen(match->wscript);

	return 1 + bitcoin_tx_input_sig_weight()
		+ (match->kind == HTLC_THEY_OFFERED ? 1 + 32 : 1)
		+ varint_size(wscript_len) + wscript_len;
}

/* Deduct the signed transaction's fee from its single output. */
static bool set_recovery_output_amount(
	struct bitcoin_tx *tx,
	const struct recoverhtlc_match *match,
	u32 feerate_perkw,
	struct recoverhtlc_amounts *amounts)
{
	/* The transaction is unsigned, so add each input's future witness. */
	size_t weight = bitcoin_tx_weight(tx)
		+ tal_count(match->outnums) * recovery_witness_weight(match);

	amounts->fee = amount_tx_fee(feerate_perkw, weight);
	/* Refuse a recovery whose fee consumes all of the HTLC value. */
	if (!amount_sat_sub(&amounts->output, amounts->input, amounts->fee))
		return false;
	bitcoin_tx_output_set_amount(tx, 0, amounts->output);
	return true;
}

static struct bitcoin_tx *new_recovery_tx(
	const tal_t *ctx,
	const struct bitcoin_tx *commitment_tx,
	const struct recoverhtlc_match *match,
	const u8 *destination_script,
	u32 feerate_perkw,
	struct recoverhtlc_amounts *amounts,
	u32 cltv_expiry)
{
	struct bitcoin_txid commitment_txid;
	struct bitcoin_tx *tx;
	size_t num_inputs = tal_count(match->outnums);

	/* Our timeout path requires nLockTime; the preimage path does not. */
	tx = bitcoin_tx(ctx, chainparams, num_inputs, 1,
			match->kind == HTLC_WE_OFFERED ? cltv_expiry : 0);
	bitcoin_txid(commitment_tx, &commitment_txid);
	amounts->input = AMOUNT_SAT(0);

	for (size_t i = 0; i < num_inputs; i++) {
		struct bitcoin_outpoint outpoint = {
			.txid = commitment_txid,
			.n = match->outnums[i],
		};
		struct amount_sat amount = bitcoin_tx_output_get_amount_sat(
			commitment_tx, match->outnums[i]);
		struct amount_sat total;

		if (!amount_sat_add(&total, amounts->input, amount))
			return tal_free(tx);
		amounts->input = total;

		/* Segwit signatures commit to each input's amount and script. */
		/* Anchor HTLC spends must wait one confirmation. */
		bitcoin_tx_add_input(tx, &outpoint, match->anchors ? 1 : 0,
				     NULL, amount, NULL, match->wscript);
	}

	/* The complete transaction shape is needed to calculate its fee. */
	bitcoin_tx_add_output(tx, destination_script, NULL, amounts->input);
	if (!set_recovery_output_amount(tx, match, feerate_perkw, amounts))
		return tal_free(tx);
	return tx;
}

static bool sign_recovery_tx(struct bitcoin_tx *tx,
			     const struct recoverhtlc_match *match,
			     const struct recoverhtlc_keys *keys,
			     const struct preimage *preimage)
{
	/* SIGHASH_ALL commits every input to the single destination output. */
	for (size_t i = 0; i < tal_count(match->outnums); i++) {
		struct bitcoin_signature signature;

		sign_tx_input(tx, i, NULL, match->wscript,
			      &keys->our_htlc_privkey, &keys->our_htlc_key,
			      SIGHASH_ALL, &signature);
		if (!check_tx_sig(tx, i, NULL, match->wscript,
				  &keys->our_htlc_key, &signature))
			return false;
		/* Witness: signature, optional preimage, then the script. */
		bitcoin_tx_input_set_witness(
			tx, i,
			take(bitcoin_witness_sig_and_element(
				tx, &signature,
				preimage ? preimage->r : NULL,
				preimage ? sizeof(preimage->r) : 0,
				match->wscript)));
	}
	return true;
}

/* Calculate fees, then build and sign a transaction sweeping every match. */
struct bitcoin_tx *hsmtool_recoverhtlc_sign(
	const tal_t *ctx,
	const struct bitcoin_tx *commitment_tx,
	const struct recoverhtlc_match *match,
	const struct recoverhtlc_keys *keys,
	const u8 *destination_script,
	u32 feerate_perkw,
	u32 cltv_expiry,
	const struct preimage *preimage,
	struct recoverhtlc_amounts *amounts)
{
	struct bitcoin_tx *tx;

	/* Peer-offered HTLCs need a preimage; our HTLCs use timeout. */
	if (match->kind == HTLC_THEY_OFFERED && !preimage)
		return NULL;
	if (match->kind == HTLC_WE_OFFERED && preimage)
		return NULL;

	tx = new_recovery_tx(ctx, commitment_tx, match, destination_script,
			     feerate_perkw, amounts, cltv_expiry);
	if (!tx)
		return NULL;
	if (!sign_recovery_tx(tx, match, keys, preimage))
		return tal_free(tx);
	return tx;
}

/* A misspelt key would otherwise be silently ignored. */
static const char *unknown_key(const tal_t *ctx,
			       const char *buffer,
			       const jsmntok_t *obj,
			       const char *const *known,
			       size_t num_known)
{
	const jsmntok_t *key;
	size_t i;

	json_for_each_obj(i, key, obj) {
		bool found = false;

		for (size_t j = 0; j < num_known; j++)
			found |= json_tok_streq(buffer, key, known[j]);
		if (!found)
			return tal_fmt(ctx, "unknown key '%.*s'",
				       key->end - key->start,
				       buffer + key->start);
	}
	return NULL;
}

static const char *parse_bundle_claim(const tal_t *ctx,
				      const char *buffer,
				      const jsmntok_t *tok,
				      struct recoverhtlc_claim *claim)
{
	static const char *const keys[] = {
		"direction", "preimage", "payment_hash", "cltv_expiry",
	};
	const jsmntok_t *direction, *preimage, *hash, *cltv;
	struct abs_locktime expiry;
	const char *err;

	if (tok->type != JSMN_OBJECT)
		return tal_strdup(ctx, "HTLC is not a JSON object");
	err = unknown_key(ctx, buffer, tok, keys, ARRAY_SIZE(keys));
	if (err)
		return err;

	direction = json_get_member(buffer, tok, "direction");
	preimage = json_get_member(buffer, tok, "preimage");
	hash = json_get_member(buffer, tok, "payment_hash");
	cltv = json_get_member(buffer, tok, "cltv_expiry");
	if (!direction)
		return tal_strdup(ctx, "HTLC is missing direction");

	memset(claim, 0, sizeof(*claim));
	if (hash && !json_to_sha256(buffer, hash, &claim->payment_hash))
		return tal_strdup(ctx, "HTLC has an invalid payment_hash");
	if (cltv
	    && (!json_to_u32(buffer, cltv, &claim->cltv_expiry)
		|| !blocks_to_abs_locktime(claim->cltv_expiry, &expiry)))
		return tal_strdup(ctx, "HTLC has an invalid cltv_expiry");

	/* The peer offered it: we claim it with the preimage. */
	if (json_tok_streq(buffer, direction, "in")) {
		struct sha256 preimage_hash;

		claim->kind = HTLC_THEY_OFFERED;
		if (!preimage
		    || !json_to_preimage(buffer, preimage, &claim->preimage))
			return tal_strdup(ctx, "HTLC has an invalid preimage");
		sha256(&preimage_hash, &claim->preimage,
		       sizeof(claim->preimage));
		/* The hash and expiry are optional: the script needs neither. */
		if (hash && !sha256_eq(&preimage_hash, &claim->payment_hash))
			return tal_strdup(ctx, "HTLC preimage does not match"
					  " its payment_hash");
		claim->payment_hash = preimage_hash;
		return NULL;
	}

	/* We offered it: we take it back once it has timed out. */
	if (json_tok_streq(buffer, direction, "out")) {
		claim->kind = HTLC_WE_OFFERED;
		if (preimage)
			return tal_strdup(ctx, "HTLC we offered is reclaimed"
					  " by timeout, not preimage");
		if (!hash)
			return tal_strdup(ctx, "HTLC is missing payment_hash");
		if (!cltv)
			return tal_strdup(ctx, "HTLC is missing cltv_expiry");
		return NULL;
	}

	return tal_strdup(ctx, "HTLC direction is not 'in' or 'out'");
}

const char *hsmtool_recoverhtlc_parse_bundle(
	const tal_t *ctx, const char *path, struct recoverhtlc_bundle *bundle)
{
	static const char *const keys[] = {
		"version", "network", "peer_id", "channel_dbid",
		"remote_htlc_basepoint", "commitment_point", "commitment_tx",
		"feerate_perkw", "allow_high_fee", "htlcs",
	};
	const jsmntok_t *toks, *htlcs, *value;
	const char *err;
	char *buffer;
	u32 version;

	memset(bundle, 0, sizeof(*bundle));
	buffer = grab_file_str(ctx, path);
	if (!buffer)
		return tal_fmt(ctx, "Could not read recovery bundle '%s'", path);
	toks = json_parse_simple(ctx, buffer, strlen(buffer));
	if (!toks || toks->type != JSMN_OBJECT)
		return tal_strdup(ctx, "Recovery bundle is not a JSON object");
	err = unknown_key(ctx, buffer, toks, keys, ARRAY_SIZE(keys));
	if (err)
		return tal_fmt(ctx, "Recovery bundle has an %s", err);

	bundle->peer_id = tal(ctx, struct node_id);
	bundle->feerate_perkw = RECOVERHTLC_DEFAULT_FEERATE;
	value = json_get_member(buffer, toks, "version");
	if (!value || !json_to_u32(buffer, value, &version))
		return tal_strdup(ctx, "Recovery bundle has an invalid version");
	if (version != 1)
		return tal_fmt(ctx, "Unsupported recovery bundle version %u",
			       version);

	value = json_get_member(buffer, toks, "network");
	bundle->network = value ? json_strdup(ctx, buffer, value) : NULL;
	if (!bundle->network)
		return tal_strdup(ctx, "Recovery bundle has an invalid network");
	value = json_get_member(buffer, toks, "peer_id");
	if (!value || !json_to_node_id(buffer, value, bundle->peer_id))
		return tal_strdup(ctx, "Recovery bundle has an invalid peer_id");
	value = json_get_member(buffer, toks, "channel_dbid");
	if (!value || !json_to_u64(buffer, value, &bundle->channel_dbid))
		return tal_strdup(ctx, "Recovery bundle has an invalid channel_dbid");
	if (!bundle->channel_dbid)
		return tal_strdup(ctx, "Recovery bundle channel_dbid must be >= 1");
	value = json_get_member(buffer, toks, "feerate_perkw");
	if (value
	    && (!json_to_u32(buffer, value, &bundle->feerate_perkw)
		|| !bundle->feerate_perkw))
		return tal_strdup(ctx,
				  "Recovery bundle has an invalid feerate_perkw");
	value = json_get_member(buffer, toks, "allow_high_fee");
	if (value && !json_to_bool(buffer, value, &bundle->allow_high_fee))
		return tal_strdup(ctx,
				  "Recovery bundle has an invalid allow_high_fee");

	value = json_get_member(buffer, toks, "remote_htlc_basepoint");
	if (!value || !json_to_pubkey(buffer, value,
				       &bundle->remote_htlc_basepoint))
		return tal_strdup(ctx,
				  "Recovery bundle has an invalid remote_htlc_basepoint");
	value = json_get_member(buffer, toks, "commitment_point");
	if (!value
	    || !json_to_pubkey(buffer, value, &bundle->commitment_point))
		return tal_strdup(ctx,
				  "Recovery bundle has an invalid commitment_point");
	value = json_get_member(buffer, toks, "commitment_tx");
	bundle->commitment_tx_hex
		= value ? json_strdup(ctx, buffer, value) : NULL;
	if (!bundle->commitment_tx_hex)
		return tal_strdup(ctx,
				  "Recovery bundle has an invalid commitment_tx");

	htlcs = json_get_member(buffer, toks, "htlcs");
	if (!htlcs)
		return tal_strdup(ctx, "Recovery bundle is missing HTLCs");
	if (htlcs->type != JSMN_ARRAY || htlcs->size == 0)
		return tal_strdup(ctx, "Recovery bundle has no HTLCs");

	bundle->claims = tal_arr(ctx, struct recoverhtlc_claim, htlcs->size);
	for (size_t i = 0; i < htlcs->size; i++) {
		err = parse_bundle_claim(ctx, buffer, json_get_arr(htlcs, i),
					 &bundle->claims[i]);
		if (err)
			return tal_fmt(ctx, "Invalid HTLC %zu: %s", i, err);
	}
	return NULL;
}
