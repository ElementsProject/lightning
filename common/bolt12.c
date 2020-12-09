#include <bitcoin/block.h>
#include <bitcoin/chainparams.h>
#include <ccan/cast/cast.h>
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/mem/mem.h>
#include <common/bech32.h>
#include <common/bech32_util.h>
#include <common/bolt12.h>
#include <common/bolt12_merkle.h>
#include <common/features.h>
#include <secp256k1_schnorrsig.h>

bool bolt12_chains_match(const struct bitcoin_blkid *chains,
			 const struct chainparams *must_be_chain)
{
	size_t num_chains;

	/* BOLT-offers #12:
	 *   - if the chain for the invoice is not solely bitcoin:
	 *     - MUST specify `chains` the offer is valid for.
	 *   - otherwise:
	 *     - the bitcoin chain is implied as the first and only entry.
	 */
	/* BOLT-offers #12:
	 * The reader of an invoice_request:
	 *...
	 *  - MUST fail the request if `chains` does not include (or
	 *    imply) a supported chain.
	 */
	/* BOLT-offers #12:
	 *
	 * - if the chain for the invoice is not solely bitcoin:
	 *   - MUST specify `chains` the invoice is valid for.
	 * - otherwise:
	 *   - the bitcoin chain is implied as the first and only entry.
	 */
	num_chains = tal_count(chains);
	if (num_chains == 0) {
		num_chains = 1;
		chains = &chainparams_for_network("bitcoin")->genesis_blockhash;
	}

	for (size_t i = 0; i < num_chains; i++) {
		if (bitcoin_blkid_eq(&chains[i],
				     &must_be_chain->genesis_blockhash))
			return true;
	}

	return false;
}

static char *check_features_and_chain(const tal_t *ctx,
				      const struct feature_set *our_features,
				      const struct chainparams *must_be_chain,
				      const u8 *features,
				      const struct bitcoin_blkid *chains)
{
	if (must_be_chain) {
		if (!bolt12_chains_match(chains, must_be_chain))
			return tal_fmt(ctx, "wrong chain");
	}

	if (our_features) {
		int badf = features_unsupported(our_features, features,
						BOLT11_FEATURE);
		if (badf != -1)
			return tal_fmt(ctx, "unknown feature bit %i", badf);
	}

	return NULL;
}

static char *check_signature(const tal_t *ctx,
			     const struct tlv_field *fields,
			     const char *messagename,
			     const char *fieldname,
			     const struct pubkey32 *node_id,
			     const struct bip340sig *sig)
{
	struct sha256 m, shash;

	if (!node_id)
		return tal_fmt(ctx, "Missing node_id");
	if (!sig)
		return tal_fmt(ctx, "Missing signature");

	merkle_tlv(fields, &m);
	sighash_from_merkle(messagename, fieldname, &m, &shash);
	if (secp256k1_schnorrsig_verify(secp256k1_ctx,
					sig->u8,
					shash.u.u8,
					&node_id->pubkey) != 1)
		return tal_fmt(ctx, "Invalid signature");
	return NULL;
}

static const u8 *string_to_data(const tal_t *ctx,
				const char *str,
				size_t str_len,
				const char *hrp_expected,
				size_t *dlen,
				char **fail)
{
	char *hrp;
	u8 *data;
	char *bech32;
	size_t bech32_len;
	bool have_plus = false;

	/* First we collapse +\s*, except at start/end. */
	bech32 = tal_arr(tmpctx, char, str_len);
	bech32_len = 0;
	for (size_t i = 0; i < str_len; i++) {
		if (i != 0 && i+1 != str_len && !have_plus && str[i] == '+') {
			have_plus = true;
			continue;
		}
		if (have_plus && cisspace(str[i]))
			continue;
		have_plus = false;
		bech32[bech32_len++] = str[i];
	}

	if (have_plus) {
		*fail = tal_fmt(ctx, "unfinished string");
		return NULL;
	}

	if (!from_bech32_charset(ctx, bech32, bech32_len, &hrp, &data)) {
		*fail = tal_fmt(ctx, "invalid bech32 string");
		return NULL;
	}
	if (!streq(hrp, hrp_expected)) {
		*fail = tal_fmt(ctx, "unexpected prefix %s", hrp);
		data = tal_free(data);
	} else
		*dlen = tal_bytelen(data);

	tal_free(hrp);
	return data;
}

char *offer_encode(const tal_t *ctx, const struct tlv_offer *offer_tlv)
{
	u8 *wire;

	wire = tal_arr(tmpctx, u8, 0);
	towire_offer(&wire, offer_tlv);

	return to_bech32_charset(ctx, "lno", wire);
}

struct tlv_offer *offer_decode(const tal_t *ctx,
			       const char *b12, size_t b12len,
			       const struct feature_set *our_features,
			       const struct chainparams *must_be_chain,
			       char **fail)
{
	struct tlv_offer *offer;

	offer = offer_decode_nosig(ctx, b12, b12len,
				   our_features, must_be_chain, fail);

	if (offer) {
		*fail = check_signature(ctx, offer->fields,
					"offer", "signature",
					offer->node_id, offer->signature);
		if (*fail)
			offer = tal_free(offer);
	}
	return offer;
}

struct tlv_offer *offer_decode_nosig(const tal_t *ctx,
				     const char *b12, size_t b12len,
				     const struct feature_set *our_features,
				     const struct chainparams *must_be_chain,
				     char **fail)
{
	struct tlv_offer *offer = tlv_offer_new(ctx);
	const u8 *data;
	size_t dlen;

	data = string_to_data(tmpctx, b12, b12len, "lno", &dlen, fail);
	if (!data)
		return tal_free(offer);

	if (!fromwire_offer(&data, &dlen, offer)) {
		*fail = tal_fmt(ctx, "invalid offer data");
		return tal_free(offer);
	}

	*fail = check_features_and_chain(ctx,
					 our_features, must_be_chain,
					 offer->features,
					 offer->chains);
	if (*fail)
		return tal_free(offer);

	return offer;
}

char *invrequest_encode(const tal_t *ctx, const struct tlv_invoice_request *invrequest_tlv)
{
	u8 *wire;

	wire = tal_arr(tmpctx, u8, 0);
	towire_invoice_request(&wire, invrequest_tlv);

	return to_bech32_charset(ctx, "lnr", wire);
}

struct tlv_invoice_request *invrequest_decode(const tal_t *ctx,
					      const char *b12, size_t b12len,
					      const struct feature_set *our_features,
					      const struct chainparams *must_be_chain,
					      char **fail)
{
	struct tlv_invoice_request *invrequest = tlv_invoice_request_new(ctx);
	const u8 *data;
	size_t dlen;

	data = string_to_data(tmpctx, b12, b12len, "lnr", &dlen, fail);
	if (!data)
		return tal_free(invrequest);

	if (!fromwire_invoice_request(&data, &dlen, invrequest)) {
		*fail = tal_fmt(ctx, "invalid invoice_request data");
		return tal_free(invrequest);
	}

	*fail = check_features_and_chain(ctx,
					 our_features, must_be_chain,
					 invrequest->features,
					 invrequest->chains);
	if (*fail)
		return tal_free(invrequest);

	return invrequest;
}

char *invoice_encode(const tal_t *ctx, const struct tlv_invoice *invoice_tlv)
{
	u8 *wire;

	wire = tal_arr(tmpctx, u8, 0);
	towire_invoice(&wire, invoice_tlv);

	return to_bech32_charset(ctx, "lni", wire);
}

struct tlv_invoice *invoice_decode_nosig(const tal_t *ctx,
					 const char *b12, size_t b12len,
					 const struct feature_set *our_features,
					 const struct chainparams *must_be_chain,
					 char **fail)
{
	struct tlv_invoice *invoice = tlv_invoice_new(ctx);
	const u8 *data;
	size_t dlen;

	data = string_to_data(tmpctx, b12, b12len, "lni", &dlen, fail);
	if (!data)
		return tal_free(invoice);

	if (!fromwire_invoice(&data, &dlen, invoice)) {
		*fail = tal_fmt(ctx, "invalid invoice data");
		return tal_free(invoice);
	}

	*fail = check_features_and_chain(ctx,
					 our_features, must_be_chain,
					 invoice->features,
					 invoice->chains);
	if (*fail)
		return tal_free(invoice);

	return invoice;
}

struct tlv_invoice *invoice_decode(const tal_t *ctx,
				   const char *b12, size_t b12len,
				   const struct feature_set *our_features,
				   const struct chainparams *must_be_chain,
				   char **fail)
{
	struct tlv_invoice *invoice;

	invoice = invoice_decode_nosig(ctx, b12, b12len, our_features,
				       must_be_chain, fail);
	if (invoice) {
		*fail = check_signature(ctx, invoice->fields,
					"invoice", "signature",
					invoice->node_id, invoice->signature);
		if (*fail)
			invoice = tal_free(invoice);
	}
	return invoice;
}
