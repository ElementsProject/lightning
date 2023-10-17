#include "config.h"
#include <assert.h>
#include <bitcoin/address.h>
#include <bitcoin/script.h>
#include <ccan/array_size/array_size.h>
#include <ccan/tal/str/str.h>
#include <common/bech32.h>
#include <common/bech32_util.h>
#include <common/bolt11.h>
#include <common/features.h>
#include <errno.h>
#include <inttypes.h>
#include <lightningd/lightningd.h>

bool dev_bolt11_old_order;
bool dev_bolt11_omit_c_value;

struct multiplier {
	const char letter;
	/* We can't represent p postfix to msat, so we multiply this by 10 */
	u64 m10;
};

/* BOLT #11:
 *
 * The following `multiplier` letters are defined:
 *
 * * `m` (milli): multiply by 0.001
 * * `u` (micro): multiply by 0.000001
 * * `n` (nano): multiply by 0.000000001
 * * `p` (pico): multiply by 0.000000000001
 */
static struct multiplier multipliers[] = {
	{ 'm', 10 * MSAT_PER_BTC / 1000 },
	{ 'u', 10 * MSAT_PER_BTC / 1000000 },
	{ 'n', 10 * MSAT_PER_BTC / 1000000000 },
	{ 'p', 10 * MSAT_PER_BTC / 1000000000000ULL }
};

/* If pad is false, we discard any bits which don't fit in the last byte.
 * Otherwise we add an extra byte.  Returns error string or NULL on success. */
static const char *pull_bits(struct hash_u5 *hu5,
			     const u5 **data, size_t *data_len,
			     void *dst, size_t nbits,
			     bool pad)
{
	size_t n5 = nbits / 5;
	size_t len = 0;

	if (nbits % 5)
		n5++;

	if (*data_len < n5)
		return "truncated";
	if (!bech32_convert_bits(dst, &len, 8, *data, n5, 5, pad))
		return "non-zero trailing bits";
	if (hu5)
		hash_u5(hu5, *data, n5);
	*data += n5;
	*data_len -= n5;

	return NULL;
}

/* Helper for pulling a variable-length big-endian int. */
static const char *pull_uint(struct hash_u5 *hu5,
		      const u5 **data, size_t *data_len,
		      u64 *val, size_t databits)
{
	be64 be_val;
	const char *err;

	/* Too big. */
	if (databits > sizeof(be_val) * CHAR_BIT)
		return "integer too large";
	err = pull_bits(hu5, data, data_len, &be_val, databits, true);
	if (err)
		return err;
	if (databits == 0)
		*val = 0;
	else
		*val = be64_to_cpu(be_val) >>
		       (sizeof(be_val) * CHAR_BIT - databits);
	return NULL;
}

static void *pull_all(const tal_t *ctx,
		      struct hash_u5 *hu5,
		      const u5 **data, size_t *data_len,
		      bool pad,
		      const char **err)
{
	void *ret;
	size_t retlen;

	if (pad)
		retlen = (*data_len * 5 + 7) / 8;
	else
		retlen = (*data_len * 5) / 8;

	ret = tal_arr(ctx, u8, retlen);
	*err = pull_bits(hu5, data, data_len, ret, *data_len * 5, pad);
	if (*err)
		return tal_free(ret);
	return ret;
}

/* Frees bolt11, returns NULL. */
static struct bolt11 *decode_fail(struct bolt11 *b11, char **fail,
				  const char *fmt, ...)
	PRINTF_FMT(3,4);

static struct bolt11 *decode_fail(struct bolt11 *b11, char **fail,
				  const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	*fail = tal_vfmt(tal_parent(b11), fmt, ap);
	va_end(ap);
	return tal_free(b11);
}

/*
 * These handle specific fields in the payment request; returning the problem
 * if any, or NULL.
 */
static const char *unknown_field(struct bolt11 *b11,
				 struct hash_u5 *hu5,
				 const u5 **data, size_t *field_len,
				 u5 type)
{
	struct bolt11_field *extra = tal(b11, struct bolt11_field);
	const char *err;

	extra->tag = type;
	/* FIXME: record u8 data here, not u5! */
	extra->data = tal_dup_arr(extra, u5, *data, *field_len, 0);
	list_add_tail(&b11->extra_fields, &extra->list);

	tal_free(pull_all(extra, hu5, data, field_len, true, &err));
	return err;
}

/* If field isn't expected length (in *bech32*!), call unknown_field.
 * Otherwise copy into dst without padding, set have_flag if non-NULL. */
static const char *pull_expected_length(struct bolt11 *b11,
					struct hash_u5 *hu5,
					const u5 **data, size_t *field_len,
					size_t expected_length,
					u5 type,
					bool *have_flag,
					void *dst)
{
	if (*field_len != expected_length)
		return unknown_field(b11, hu5, data, field_len, type);

	if (have_flag)
		*have_flag = true;
	return pull_bits(hu5, data, field_len, dst, *field_len * 5, false);
}

/* BOLT #11:
 *
 * `p` (1): `data_length` 52.  256-bit SHA256 payment_hash.  Preimage of this
 * provides proof of payment
 */
static const char *decode_p(struct bolt11 *b11,
			    const struct feature_set *our_features,
			    struct hash_u5 *hu5,
			    const u5 **data, size_t *field_len,
			    bool *have_p)
{
	/* BOLT #11:
	 *
	 * A payer... SHOULD use the first `p` field that it did NOT
	 * skip as the payment hash.
	 */
	assert(!*have_p);

	/* BOLT #11:
	 *
	 * A reader... MUST skip over unknown fields, OR an `f` field
	 * with unknown `version`, OR `p`, `h`, `s` or `n` fields that do
	 * NOT have `data_length`s of 52, 52, 52 or 53, respectively.
	 */
	return pull_expected_length(b11, hu5, data, field_len, 52, 'p',
				    have_p, &b11->payment_hash);
}

/* BOLT #11:
 *
 * `d` (13): `data_length` variable.  Short description of purpose of payment
 * (UTF-8), e.g. '1 cup of coffee' or 'ナンセンス 1杯'
 */
static const char *decode_d(struct bolt11 *b11,
			    const struct feature_set *our_features,
			    struct hash_u5 *hu5,
			    const u5 **data, size_t *field_len,
			    bool *have_d)
{
	u8 *desc;
	const char *err;

	assert(!*have_d);
	desc = pull_all(NULL, hu5, data, field_len, false, &err);
	if (!desc)
		return err;

	*have_d = true;
	b11->description = utf8_str(b11, take(desc), tal_bytelen(desc));
	if (b11->description)
		return NULL;

	return tal_fmt(b11, "d: invalid utf8");
}

/* BOLT #11:
 *
 * `h` (23): `data_length` 52.  256-bit description of purpose of payment
 * (SHA256).  This is used to commit to an associated description that is over
 * 639 bytes, but the transport mechanism for the description in that case is
 * transport specific and not defined here.
 */
static const char *decode_h(struct bolt11 *b11,
			    const struct feature_set *our_features,
			    struct hash_u5 *hu5,
			    const u5 **data, size_t *field_len,
			    bool *have_h)
{
	const char *err;
	struct sha256 hash;

	assert(!*have_h);
	/* BOLT #11:
	 *
	 * A reader... MUST skip over unknown fields, OR an `f` field
	 * with unknown `version`, OR `p`, `h`, `s` or `n` fields that do
	 * NOT have `data_length`s of 52, 52, 52 or 53, respectively. */
	err = pull_expected_length(b11, hu5, data, field_len, 52, 'h',
				    have_h, &hash);

	/* If that gave us the hash, store it */
	if (*have_h)
		b11->description_hash = tal_dup(b11, struct sha256, &hash);
	return err;
}

/* BOLT #11:
 *
 * `x` (6): `data_length` variable.  `expiry` time in seconds
 * (big-endian). Default is 3600 (1 hour) if not specified.
 */
#define DEFAULT_X 3600
static const char *decode_x(struct bolt11 *b11,
			    const struct feature_set *our_features,
			    struct hash_u5 *hu5,
			    const u5 **data, size_t *field_len,
			    bool *have_x)
{
	const char *err;

	assert(!*have_x);

	/* FIXME: Put upper limit in bolt 11 */
	err = pull_uint(hu5, data, field_len, &b11->expiry, *field_len * 5);
	if (err)
		return tal_fmt(b11, "x: %s", err);

	*have_x = true;
	return NULL;
}

/* BOLT #11:
 *
 * `c` (24): `data_length` variable. `min_final_cltv_expiry_delta` to use for the
 * last HTLC in the route. Default is 18 if not specified.
 */
static const char *decode_c(struct bolt11 *b11,
			    const struct feature_set *our_features,
			    struct hash_u5 *hu5,
			    const u5 **data, size_t *field_len,
			    bool *have_c)
{
	u64 c;
	const char *err;

	assert(!*have_c);

	/* FIXME: Put upper limit in bolt 11 */
	err = pull_uint(hu5, data, field_len, &c, *field_len * 5);
	if (err)
		return tal_fmt(b11, "c: %s", err);
	b11->min_final_cltv_expiry = c;
	/* Can overflow, since c is 64 bits but value must be < 32 bits */
	if (b11->min_final_cltv_expiry != c)
		return tal_fmt(b11, "c: %"PRIu64" is too large", c);

	*have_c = true;
	return NULL;
}

static const char *decode_n(struct bolt11 *b11,
			    const struct feature_set *our_features,
			    struct hash_u5 *hu5,
			    const u5 **data, size_t *field_len,
			    bool *have_n)
{
	assert(!*have_n);
	/* BOLT #11:
	 *
	 * A reader... MUST skip over unknown fields, OR an `f` field
	 * with unknown `version`, OR `p`, `h`, `s` or `n` fields that do
	 * NOT have `data_length`s of 52, 52, 52 or 53, respectively. */
	return pull_expected_length(b11, hu5, data, field_len, 53, 'n',
				    have_n, &b11->receiver_id.k);
}

/* BOLT #11:
 *
 * * `s` (16): `data_length` 52. This 256-bit secret prevents
 *    forwarding nodes from probing the payment recipient.
 */
static const char *decode_s(struct bolt11 *b11,
			    const struct feature_set *our_features,
			    struct hash_u5 *hu5,
			    const u5 **data, size_t *field_len,
			    bool *have_s)
{
	const char *err;
	struct secret secret;

	assert(!*have_s);

	/* BOLT #11:
	 *
	 * A reader... MUST skip over unknown fields, OR an `f` field
	 * with unknown `version`, OR `p`, `h`, `s` or `n` fields that do
	 * NOT have `data_length`s of 52, 52, 52 or 53, respectively. */
	err = pull_expected_length(b11, hu5, data, field_len, 52, 's',
				   have_s, &secret);
	if (*have_s)
		b11->payment_secret = tal_dup(b11, struct secret, &secret);
	return err;
}

/* BOLT #11:
 *
 * `f` (9): `data_length` variable, depending on version. Fallback
 * on-chain address: for Bitcoin, this starts with a 5-bit `version`
 * and contains a witness program or P2PKH or P2SH address.
 */
static const char *decode_f(struct bolt11 *b11,
			    const struct feature_set *our_features,
			    struct hash_u5 *hu5,
			    const u5 **data, size_t *field_len,
			    bool *have_f)
{
	u64 version;
	u8 *fallback;
	const u5 *orig_data = *data;
	size_t orig_len = *field_len;
	const char *err;

	err = pull_uint(hu5, data, field_len, &version, 5);
	if (err)
		return tal_fmt(b11, "f: %s", err);

	/* BOLT #11:
	 *
	 * for Bitcoin payments... MUST set an `f` field to a valid
	 * witness version and program, OR to `17` followed by a
	 * public key hash, OR to `18` followed by a script hash.
	*/
	if (version == 17) {
		/* Pay to pubkey hash (P2PKH) */
		struct bitcoin_address *pkhash;
		pkhash = pull_all(tmpctx, hu5, data, field_len, false, &err);
		if (!pkhash)
			return err;
		if (tal_bytelen(pkhash) != sizeof(*pkhash))
			return tal_fmt(b11, "f: pkhash length %zu",
				       tal_bytelen(pkhash));
		fallback = scriptpubkey_p2pkh(b11, pkhash);
	} else if (version == 18) {
		/* Pay to pubkey script hash (P2SH) */
		struct ripemd160 *shash;
		shash = pull_all(tmpctx, hu5, data, field_len, false, &err);
		if (!shash)
			return err;
		if (tal_bytelen(shash) != sizeof(*shash))
			return tal_fmt(b11, "f: p2sh length %zu",
				       tal_bytelen(shash));
		fallback = scriptpubkey_p2sh_hash(b11, shash);
	} else if (version < 17) {
		u8 *f = pull_all(tmpctx, hu5, data, field_len, false, &err);
		if (!f)
			return err;
		if (version == 0) {
			if (tal_count(f) != 20 && tal_count(f) != 32)
				return tal_fmt(b11,
					       "f: witness v0 bad length %zu",
					       tal_count(f));
		}
		if (version == 1 && tal_count(f) != 32) {
			return tal_fmt(b11,
				       "f: witness v1 bad length %zu",
				       tal_count(f));
		}
		if (tal_count(f) > 40) {
			return tal_fmt(b11,
				       "f: witness v%"PRIu64" bad length %zu",
				       version,
				       tal_count(f));
		}
		fallback = scriptpubkey_witness_raw(b11, version,
						    f, tal_count(f));
	} else {
		/* Restore version for unknown field! */
		*data = orig_data;
		*field_len = orig_len;
		return unknown_field(b11, hu5, data, field_len, 'f');
	}

	if (b11->fallbacks == NULL)
		b11->fallbacks = tal_arr(b11, const u8 *, 1);
	else
		tal_resize(&b11->fallbacks, tal_count(b11->fallbacks) + 1);

	b11->fallbacks[tal_count(b11->fallbacks)-1]
		= tal_steal(b11->fallbacks, fallback);
	*have_f = true;
	return NULL;
}

static bool fromwire_route_info(const u8 **cursor, size_t *max,
				struct route_info *route_info)
{
	fromwire_node_id(cursor, max, &route_info->pubkey);
	fromwire_short_channel_id(cursor, max, &route_info->short_channel_id);
	route_info->fee_base_msat = fromwire_u32(cursor, max);
	route_info->fee_proportional_millionths = fromwire_u32(cursor, max);
	route_info->cltv_expiry_delta = fromwire_u16(cursor, max);
	return *cursor != NULL;
}

static void towire_route_info(u8 **pptr, const struct route_info *route_info)
{
	towire_node_id(pptr, &route_info->pubkey);
	towire_short_channel_id(pptr, &route_info->short_channel_id);
	towire_u32(pptr, route_info->fee_base_msat);
	towire_u32(pptr, route_info->fee_proportional_millionths);
	towire_u16(pptr, route_info->cltv_expiry_delta);
}

/* BOLT #11:
 *
 * `r` (3): `data_length` variable.  One or more entries containing
 * extra routing information for a private route; there may be more
 * than one `r` field
 *
 *   * `pubkey` (264 bits)
 *   * `short_channel_id` (64 bits)
 *   * `fee_base_msat` (32 bits, big-endian)
 *   * `fee_proportional_millionths` (32 bits, big-endian)
 *   * `cltv_expiry_delta` (16 bits, big-endian)
 */
static const char *decode_r(struct bolt11 *b11,
			    const struct feature_set *our_features,
			    struct hash_u5 *hu5,
			    const u5 **data, size_t *field_len,
			    bool *have_r)
{
	const u8 *r8;
	size_t n = 0;
	struct route_info *r = tal_arr(b11->routes, struct route_info, n);
	const char *err;
	size_t rlen;

	/* Route hops don't split in 5 bit boundaries, so convert whole thing */
	r8 = pull_all(tmpctx, hu5, data, field_len, false, &err);
	if (!r8)
		return err;
	rlen = tal_bytelen(r8);

	do {
		struct route_info ri;
		if (!fromwire_route_info(&r8, &rlen, &ri)) {
			return tal_fmt(b11, "r: hop %zu truncated", n);
		}
		tal_arr_expand(&r, ri);
	} while (rlen);

	/* Append route */
	tal_arr_expand(&b11->routes, r);
	*have_r = true;
	return NULL;
}

static void shift_bitmap_down(u8 *bitmap, size_t bits)
{
	u8 prev = 0;
	assert(bits < CHAR_BIT);

	for (size_t i = 0; i < tal_bytelen(bitmap); i++) {
		/* Save top bits for next one */
		u8 v = bitmap[i];
		bitmap[i] = (prev | (v >> bits));
		prev = (v << (8 - bits));
	}
	assert(prev == 0);
}

/* BOLT #11:
 *
 * `9` (5): `data_length` variable. One or more 5-bit values containing features
 *  supported or required for receiving this payment.
 *  See [Feature Bits](#feature-bits).
 */
static const char *decode_9(struct bolt11 *b11,
			    const struct feature_set *our_features,
			    struct hash_u5 *hu5,
			    const u5 **data, size_t *field_len,
			    bool *have_9)
{
	size_t flen = (*field_len * 5 + 7) / 8;
	int badf;
	size_t databits = *field_len * 5;
	const char *err;

	assert(!*have_9);

	b11->features = pull_all(b11, hu5, data, field_len, true, &err);
	if (!b11->features)
		return err;

	/* pull_bits pads with zero bits: we need to remove them. */
	shift_bitmap_down(b11->features,
			  flen * 8 - databits);

	/* BOLT #11:
	 *
	 * - if the `9` field contains unknown _odd_ bits that are non-zero:
	 *   - MUST ignore the bit.
	 * - if the `9` field contains unknown _even_ bits that are non-zero:
	 *   - MUST fail the payment.
	 */
	/* We skip this check for the cli tool, which sets our_features to NULL */
	if (our_features) {
		badf = features_unsupported(our_features,
					    b11->features, BOLT11_FEATURE);
		if (badf != -1)
			return tal_fmt(b11, "9: unknown feature bit %i", badf);
	}

	*have_9 = true;
	return NULL;
}

/* BOLT #11:
 *
 * `m` (27): `data_length` variable. Additional metadata to attach to
 * the payment. Note that the size of this field is limited by the
 * maximum hop payload size. Long metadata fields reduce the maximum
 * route length.
 */
static const char *decode_m(struct bolt11 *b11,
			    const struct feature_set *our_features,
			    struct hash_u5 *hu5,
			    const u5 **data, size_t *field_len,
			    bool *have_m)
{
	const char *err;

	assert(!*have_m);

	b11->metadata = pull_all(b11, hu5, data, field_len, false, &err);
	if (!b11->metadata)
		return err;

	*have_m = true;
	return NULL;
}

struct bolt11 *new_bolt11(const tal_t *ctx,
			  const struct amount_msat *msat TAKES)
{
	struct bolt11 *b11 = tal(ctx, struct bolt11);

	list_head_init(&b11->extra_fields);
	b11->description = NULL;
	b11->description_hash = NULL;
	b11->fallbacks = NULL;
	b11->routes = NULL;
	b11->msat = NULL;
	b11->expiry = DEFAULT_X;
	b11->features = tal_arr(b11, u8, 0);
	/* BOLT #11:
	 *   - if the `c` field (`min_final_cltv_expiry_delta`) is not provided:
	 *     - MUST use an expiry delta of at least 18 when making the payment
	 */
	b11->min_final_cltv_expiry = 18;
	b11->payment_secret = NULL;
	b11->metadata = NULL;

	if (msat)
		b11->msat = tal_dup(b11, struct amount_msat, msat);
	return b11;
}

struct decoder {
	/* What BOLT11 letter this is */
	const char letter;
	/* If false, then any dups get treated as "unknown" fields */
	bool allow_duplicates;
	/* Routine to decode: returns NULL if it decodes ok, and
	 * sets *have_field = true if it is not an unknown form.
	 * Otherwise returns error string (literal or tal off b11). */
	const char *(*decode)(struct bolt11 *b11,
			      const struct feature_set *our_features,
			      struct hash_u5 *hu5,
			      const u5 **data, size_t *field_len,
			      bool *have_field);
};

static const struct decoder decoders[] = {
	/* BOLT #11:
	 *
	 * A payer... SHOULD use the first `p` field that it did NOT
	 * skip as the payment hash.
	 */
	{ 'p', false, decode_p },
	{ 'd', false, decode_d },
	{ 'h', false, decode_h },
	{ 'x', false, decode_x },
	{ 'c', false, decode_c },
	{ 'n', false, decode_n },
	{ 's', false, decode_s },
	/* BOLT #11:
	 *   - MAY include one or more `f` fields.
	 */
	{ 'f', true, decode_f },
	/* BOLT #11:
	 *
	 * there may be more than one `r` field
	 */
	{ 'r', true, decode_r },
	{ '9', false, decode_9 },
	{ 'm', false, decode_m },
};

static const struct decoder *find_decoder(char c)
{
	for (size_t i = 0; i < ARRAY_SIZE(decoders); i++) {
		if (decoders[i].letter == c)
			return decoders + i;
	}
	return NULL;
}

static bool bech32_decode_alloc(const tal_t *ctx,
				const char **hrp_ret,
				const u5 **data_ret,
				size_t *data_len,
				const char *str)
{
	char *hrp = tal_arr(ctx, char, strlen(str) - 6);
	u5 *data = tal_arr(ctx, u5, strlen(str) - 8);

	if (bech32_decode(hrp, data, data_len, str, (size_t)-1)
	    != BECH32_ENCODING_BECH32) {
		tal_free(hrp);
		tal_free(data);
		return false;
	}

	/* We needed temporaries because these are const */
	*hrp_ret = hrp;
	*data_ret = data;
	return true;
}

static bool has_lightning_prefix(const char *invstring)
{
	/* BOLT #11:
	 *
	 * If a URI scheme is desired, the current recommendation is to either
	 * use 'lightning:' as a prefix before the BOLT-11 encoding */
	return (strstarts(invstring, "lightning:") ||
		strstarts(invstring, "LIGHTNING:"));
}

const char *to_canonical_invstr(const tal_t *ctx,
				const char *invstring)
{
	if (has_lightning_prefix(invstring))
		invstring += strlen("lightning:");
	return str_lowering(ctx, invstring);
}

/* Extracts signature but does not check it. */
struct bolt11 *bolt11_decode_nosig(const tal_t *ctx, const char *str,
				   const struct feature_set *our_features,
				   const char *description,
				   const struct chainparams *must_be_chain,
				   struct sha256 *hash,
				   const u5 **sig,
				   bool *have_n,
				   char **fail)
{
	const char *hrp, *prefix;
	char *amountstr;
	const u5 *data;
	size_t data_len;
	struct bolt11 *b11 = new_bolt11(ctx, NULL);
	struct hash_u5 hu5;
	const char *err;
	/* We don't need all of these, but in theory we could have 32 types */
	bool have_field[32];

	memset(have_field, 0, sizeof(have_field));
	b11->routes = tal_arr(b11, struct route_info *, 0);

	assert(!has_lightning_prefix(str));
	if (strlen(str) < 8)
		return decode_fail(b11, fail, "Bad bech32 string");

	if (!bech32_decode_alloc(tmpctx, &hrp, &data, &data_len, str))
		return decode_fail(b11, fail, "Bad bech32 string");

	/* For signature checking at the end. */
	hash_u5_init(&hu5, hrp);

	/* BOLT #11:
	 *
	 * The human-readable part of a Lightning invoice consists of two sections:
	 * 1. `prefix`: `ln` + BIP-0173 currency prefix (e.g. `lnbc` for Bitcoin mainnet,
	 *    `lntb` for Bitcoin testnet, `lntbs` for Bitcoin signet, and `lnbcrt` for Bitcoin regtest)
	 * 1. `amount`: optional number in that currency, followed by an optional
	 *    `multiplier` letter. The unit encoded here is the 'social' convention of a payment unit -- in the case of Bitcoin the unit is 'bitcoin' NOT satoshis.
	*/
	prefix = tal_strndup(tmpctx, hrp, strcspn(hrp, "0123456789"));

	/* BOLT #11:
	 *
	 * A reader...if it does NOT understand the `prefix`... MUST fail the payment.
	 */
	if (!strstarts(prefix, "ln"))
		return decode_fail(b11, fail,
				   "Prefix '%s' does not start with ln", prefix);

	if (must_be_chain) {
		if (streq(prefix + 2, must_be_chain->lightning_hrp))
			b11->chain = must_be_chain;
		else
			return decode_fail(b11, fail, "Prefix %s is not for %s",
					   prefix + 2,
					   must_be_chain->network_name);
	} else {
		b11->chain = chainparams_by_lightning_hrp(prefix + 2);
		if (!b11->chain)
			return decode_fail(b11, fail, "Unknown chain %s",
					   prefix + 2);
	}

	/* BOLT #11:
	 *
	 *   - if the `amount` is empty:
	 * */
	amountstr = tal_strdup(tmpctx, hrp + strlen(prefix));
	if (streq(amountstr, "")) {
		/* BOLT #11:
		 *
		 * - SHOULD indicate to the payer that amount is unspecified.
		 */
		b11->msat = NULL;
	} else {
		u64 m10 = 10 * MSAT_PER_BTC; /* Pico satoshis in a Bitcoin */
		u64 amount;
		char *end;

		/* Gather and trim multiplier */
		end = amountstr + strlen(amountstr)-1;
		for (size_t i = 0; i < ARRAY_SIZE(multipliers); i++) {
			if (*end == multipliers[i].letter) {
				m10 = multipliers[i].m10;
				*end = '\0';
				break;
			}
		}

		/* BOLT #11:
		 *
		 * if `amount` contains a non-digit OR is followed by
		 * anything except a `multiplier` (see table above)... MUST fail the
		 * payment.
		 **/
		amount = strtoull(amountstr, &end, 10);
		if (amount == ULLONG_MAX && errno == ERANGE)
			return decode_fail(b11, fail,
					   "Invalid amount '%s'", amountstr);
		if (!*amountstr || *end)
			return decode_fail(b11, fail,
					   "Invalid amount postfix '%s'", end);

		/* BOLT #11:
		 *
		 * if the `multiplier` is present...  MUST multiply
		 * `amount` by the `multiplier` value to derive the
		 * amount required for payment.
		*/
		b11->msat = tal(b11, struct amount_msat);
		/* BOLT #11:
		 *
		 * - if multiplier is `p` and the last decimal of `amount` is
		 *   not 0:
		 *    - MUST fail the payment.
		 */
		if (amount * m10 % 10 != 0)
			return decode_fail(b11, fail,
					   "Invalid sub-millisatoshi amount"
					   " '%sp'", amountstr);

		*b11->msat = amount_msat(amount * m10 / 10);
	}

	/* BOLT #11:
	 *
	 * The data part of a Lightning invoice consists of multiple sections:
	 *
	 * 1. `timestamp`: seconds-since-1970 (35 bits, big-endian)
	 * 1. zero or more tagged parts
	 * 1. `signature`: Bitcoin-style signature of above (520 bits)
	 */
	err = pull_uint(&hu5, &data, &data_len, &b11->timestamp, 35);
	if (err)
		return decode_fail(b11, fail,
				   "Can't get 35-bit timestamp: %s", err);

	while (data_len > 520 / 5) {
		const char *problem = NULL;
		u64 type, field_len64;
		size_t field_len;
		const struct decoder *decoder;

		/* BOLT #11:
		 *
		 * Each Tagged Field is of the form:
		 *
		 * 1. `type` (5 bits)
		 * 1. `data_length` (10 bits, big-endian)
		 * 1. `data` (`data_length` x 5 bits)
		 */
		err = pull_uint(&hu5, &data, &data_len, &type, 5);
		if (err)
			return decode_fail(b11, fail,
					   "Can't get tag: %s", err);
		err = pull_uint(&hu5, &data, &data_len, &field_len64, 10);
		if (err)
			return decode_fail(b11, fail,
					   "Can't get length: %s", err);

		/* Can't exceed total data remaining. */
		if (field_len64 > data_len)
			return decode_fail(b11, fail, "%c: truncated",
					   bech32_charset[type]);

		/* These are different types on 32 bit!  But since data_len is
		 * also size_t, above check ensures this will fit. */
		field_len = field_len64;
		assert(field_len == field_len64);

		/* Do this now: the decode function fixes up the data ptr */
		data_len -= field_len;

		decoder = find_decoder(bech32_charset[type]);
		if (!decoder || (have_field[type] && !decoder->allow_duplicates)) {
			problem = unknown_field(b11, &hu5, &data, &field_len,
						bech32_charset[type]);
		} else {
			problem = decoder->decode(b11, our_features, &hu5,
						  &data, &field_len, &have_field[type]);
		}
		if (problem)
			return decode_fail(b11, fail, "%s", problem);
		if (field_len)
			return decode_fail(b11, fail, "%c: extra %zu bytes",
					   bech32_charset[type], field_len);
	}

	if (!have_field[bech32_charset_rev['p']])
		return decode_fail(b11, fail, "No valid 'p' field found");

	if (have_field[bech32_charset_rev['h']] && description) {
		struct sha256 sha;

		/* BOLT #11:
		 *
		 * A reader... MUST check that the SHA2 256-bit hash
		 * in the `h` field exactly matches the hashed
		 * description.
		 */
		sha256(&sha, description, strlen(description));
		if (!sha256_eq(b11->description_hash, &sha))
			return decode_fail(b11, fail,
					   "h: does not match description");
	}

	/* BOLT #11:
	 * A writer:
	 *...
	 * - MUST include either exactly one `d` or exactly one `h` field.
	 */
	/* FIXME: It doesn't actually say the reader must check though! */
	if (!have_field[bech32_charset_rev['d']]
	    && !have_field[bech32_charset_rev['h']])
		return decode_fail(b11, fail,
				   "must have either 'd' or 'h' field");

	hash_u5_done(&hu5, hash);
	*sig = tal_dup_arr(ctx, u5, data, data_len, 0);

	*have_n = have_field[bech32_charset_rev['n']];
	return b11;
}

/* Decodes and checks signature; returns NULL on error. */
struct bolt11 *bolt11_decode(const tal_t *ctx, const char *str,
			     const struct feature_set *our_features,
			     const char *description,
			     const struct chainparams *must_be_chain,
			     char **fail)
{
	const u5 *sigdata;
	size_t data_len;
	u8 sig_and_recid[65];
	secp256k1_ecdsa_recoverable_signature sig;
	struct bolt11 *b11;
	struct sha256 hash;
	bool have_n;
	const char *err;

	b11 = bolt11_decode_nosig(ctx, str, our_features, description,
				  must_be_chain, &hash, &sigdata, &have_n,
				  fail);
	if (!b11)
		return NULL;

	/* BOLT #11:
	 *
	 * A writer...MUST set `signature` to a valid 512-bit
	 * secp256k1 signature of the SHA2 256-bit hash of the
	 * human-readable part, represented as UTF-8 bytes,
	 * concatenated with the data part (excluding the signature)
	 * with 0 bits appended to pad the data to the next byte
	 * boundary, with a trailing byte containing the recovery ID
	 * (0, 1, 2, or 3).
	 */
	data_len = tal_count(sigdata);
	err = pull_bits(NULL, &sigdata, &data_len, sig_and_recid, 520, false);
	if (err)
		return decode_fail(b11, fail, "can't read signature: %s",
				   err);

	assert(data_len == 0);

	if (!secp256k1_ecdsa_recoverable_signature_parse_compact
	    (secp256k1_ctx, &sig, sig_and_recid, sig_and_recid[64]))
		return decode_fail(b11, fail, "signature invalid");

	secp256k1_ecdsa_recoverable_signature_convert(secp256k1_ctx,
						      &b11->sig, &sig);

	/* BOLT #11:
	 *
	 * A reader...  MUST check that the `signature` is valid (see
	 * the `n` tagged field specified below). ... A reader...
	 * MUST use the `n` field to validate the signature instead of
	 * performing signature recovery.
	 */
	if (!have_n) {
		struct pubkey k;
		if (!secp256k1_ecdsa_recover(secp256k1_ctx,
					     &k.pubkey,
					     &sig,
					     (const u8 *)&hash))
			return decode_fail(b11, fail,
					   "signature recovery failed");
		node_id_from_pubkey(&b11->receiver_id, &k);
	} else {
		struct pubkey k;
		/* n parsing checked this! */
		if (!pubkey_from_node_id(&k, &b11->receiver_id))
			abort();
		if (!secp256k1_ecdsa_verify(secp256k1_ctx, &b11->sig,
					    (const u8 *)&hash,
					    &k.pubkey))
			return decode_fail(b11, fail, "invalid signature");
	}

	return b11;
}

/* Helper for pushing a variable-length big-endian int. */
static void push_varlen_uint(u5 **data, u64 val, size_t nbits)
{
	be64 be_val = cpu_to_be64(val << (64 - nbits));
	bech32_push_bits(data, &be_val, nbits);
}

/* BOLT #11:
 *
 * Each Tagged Field is of the form:
 *
 * 1. `type` (5 bits)
 * 1. `data_length` (10 bits, big-endian)
 * 1. `data` (`data_length` x 5 bits)
 */
static void push_field_type_and_len(u5 **data, char type, size_t nbits)
{
	assert(bech32_charset_rev[(unsigned char)type] >= 0);
	push_varlen_uint(data, bech32_charset_rev[(unsigned char)type], 5);
	push_varlen_uint(data, (nbits + 4) / 5, 10);
}

static void push_field(u5 **data, char type, const void *src, size_t nbits)
{
	push_field_type_and_len(data, type, nbits);
	bech32_push_bits(data, src, nbits);
}

/* BOLT #11:
 *
 * - if `x` is included:
 *   - SHOULD use the minimum `data_length` possible.
 * - SHOULD include one `c` field (`min_final_cltv_expiry_delta`).
 *...
 *   - SHOULD use the minimum `data_length` possible.
 */
static void push_varlen_field(u5 **data, char type, u64 val)
{
	assert(bech32_charset_rev[(unsigned char)type] >= 0);
	push_varlen_uint(data, bech32_charset_rev[(unsigned char)type], 5);

	for (size_t nbits = 5; nbits < 65; nbits += 5) {
		if ((val >> nbits) == 0) {
			push_varlen_uint(data, nbits / 5, 10);
			push_varlen_uint(data, val,  nbits);
			return;
		}
	}
	/* Can't be encoded in <= 60 bits. */
	abort();
}

/* BOLT #11:
 *
 * `f` (9): `data_length` variable, depending on version. Fallback
 * on-chain address: for Bitcoin, this starts with a 5-bit `version`
 * and contains a witness program or P2PKH or P2SH address.
 */
static void push_fallback_addr(u5 **data, u5 version, const void *addr, u16 addr_len)
{
	push_varlen_uint(data, bech32_charset_rev[(unsigned char)'f'], 5);
	push_varlen_uint(data, ((5 + addr_len * CHAR_BIT) + 4) / 5, 10);
	push_varlen_uint(data, version, 5);
	bech32_push_bits(data, addr, addr_len * CHAR_BIT);
}

static void encode_p(u5 **data, const struct sha256 *hash)
{
	push_field(data, 'p', hash, 256);
}

static void encode_m(u5 **data, const u8 *metadata)
{
	push_field(data, 'm', metadata, tal_bytelen(metadata) * CHAR_BIT);
}

static void encode_d(u5 **data, const char *description)
{
	push_field(data, 'd', description, strlen(description) * CHAR_BIT);
}

static void encode_h(u5 **data, const struct sha256 *hash)
{
	push_field(data, 'h', hash, 256);
}

static void encode_n(u5 **data, const struct node_id *id)
{
	assert(node_id_valid(id));
	push_field(data, 'n', id->k, sizeof(id->k) * CHAR_BIT);
}

static void encode_x(u5 **data, u64 expiry)
{
	push_varlen_field(data, 'x', expiry);
}

static void encode_c(u5 **data, u16 min_final_cltv_expiry)
{
	if (dev_bolt11_omit_c_value)
		return;
	push_varlen_field(data, 'c', min_final_cltv_expiry);
}

static void encode_s(u5 **data, const struct secret *payment_secret)
{
	push_field(data, 's', payment_secret, 256);
}

static void encode_f(u5 **data, const u8 *fallback)
{
	struct bitcoin_address pkh;
	struct ripemd160 sh;
	struct sha256 wsh;

	/* BOLT #11:
	 *
	 * for Bitcoin payments... MUST set an `f` field to a valid
	 * witness version and program, OR to `17` followed by a
	 * public key hash, OR to `18` followed by a script hash.
	 */
	if (is_p2pkh(fallback, &pkh)) {
		push_fallback_addr(data, 17, &pkh, sizeof(pkh));
	} else if (is_p2sh(fallback, &sh)) {
		push_fallback_addr(data, 18, &sh, sizeof(sh));
	} else if (is_p2wpkh(fallback, &pkh)) {
		push_fallback_addr(data, 0, &pkh, sizeof(pkh));
	} else if (is_p2wsh(fallback, &wsh)) {
		push_fallback_addr(data, 0, &wsh, sizeof(wsh));
	} else if (tal_count(fallback) > 1
		   && fallback[0] >= 0x50
		   && fallback[0] < (0x50+16)) {
		/* Other (future) witness versions: turn OP_N into N */
		push_fallback_addr(data, fallback[0] - 0x50, fallback + 2,
				   tal_count(fallback) - 2);
	} else {
		/* Copy raw. */
		push_field(data, 'f',
			   fallback, tal_count(fallback) * CHAR_BIT);
	}
}

static void encode_r(u5 **data, const struct route_info *r)
{
	u8 *rinfo = tal_arr(NULL, u8, 0);

	for (size_t i = 0; i < tal_count(r); i++)
		towire_route_info(&rinfo, &r[i]);

	push_field(data, 'r', rinfo, tal_count(rinfo) * CHAR_BIT);
	tal_free(rinfo);
}

static void maybe_encode_9(u5 **data, const u8 *features,
			   bool have_payment_metadata)
{
	u5 *f5 = tal_arr(NULL, u5, 0);

	for (size_t i = 0; i < tal_count(features) * CHAR_BIT; i++) {
		if (!feature_is_set(features, i))
			continue;

		/* Don't set option_payment_metadata unless we acually use it */
		if (!have_payment_metadata
		    && COMPULSORY_FEATURE(i) == OPT_PAYMENT_METADATA)
			continue;

		/* We expand it out so it makes a BE 5-bit/btye bitfield */
		set_feature_bit(&f5, (i / 5) * 8 + (i % 5));
	}

	/* BOLT #11:
	 *
	 * - if `9` contains non-zero bits:
	 *   - SHOULD use the minimum `data_length` possible.
	 * - otherwise:
	 *   - MUST omit the `9` field altogether.
	 */
	if (tal_count(f5) != 0) {
		push_field_type_and_len(data, '9', tal_count(f5) * 5);
		tal_expand(data, f5, tal_count(f5));
	}
	tal_free(f5);
}

static bool encode_extra(u5 **data, const struct bolt11_field *extra)
{
	size_t len;

	/* Can't encode an invalid tag. */
	if (bech32_charset_rev[(unsigned char)extra->tag] == -1)
		return false;

	push_varlen_uint(data, bech32_charset_rev[(unsigned char)extra->tag], 5);
	push_varlen_uint(data, tal_count(extra->data), 10);

	/* extra->data is already u5s, so do this raw. */
	len = tal_count(*data);
	tal_resize(data, len + tal_count(extra->data));
	memcpy(*data + len, extra->data, tal_count(extra->data));
	return true;
}

/* Encodes, even if it's nonsense. */
char *bolt11_encode_(const tal_t *ctx,
		     const struct bolt11 *b11, bool n_field,
		     bool (*sign)(const u5 *u5bytes,
				  const u8 *hrpu8,
				  secp256k1_ecdsa_recoverable_signature *rsig,
				  void *arg),
		     void *arg)
{
	u5 *data = tal_arr(tmpctx, u5, 0);
	char *hrp, *output;
	u64 amount;
	struct bolt11_field *extra;
	secp256k1_ecdsa_recoverable_signature rsig;
	u8 sig_and_recid[65];
	u8 *hrpu8;
	int recid;

	/* BOLT #11:
	 *
	 * A writer:
	 * - MUST encode `prefix` using the currency required for successful payment.
	 * - if a specific minimum `amount` is required for successful payment:
	 *   - MUST include that `amount`.
	 * - MUST encode `amount` as a positive decimal integer with no leading 0s.
	 * - If the `p` multiplier is used the last decimal of `amount` MUST be `0`.
	 * - SHOULD use the shortest representation possible, by using the largest multiplier or omitting the multiplier.
	 */
	if (b11->msat) {
		char postfix;
		u64 msat = b11->msat->millisatoshis; /* Raw: best-multiplier calc */
		if (msat % MSAT_PER_BTC == 0) {
			postfix = '\0';
			amount = msat / MSAT_PER_BTC;
		} else {
			size_t i;
			for (i = 0; i < ARRAY_SIZE(multipliers)-1; i++) {
				if (!(msat * 10 % multipliers[i].m10))
					break;
			}
			postfix = multipliers[i].letter;
			amount = msat * 10 / multipliers[i].m10;
		}
		hrp = tal_fmt(tmpctx, "ln%s%"PRIu64"%c",
			      b11->chain->lightning_hrp, amount, postfix);
	} else
		hrp = tal_fmt(tmpctx, "ln%s", b11->chain->lightning_hrp);

	/* BOLT #11:
	 *
	 * 1. `timestamp`: seconds-since-1970 (35 bits, big-endian)
	 * 1. zero or more tagged parts
	 * 1. `signature`: Bitcoin-style signature of above (520 bits)
	 */
	push_varlen_uint(&data, b11->timestamp, 35);

	/* This is a hack to match the test vectors, *some* of which
	 * order differently! */
	if (!dev_bolt11_old_order) {
		if (b11->payment_secret)
			encode_s(&data, b11->payment_secret);
	}

	/* BOLT #11:
	 *
	 * if a writer offers more than one of any field type,
	 * it... MUST specify the most-preferred field first, followed
	 * by less-preferred fields, in order.
	 */
	/* Thus we do built-in fields, then extras last. */
	encode_p(&data, &b11->payment_hash);

	/* BOLT #11:
	 * A writer:
	 *...
	 *    - MUST include either exactly one `d` or exactly one `h` field.
	 */
	/* We sometimes keep description around (to put in db), so prefer hash */
	if (b11->description_hash)
		encode_h(&data, b11->description_hash);
	else if (b11->description)
		encode_d(&data, b11->description);

	if (b11->metadata)
		encode_m(&data, b11->metadata);

	if (n_field)
		encode_n(&data, &b11->receiver_id);

	if (dev_bolt11_old_order) {
		if (b11->payment_secret)
			encode_s(&data, b11->payment_secret);
	}

	if (b11->expiry != DEFAULT_X)
		encode_x(&data, b11->expiry);

	/* BOLT #11:
	 *   - SHOULD include one `c` field (`min_final_cltv_expiry_delta`).
	 *...
	 * A reader:
	 *...
	 *   - if the `c` field (`min_final_cltv_expiry_delta`) is not provided:
	 *     - MUST use an expiry delta of at least 18 when making the payment
	 */
	if (b11->min_final_cltv_expiry != 18)
		encode_c(&data, b11->min_final_cltv_expiry);

	for (size_t i = 0; i < tal_count(b11->fallbacks); i++)
		encode_f(&data, b11->fallbacks[i]);

	for (size_t i = 0; i < tal_count(b11->routes); i++)
		encode_r(&data, b11->routes[i]);

	maybe_encode_9(&data, b11->features, b11->metadata != NULL);

	list_for_each(&b11->extra_fields, extra, list)
		if (!encode_extra(&data, extra))
			return NULL;

	/* FIXME: towire_ should check this? */
	if (tal_count(data) > 65535)
		return NULL;

	/* Need exact length here */
	hrpu8 = tal_dup_arr(tmpctx, u8, (const u8 *)hrp, strlen(hrp), 0);
	if (!sign(data, hrpu8, &rsig, arg))
		return NULL;

	secp256k1_ecdsa_recoverable_signature_serialize_compact(
		secp256k1_ctx,
		sig_and_recid,
		&recid,
		&rsig);
	sig_and_recid[64] = recid;

	bech32_push_bits(&data, sig_and_recid, sizeof(sig_and_recid) * CHAR_BIT);

	output = tal_arr(ctx, char, strlen(hrp) + tal_count(data) + 8);
	if (!bech32_encode(output, hrp, data, tal_count(data), (size_t)-1,
			   BECH32_ENCODING_BECH32))
		output = tal_free(output);

	return output;
}
