#include "config.h"
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
 * Otherwise we add an extra byte */
static bool pull_bits(struct hash_u5 *hu5,
		      u5 **data, size_t *data_len, void *dst, size_t nbits,
		      bool pad)
{
	size_t n5 = nbits / 5;
	size_t len = 0;

	if (nbits % 5)
		n5++;

	if (*data_len < n5)
		return false;
	if (!bech32_convert_bits(dst, &len, 8, *data, n5, 5, pad))
		return false;
	if (hu5)
		hash_u5(hu5, *data, n5);
	*data += n5;
	*data_len -= n5;

	return true;
}

/* For pulling fields where we should have checked it will succeed already. */
#ifndef NDEBUG
#define pull_bits_certain(hu5, data, data_len, dst, nbits, pad)	     \
	assert(pull_bits((hu5), (data), (data_len), (dst), (nbits), (pad)))
#else
#define pull_bits_certain pull_bits
#endif

/* Helper for pulling a variable-length big-endian int. */
static bool pull_uint(struct hash_u5 *hu5,
		      u5 **data, size_t *data_len,
		      u64 *val, size_t databits)
{
	be64 be_val;

	/* Too big. */
	if (databits > sizeof(be_val) * CHAR_BIT)
		return false;
	if (!pull_bits(hu5, data, data_len, &be_val, databits, true))
		return false;
	*val = be64_to_cpu(be_val) >> (sizeof(be_val) * CHAR_BIT - databits);
	return true;
}

static size_t num_u8(size_t num_u5)
{
	return (num_u5 * 5 + 4) / 8;
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
static char *unknown_field(struct bolt11 *b11,
			   struct hash_u5 *hu5,
			   u5 **data, size_t *data_len,
			   u5 type, size_t length)
{
	struct bolt11_field *extra = tal(b11, struct bolt11_field);
	u8 u8data[num_u8(length)];

	extra->tag = type;
	extra->data = tal_dup_arr(extra, u5, *data, length, 0);
	list_add_tail(&b11->extra_fields, &extra->list);

	pull_bits_certain(hu5, data, data_len, u8data, length * 5, true);
	return NULL;
}

/* BOLT #11:
 *
 * `p` (1): `data_length` 52.  256-bit SHA256 payment_hash.  Preimage of this
 * provides proof of payment
 */
static void decode_p(struct bolt11 *b11,
		     struct hash_u5 *hu5,
		     u5 **data, size_t *data_len,
		     size_t data_length, bool *have_p)
{
	/* BOLT #11:
	 *
	 * A payer... SHOULD use the first `p` field that it did NOT
	 * skip as the payment hash.
	 */
	if (*have_p) {
		unknown_field(b11, hu5, data, data_len, 'p', data_length);
		return;
	}

	/* BOLT #11:
	 *
	 * A reader... MUST skip over unknown fields, OR an `f` field
	 * with unknown `version`, OR `p`, `h`, `s` or `n` fields that do
	 * NOT have `data_length`s of 52, 52, 52 or 53, respectively.
	*/
	if (data_length != 52) {
		unknown_field(b11, hu5, data, data_len, 'p', data_length);
		return;
	}

	pull_bits_certain(hu5, data, data_len, &b11->payment_hash, 256, false);
	*have_p = true;
}

/* BOLT #11:
 *
 * `d` (13): `data_length` variable.  Short description of purpose of payment
 * (UTF-8), e.g. '1 cup of coffee' or 'ナンセンス 1杯'
 */
static char *decode_d(struct bolt11 *b11,
		      struct hash_u5 *hu5,
		      u5 **data, size_t *data_len,
		      size_t data_length, bool *have_d)
{
	u8 *desc;
	if (*have_d)
		return unknown_field(b11, hu5, data, data_len, 'd', data_length);

	desc = tal_arr(NULL, u8, data_length * 5 / 8);
	pull_bits_certain(hu5, data, data_len, desc, data_length*5, false);

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
static void decode_h(struct bolt11 *b11,
		     struct hash_u5 *hu5,
		     u5 **data, size_t *data_len,
		     size_t data_length, bool *have_h)
{
	if (*have_h) {
		unknown_field(b11, hu5, data, data_len, 'h', data_length);
		return;
	}

	/* BOLT #11:
	 *
	 * A reader... MUST skip over unknown fields, OR an `f` field
	 * with unknown `version`, OR `p`, `h`, `s` or `n` fields that do
	 * NOT have `data_length`s of 52, 52, 52 or 53, respectively. */
	if (data_length != 52) {
		unknown_field(b11, hu5, data, data_len, 'h', data_length);
		return;
	}

	b11->description_hash = tal(b11, struct sha256);
	pull_bits_certain(hu5, data, data_len, b11->description_hash, 256,
			  false);
	*have_h = true;
}

/* BOLT #11:
 *
 * `x` (6): `data_length` variable.  `expiry` time in seconds
 * (big-endian). Default is 3600 (1 hour) if not specified.
 */
#define DEFAULT_X 3600
static char *decode_x(struct bolt11 *b11,
		      struct hash_u5 *hu5,
		      u5 **data, size_t *data_len,
		      size_t data_length, bool *have_x)
{
	if (*have_x)
		return unknown_field(b11, hu5, data, data_len, 'x',
				     data_length);

	/* FIXME: Put upper limit in bolt 11 */
	if (!pull_uint(hu5, data, data_len, &b11->expiry, data_length * 5))
		return tal_fmt(b11, "x: length %zu chars is excessive",
			       *data_len);

	*have_x = true;
	return NULL;
}

/* BOLT #11:
 *
 * `c` (24): `data_length` variable.  `min_final_cltv_expiry` to use for the
 * last HTLC in the route. Default is 18 if not specified.
 */
static char *decode_c(struct bolt11 *b11,
		      struct hash_u5 *hu5,
		      u5 **data, size_t *data_len,
		      size_t data_length, bool *have_c)
{
	u64 c;
	if (*have_c)
		return unknown_field(b11, hu5, data, data_len, 'c',
				     data_length);

	/* FIXME: Put upper limit in bolt 11 */
	if (!pull_uint(hu5, data, data_len, &c, data_length * 5))
		return tal_fmt(b11, "c: length %zu chars is excessive",
			       *data_len);
	b11->min_final_cltv_expiry = c;
	/* Can overflow, since c is 64 bits but value must be < 32 bits */
	if (b11->min_final_cltv_expiry != c)
		return tal_fmt(b11, "c: %"PRIu64" is too large", c);

	*have_c = true;
	return NULL;
}

static char *decode_n(struct bolt11 *b11,
		      struct hash_u5 *hu5,
		      u5 **data, size_t *data_len,
		      size_t data_length, bool *have_n)
{
	if (*have_n)
		return unknown_field(b11, hu5, data, data_len, 'n',
				     data_length);

	/* BOLT #11:
	 *
	 * A reader... MUST skip over unknown fields, OR an `f` field
	 * with unknown `version`, OR `p`, `h`, `s` or `n` fields that do
	 * NOT have `data_length`s of 52, 52, 52 or 53, respectively. */
	if (data_length != 53)
		return unknown_field(b11, hu5, data, data_len, 'n',
				     data_length);

	pull_bits_certain(hu5, data, data_len, &b11->receiver_id.k,
			  data_length * 5, false);
	if (!node_id_valid(&b11->receiver_id))
		return tal_fmt(b11, "n: invalid pubkey %s",
			       node_id_to_hexstr(tmpctx, &b11->receiver_id));

	*have_n = true;
	return NULL;
}

/* BOLT #11:
 *
 * * `s` (16): `data_length` 52. This 256-bit secret prevents
 *    forwarding nodes from probing the payment recipient.
 */
static char *decode_s(struct bolt11 *b11,
		      struct hash_u5 *hu5,
		      u5 **data, size_t *data_len,
		      size_t data_length,
		      bool *have_s)
{
	if (*have_s)
		return unknown_field(b11, hu5, data, data_len, 's',
				     data_length);

	/* BOLT #11:
	 *
	 * A reader... MUST skip over unknown fields, OR an `f` field
	 * with unknown `version`, OR `p`, `h`, `s` or `n` fields that do
	 * NOT have `data_length`s of 52, 52, 52 or 53, respectively. */
	if (data_length != 52)
		return unknown_field(b11, hu5, data, data_len, 's',
				     data_length);

	b11->payment_secret = tal(b11, struct secret);
	pull_bits_certain(hu5, data, data_len, b11->payment_secret, 256,
			  false);
	*have_s = true;
	return NULL;
}

/* BOLT #11:
 *
 * `f` (9): `data_length` variable, depending on version. Fallback
 * on-chain address: for Bitcoin, this starts with a 5-bit `version`
 * and contains a witness program or P2PKH or P2SH address.
 */
static char *decode_f(struct bolt11 *b11,
		      struct hash_u5 *hu5,
		      u5 **data, size_t *data_len,
		      size_t data_length)
{
	u64 version;
	u8 *fallback;

	if (!pull_uint(hu5, data, data_len, &version, 5))
		return tal_fmt(b11, "f: data_length %zu short", data_length);
	data_length--;

	/* BOLT #11:
	 *
	 * for Bitcoin payments... MUST set an `f` field to a valid
	 * witness version and program, OR to `17` followed by a
	 * public key hash, OR to `18` followed by a script hash.
	*/
	if (version == 17) {
		/* Pay to pubkey hash (P2PKH) */
		struct bitcoin_address pkhash;
		if (num_u8(data_length) != sizeof(pkhash))
			return tal_fmt(b11, "f: pkhash length %zu",
				       data_length);

		pull_bits_certain(hu5, data, data_len, &pkhash, data_length*5,
				  false);
		fallback = scriptpubkey_p2pkh(b11, &pkhash);
	} else if (version == 18) {
		/* Pay to pubkey script hash (P2SH) */
		struct ripemd160 shash;
		if (num_u8(data_length) != sizeof(shash))
			return tal_fmt(b11, "f: p2sh length %zu",
				       data_length);

		pull_bits_certain(hu5, data, data_len, &shash, data_length*5,
				  false);
		fallback = scriptpubkey_p2sh_hash(b11, &shash);
	} else if (version < 17) {
		u8 *f = tal_arr(b11, u8, data_length * 5 / 8);
		if (version == 0) {
			if (tal_count(f) != 20 && tal_count(f) != 32)
				return tal_fmt(b11,
					       "f: witness v0 bad length %zu",
					       data_length);
		}
		pull_bits_certain(hu5, data, data_len, f, data_length * 5,
				  false);
		fallback = scriptpubkey_witness_raw(b11, version,
						    f, tal_count(f));
		tal_free(f);
	} else {
		/* Restore version for unknown field! */
		(*data)--;
		(*data_len)++;
		data_length++;
		return unknown_field(b11, hu5, data, data_len, 'f',
				     data_length);
	}

	if (b11->fallbacks == NULL)
		b11->fallbacks = tal_arr(b11, const u8 *, 1);
	else
		tal_resize(&b11->fallbacks, tal_count(b11->fallbacks) + 1);

	b11->fallbacks[tal_count(b11->fallbacks)-1]
		= tal_steal(b11->fallbacks, fallback);
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
static char *decode_r(struct bolt11 *b11,
		      struct hash_u5 *hu5,
		      u5 **data, size_t *data_len,
		      size_t data_length)
{
	size_t rlen = data_length * 5 / 8;
	u8 *r8 = tal_arr(tmpctx, u8, rlen);
	size_t n = 0;
	struct route_info *r = tal_arr(tmpctx, struct route_info, n);
	const u8 *cursor = r8;

	/* Route hops don't split in 5 bit boundaries, so convert whole thing */
	pull_bits_certain(hu5, data, data_len, r8, data_length * 5, false);

	do {
		struct route_info ri;
		if (!fromwire_route_info(&cursor, &rlen, &ri)) {
			return tal_fmt(b11, "r: hop %zu truncated", n);
		}
		tal_arr_expand(&r, ri);
	} while (rlen);

	/* Append route */
	tal_arr_expand(&b11->routes, tal_steal(b11, r));
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
static char *decode_9(struct bolt11 *b11,
		      const struct feature_set *our_features,
		      struct hash_u5 *hu5,
		      u5 **data, size_t *data_len,
		      size_t data_length)
{
	size_t flen = (data_length * 5 + 7) / 8;
	int badf;

	b11->features = tal_arr(b11, u8, flen);
	pull_bits_certain(hu5, data, data_len, b11->features,
			  data_length * 5, true);

	/* pull_bits pads with zero bits: we need to remove them. */
	shift_bitmap_down(b11->features,
			  flen * 8 - data_length * 5);

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
	 *   - if the `c` field (`min_final_cltv_expiry`) is not provided:
	 *     - MUST use an expiry delta of at least 18 when making the payment
	 */
	b11->min_final_cltv_expiry = 18;
	b11->payment_secret = NULL;

	if (msat)
		b11->msat = tal_dup(b11, struct amount_msat, msat);
	return b11;
}

/* Extracts signature but does not check it. */
struct bolt11 *bolt11_decode_nosig(const tal_t *ctx, const char *str,
				   const struct feature_set *our_features,
				   const char *description,
				   const struct chainparams *must_be_chain,
				   struct sha256 *hash,
				   u5 **sig,
				   bool *have_n,
				   char **fail)
{
	char *hrp, *amountstr, *prefix;
	u5 *data;
	size_t data_len;
	struct bolt11 *b11 = new_bolt11(ctx, NULL);
	struct hash_u5 hu5;
	bool have_p = false, have_d = false, have_h = false,
		have_x = false, have_c = false, have_s = false;

	*have_n = false;
	b11->routes = tal_arr(b11, struct route_info *, 0);

	/* BOLT #11:
	 *
	 * If a URI scheme is desired, the current recommendation is to either
	 * use 'lightning:' as a prefix before the BOLT-11 encoding
	 */
	if (strstarts(str, "lightning:") || strstarts(str, "LIGHTNING:"))
		str += strlen("lightning:");

	if (strlen(str) < 8)
		return decode_fail(b11, fail, "Bad bech32 string");

	hrp = tal_arr(tmpctx, char, strlen(str) - 6);
	data = tal_arr(tmpctx, u5, strlen(str) - 8);

	if (bech32_decode(hrp, data, &data_len, str, (size_t)-1)
	    != BECH32_ENCODING_BECH32)
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
	if (!pull_uint(&hu5, &data, &data_len, &b11->timestamp, 35))
		return decode_fail(b11, fail, "Can't get 35-bit timestamp");

	while (data_len > 520 / 5) {
		const char *problem = NULL;
		u64 type, data_length;

		/* BOLT #11:
		 *
		 * Each Tagged Field is of the form:
		 *
		 * 1. `type` (5 bits)
		 * 1. `data_length` (10 bits, big-endian)
		 * 1. `data` (`data_length` x 5 bits)
		 */
		if (!pull_uint(&hu5, &data, &data_len, &type, 5)
		    || !pull_uint(&hu5, &data, &data_len, &data_length, 10))
			return decode_fail(b11, fail,
					   "Can't get tag and length");

		/* Can't exceed total data remaining. */
		if (data_length > data_len)
			return decode_fail(b11, fail, "%c: truncated",
					   bech32_charset[type]);

		switch (bech32_charset[type]) {
		case 'p':
			decode_p(b11, &hu5, &data, &data_len, data_length,
				 &have_p);
			break;

		case 'd':
			problem = decode_d(b11, &hu5, &data, &data_len,
					   data_length, &have_d);
			break;

		case 'h':
			decode_h(b11, &hu5, &data, &data_len, data_length,
				 &have_h);
			break;

		case 'n':
			problem = decode_n(b11, &hu5, &data,
					   &data_len, data_length,
					   have_n);
			break;

		case 'x':
			problem = decode_x(b11, &hu5, &data,
					   &data_len, data_length,
					   &have_x);
			break;

		case 'c':
			problem = decode_c(b11, &hu5, &data,
					   &data_len, data_length,
					   &have_c);
			break;

		case 'f':
			problem = decode_f(b11, &hu5, &data,
					   &data_len, data_length);
			break;
		case 'r':
			problem = decode_r(b11, &hu5, &data, &data_len,
					   data_length);
			break;
		case '9':
			problem = decode_9(b11, our_features, &hu5,
					   &data, &data_len,
					   data_length);
			break;
		case 's':
			problem = decode_s(b11, &hu5, &data, &data_len,
					   data_length, &have_s);
			break;
		default:
			unknown_field(b11, &hu5, &data, &data_len,
				      bech32_charset[type], data_length);
		}
		if (problem)
			return decode_fail(b11, fail, "%s", problem);
	}

	if (!have_p)
		return decode_fail(b11, fail, "No valid 'p' field found");

	if (have_h && description) {
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

	hash_u5_done(&hu5, hash);
	*sig = tal_dup_arr(ctx, u5, data, data_len, 0);
	return b11;
}

/* Decodes and checks signature; returns NULL on error. */
struct bolt11 *bolt11_decode(const tal_t *ctx, const char *str,
			     const struct feature_set *our_features,
			     const char *description,
			     const struct chainparams *must_be_chain,
			     char **fail)
{
	u5 *sigdata;
	size_t data_len;
	u8 sig_and_recid[65];
	secp256k1_ecdsa_recoverable_signature sig;
	struct bolt11 *b11;
	struct sha256 hash;
	bool have_n;

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
	if (!pull_bits(NULL, &sigdata, &data_len, sig_and_recid, 520, false))
		return decode_fail(b11, fail, "signature truncated");

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
 * - MUST include one `c` field (`min_final_cltv_expiry`).
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
	} else if (tal_count(fallback)
		   && fallback[0] >= 0x50
		   && fallback[0] < (0x50+16)) {
		/* Other (future) witness versions: turn OP_N into N */
		push_fallback_addr(data, fallback[0] - 0x50, fallback + 1,
				   tal_count(fallback) - 1);
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

static void maybe_encode_9(u5 **data, const u8 *features)
{
	u5 *f5 = tal_arr(NULL, u5, 0);

	for (size_t i = 0; i < tal_count(features) * CHAR_BIT; i++) {
		if (!feature_is_set(features, i))
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

	/* BOLT #11:
	 *
	 * if a writer offers more than one of any field type,
	 * it... MUST specify the most-preferred field first, followed
	 * by less-preferred fields, in order.
	 */
	/* Thus we do built-in fields, then extras last. */
	encode_p(&data, &b11->payment_hash);

	if (b11->description)
		encode_d(&data, b11->description);

	if (b11->description_hash)
		encode_h(&data, b11->description_hash);

	if (n_field)
		encode_n(&data, &b11->receiver_id);

	if (b11->expiry != DEFAULT_X)
		encode_x(&data, b11->expiry);

	/* BOLT #11:
	 *   - MUST include one `c` field (`min_final_cltv_expiry`).
	 */
	encode_c(&data, b11->min_final_cltv_expiry);

	if (b11->payment_secret)
		encode_s(&data, b11->payment_secret);

	for (size_t i = 0; i < tal_count(b11->fallbacks); i++)
		encode_f(&data, b11->fallbacks[i]);

	for (size_t i = 0; i < tal_count(b11->routes); i++)
		encode_r(&data, b11->routes[i]);

	maybe_encode_9(&data, b11->features);

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
