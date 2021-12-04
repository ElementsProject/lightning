#include "config.h"
#include <assert.h>
#include <ccan/crypto/siphash24/siphash24.h>
#include <ccan/endian/endian.h>
#include <ccan/mem/mem.h>
#include <common/utils.h>
#include <wire/wire.h>

#ifndef SUPERVERBOSE
#define SUPERVERBOSE(...)
#endif

extern const struct chainparams *chainparams;

/* Sets *cursor to NULL and returns NULL when extraction fails. */
void *fromwire_fail(const u8 **cursor, size_t *max)
{
	*cursor = NULL;
	*max = 0;
	return NULL;
}

const u8 *fromwire(const u8 **cursor, size_t *max, void *copy, size_t n)
{
	const u8 *p = *cursor;

	if (*max < n) {
		/* Just make sure we don't leak uninitialized mem! */
		if (copy)
			memset(copy, 0, n);
		if (*cursor)
			SUPERVERBOSE("less than encoding length");
		return fromwire_fail(cursor, max);
	}
	*cursor += n;
	*max -= n;
	if (copy)
		memcpy(copy, p, n);
	return memcheck(p, n);
}

int fromwire_peektype(const u8 *cursor)
{
	be16 be_type;
	size_t max = tal_count(cursor);

	fromwire(&cursor, &max, &be_type, sizeof(be_type));
	if (!cursor)
		return -1;
	return be16_to_cpu(be_type);
}

u8 fromwire_u8(const u8 **cursor, size_t *max)
{
	u8 ret;

	if (!fromwire(cursor, max, &ret, sizeof(ret)))
		return 0;
	return ret;
}

u16 fromwire_u16(const u8 **cursor, size_t *max)
{
	be16 ret;

	if (!fromwire(cursor, max, &ret, sizeof(ret)))
		return 0;
	return be16_to_cpu(ret);
}

u32 fromwire_u32(const u8 **cursor, size_t *max)
{
	be32 ret;

	if (!fromwire(cursor, max, &ret, sizeof(ret)))
		return 0;
	return be32_to_cpu(ret);
}

u64 fromwire_u64(const u8 **cursor, size_t *max)
{
	be64 ret;

	if (!fromwire(cursor, max, &ret, sizeof(ret)))
		return 0;
	return be64_to_cpu(ret);
}

static u64 fromwire_tlv_uint(const u8 **cursor, size_t *max, size_t maxlen)
{
	u8 bytes[8];
	size_t length;
	be64 val;

	assert(maxlen <= sizeof(bytes));

	/* BOLT #1:
	 *
	 * - if `length` is not exactly equal to that required for the
	 *   known encoding for `type`:
	 *      - MUST fail to parse the `tlv_stream`.
	 */
	length = *max;
	if (length > maxlen) {
		SUPERVERBOSE("greater than encoding length");
		fromwire_fail(cursor, max);
		return 0;
	}

	memset(bytes, 0, sizeof(bytes));
	fromwire(cursor, max, bytes + sizeof(bytes) - length, length);

	/* BOLT #1:
	 * - if variable-length fields within the known encoding for `type` are
	 *   not minimal:
	 *    - MUST fail to parse the `tlv_stream`.
	 */
	if (length > 0 && bytes[sizeof(bytes) - length] == 0) {
		SUPERVERBOSE("not minimal");
		fromwire_fail(cursor, max);
		return 0;
	}
	BUILD_ASSERT(sizeof(val) == sizeof(bytes));
	memcpy(&val, bytes, sizeof(bytes));
	return be64_to_cpu(val);
}

u16 fromwire_tu16(const u8 **cursor, size_t *max)
{
	return fromwire_tlv_uint(cursor, max, 2);
}

u32 fromwire_tu32(const u8 **cursor, size_t *max)
{
	return fromwire_tlv_uint(cursor, max, 4);
}

u64 fromwire_tu64(const u8 **cursor, size_t *max)
{
	return fromwire_tlv_uint(cursor, max, 8);
}

bool fromwire_bool(const u8 **cursor, size_t *max)
{
	u8 ret;

	if (!fromwire(cursor, max, &ret, sizeof(ret)))
		return false;
	if (ret != 0 && ret != 1)
		fromwire_fail(cursor, max);
	return ret;
}

errcode_t fromwire_errcode_t(const u8 **cursor, size_t *max)
{
	errcode_t ret;

	ret = (s32)fromwire_u32(cursor, max);

	return ret;
}

void fromwire_secp256k1_ecdsa_signature(const u8 **cursor,
				size_t *max, secp256k1_ecdsa_signature *sig)
{
	u8 compact[64];

	if (!fromwire(cursor, max, compact, sizeof(compact)))
		return;

	if (secp256k1_ecdsa_signature_parse_compact(secp256k1_ctx, sig, compact)
	    != 1)
		fromwire_fail(cursor, max);
}

void fromwire_secp256k1_ecdsa_recoverable_signature(const u8 **cursor,
				    size_t *max,
				    secp256k1_ecdsa_recoverable_signature *rsig)
{
	u8 compact[64];
	int recid;

	fromwire(cursor, max, compact, sizeof(compact));
	recid = fromwire_u8(cursor, max);

	if (secp256k1_ecdsa_recoverable_signature_parse_compact(secp256k1_ctx,
								rsig, compact,
								recid) != 1)
		fromwire_fail(cursor, max);
}

void fromwire_sha256(const u8 **cursor, size_t *max, struct sha256 *sha256)
{
	fromwire(cursor, max, sha256, sizeof(*sha256));
}

void fromwire_ripemd160(const u8 **cursor, size_t *max, struct ripemd160 *ripemd)
{
	fromwire(cursor, max, ripemd, sizeof(*ripemd));
}

void fromwire_u8_array(const u8 **cursor, size_t *max, u8 *arr, size_t num)
{
	fromwire(cursor, max, arr, num);
}

void fromwire_utf8_array(const u8 **cursor, size_t *max, char *arr, size_t num)
{
	fromwire(cursor, max, arr, num);
	if (!utf8_check(arr, num))
		fromwire_fail(cursor, max);
}

u8 *fromwire_tal_arrn(const tal_t *ctx,
		      const u8 **cursor, size_t *max, size_t num)
{
	u8 *arr;
	if (num == 0)
		return NULL;

	if (num > *max)
		return fromwire_fail(cursor, max);

	arr = tal_arr(ctx, u8, num);
	fromwire_u8_array(cursor, max, arr, num);
	return arr;
}

void fromwire_pad(const u8 **cursor, size_t *max, size_t num)
{
	fromwire(cursor, max, NULL, num);
}

/*
 * Don't allow control chars except spaces: we only use this for stuff
 * from subdaemons, who shouldn't do that.
 */
char *fromwire_wirestring(const tal_t *ctx, const u8 **cursor, size_t *max)
{
	size_t i;

	for (i = 0; i < *max; i++) {
		if ((*cursor)[i] == '\0') {
			char *str = tal_arr(ctx, char, i + 1);
			fromwire(cursor, max, str, i + 1);
			return str;
		}
		if ((*cursor)[i] < ' ')
			break;
	}
	return fromwire_fail(cursor, max);
}

void fromwire_siphash_seed(const u8 **cursor, size_t *max,
			   struct siphash_seed *seed)
{
	fromwire(cursor, max, seed, sizeof(*seed));
}
