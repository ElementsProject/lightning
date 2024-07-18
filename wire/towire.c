#include "config.h"
#include "wire.h"
#include <assert.h>
#include <ccan/crypto/siphash24/siphash24.h>
#include <ccan/endian/endian.h>
#include <ccan/mem/mem.h>
#include <channeld/inflight.h>
#include <common/utils.h>

void towire(u8 **pptr, const void *data, size_t len)
{
	size_t oldsize = tal_count(*pptr);

	tal_resize(pptr, oldsize + len);
	/* The C standards committee has a lot to answer for :( */
	if (len)
		memcpy(*pptr + oldsize, memcheck(data, len), len);
}

void towire_u8(u8 **pptr, u8 v)
{
	towire(pptr, &v, sizeof(v));
}

void towire_u16(u8 **pptr, u16 v)
{
	be16 l = cpu_to_be16(v);
	towire(pptr, &l, sizeof(l));
}

void towire_u32(u8 **pptr, u32 v)
{
	be32 l = cpu_to_be32(v);
	towire(pptr, &l, sizeof(l));
}

void towire_u64(u8 **pptr, u64 v)
{
	be64 l = cpu_to_be64(v);
	towire(pptr, &l, sizeof(l));
}

void towire_s8(u8 **pptr, s8 v)
{
	towire_u8(pptr, (u8)v);
}

void towire_s32(u8 **pptr, s32 v)
{
	towire_u32(pptr, (u32)v);
}

void towire_s16(u8 **pptr, s16 v)
{
	towire_u16(pptr, (u16)v);
}

void towire_s64(u8 **pptr, s64 v)
{
	towire_u64(pptr, (u64)v);
}

static void towire_tlv_uint(u8 **pptr, u64 v)
{
	u8 bytes[8];
	size_t num_zeroes;
	be64 val;

	val = cpu_to_be64(v);
	CROSS_TYPE_ASSIGNMENT(&bytes, &val);

	for (num_zeroes = 0; num_zeroes < sizeof(bytes); num_zeroes++)
		if (bytes[num_zeroes] != 0)
			break;

	towire(pptr, bytes + num_zeroes, sizeof(bytes) - num_zeroes);
}

void towire_tu16(u8 **pptr, u16 v)
{
	return towire_tlv_uint(pptr, v);
}

void towire_tu32(u8 **pptr, u32 v)
{
	return towire_tlv_uint(pptr, v);
}

void towire_tu64(u8 **pptr, u64 v)
{
	return towire_tlv_uint(pptr, v);
}

void towire_bool(u8 **pptr, bool v)
{
	u8 val = v;
	towire(pptr, &val, sizeof(val));
}

void towire_jsonrpc_errcode(u8 **pptr, enum jsonrpc_errcode v)
{
	towire_u32(pptr, (u32)v);
}

void towire_secp256k1_ecdsa_signature(u8 **pptr,
				      const secp256k1_ecdsa_signature *sig)
{
	u8 compact[64];

	secp256k1_ecdsa_signature_serialize_compact(secp256k1_ctx,
						    compact, sig);
	towire(pptr, compact, sizeof(compact));
}

void towire_secp256k1_ecdsa_recoverable_signature(u8 **pptr,
			const secp256k1_ecdsa_recoverable_signature *rsig)
{
	u8 compact[64];
	int recid;

	secp256k1_ecdsa_recoverable_signature_serialize_compact(secp256k1_ctx,
								compact,
								&recid,
								rsig);
	towire(pptr, compact, sizeof(compact));
	towire_u8(pptr, recid);
}

void towire_sha256(u8 **pptr, const struct sha256 *sha256)
{
	towire(pptr, sha256, sizeof(*sha256));
}

void towire_ripemd160(u8 **pptr, const struct ripemd160 *ripemd)
{
	towire(pptr, ripemd, sizeof(*ripemd));
}

void towire_u8_array(u8 **pptr, const u8 *arr, size_t num)
{
	towire(pptr, arr, num);
}

void towire_utf8_array(u8 **pptr, const char *arr, size_t num)
{
	assert(utf8_check(arr, num));
	towire(pptr, arr, num);
}

void towire_pad(u8 **pptr, size_t num)
{
	/* Simply insert zeros. */
	size_t oldsize = tal_count(*pptr);

	tal_resize(pptr, oldsize + num);
	memset(*pptr + oldsize, 0, num);
}

void towire_wirestring(u8 **pptr, const char *str)
{
	towire(pptr, str, strlen(str) + 1);
}

void towire_siphash_seed(u8 **pptr, const struct siphash_seed *seed)
{
	towire(pptr, seed, sizeof(*seed));
}
