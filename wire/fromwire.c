#include "wire.h"
#include <bitcoin/pubkey.h>
#include <ccan/endian/endian.h>
#include <ccan/mem/mem.h>

/* Sets *cursor to NULL and returns NULL when extraction fails. */
static const void *fail_pull(const u8 **cursor, size_t *max)
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
		return fail_pull(cursor, max);
	}
	*cursor += n;
	*max -= n;
	if (copy)
		memcpy(copy, p, n);
	return memcheck(p, n);
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

void fromwire_pubkey(const u8 **cursor, size_t *max, struct pubkey *pubkey)
{
	u8 der[PUBKEY_DER_LEN];

	if (!fromwire(cursor, max, der, sizeof(der)))
		return;

	if (!pubkey_from_der(secp256k1_ctx, der, sizeof(der), pubkey))
		fail_pull(cursor, max);
}

void fromwire_signature(const u8 **cursor, size_t *max, struct signature *sig)
{
	u8 compact[64];

	if (!fromwire(cursor, max, compact, sizeof(compact)))
		return;

	if (secp256k1_ecdsa_signature_parse_compact(secp256k1_ctx,
						    &sig->sig, compact)
	    != 1)
		fail_pull(cursor, max);
}

void fromwire_channel_id(const u8 **cursor, size_t *max,
			 struct channel_id *channel_id)
{
	be32 txnum = 0;
	u8 outnum;

	channel_id->blocknum = fromwire_u32(cursor, max);
	/* Pulling 3 bytes off wire is tricky; they're big-endian. */
	fromwire(cursor, max, (char *)&txnum + 1, 3);
	channel_id->txnum = be32_to_cpu(txnum);
	fromwire(cursor, max, &outnum, 1);
	channel_id->outnum = outnum;
}
	
void fromwire_sha256(const u8 **cursor, size_t *max, struct sha256 *sha256)
{
	fromwire(cursor, max, sha256, sizeof(*sha256));
}

void fromwire_ipv6(const u8 **cursor, size_t *max, struct ipv6 *ipv6)
{
	fromwire(cursor, max, ipv6, sizeof(*ipv6));
}

void fromwire_u8_array(const u8 **cursor, size_t *max, u8 *arr, size_t num)
{
	fromwire(cursor, max, arr, num);
}

void fromwire_pad_array(const u8 **cursor, size_t *max, u8 *arr, size_t num)
{
	fromwire(cursor, max, arr, num);
}
	
void fromwire_signature_array(const u8 **cursor, size_t *max,
			      struct signature *arr, size_t num)
{
	size_t i;

	for (i = 0; i < num; i++)
		fromwire_signature(cursor, max, arr + i);
}
