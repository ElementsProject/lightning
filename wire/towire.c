#include "wire.h"
#include <ccan/endian/endian.h>
#include <ccan/mem/mem.h>
#include <ccan/tal/tal.h>

void towire(u8 **pptr, const void *data, size_t len)
{
	size_t oldsize = tal_count(*pptr);

	tal_resize(pptr, oldsize + len);
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

void towire_pubkey(u8 **pptr, const struct pubkey *pubkey)
{
	u8 output[PUBKEY_DER_LEN];
	size_t outputlen = sizeof(output);

	secp256k1_ec_pubkey_serialize(secp256k1_ctx, output, &outputlen,
				      &pubkey->pubkey,
				      SECP256K1_EC_COMPRESSED);
	towire(pptr, output, outputlen);
}

void towire_signature(u8 **pptr, const struct signature *sig)
{
	u8 compact[64];

	secp256k1_ecdsa_signature_serialize_compact(secp256k1_ctx,
						    compact, &sig->sig);
	towire(pptr, compact, sizeof(compact));
}

void towire_channel_id(u8 **pptr, const struct channel_id *channel_id)
{
	be32 txnum = cpu_to_be32(channel_id->txnum);
	u8 outnum = channel_id->outnum;
	
	towire_u32(pptr, channel_id->blocknum);
	towire(pptr, (char *)&txnum + 1, 3);
	towire(pptr, &outnum, 1);
}

void towire_sha256(u8 **pptr, const struct sha256 *sha256)
{
	towire(pptr, sha256, sizeof(*sha256));
}

void towire_ipv6(u8 **pptr, const struct ipv6 *ipv6)
{
	towire(pptr, ipv6, sizeof(*ipv6));
}

void towire_u8_array(u8 **pptr, const u8 *arr, size_t num)
{
	towire(pptr, arr, num);
}

void towire_pad_array(u8 **pptr, const u8 *arr, size_t num)
{
	/* Simply insert zeros. */
	size_t oldsize = tal_count(*pptr);

	tal_resize(pptr, oldsize + num);
	memset(*pptr + oldsize, 0, num);
}
	
void towire_signature_array(u8 **pptr, const struct signature *arr, size_t num)
{
	size_t i;

	for (i = 0; i < num; i++)
		towire_signature(pptr, arr+i);
}
