#include "wire.h"
#include <bitcoin/preimage.h>
#include <bitcoin/shadouble.h>
#include <bitcoin/tx.h>
#include <ccan/crypto/ripemd160/ripemd160.h>
#include <ccan/crypto/siphash24/siphash24.h>
#include <ccan/endian/endian.h>
#include <ccan/mem/mem.h>
#include <ccan/tal/tal.h>
#include <common/utils.h>

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

void towire_double(u8 **pptr, const double *v)
{
	towire(pptr, v, sizeof(*v));
}

void towire_bool(u8 **pptr, bool v)
{
	u8 val = v;
	towire(pptr, &val, sizeof(val));
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

void towire_secret(u8 **pptr, const struct secret *secret)
{
	towire(pptr, secret->data, sizeof(secret->data));
}

void towire_privkey(u8 **pptr, const struct privkey *privkey)
{
	towire_secret(pptr, &privkey->secret);
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

void towire_channel_id(u8 **pptr, const struct channel_id *channel_id)
{
	towire(pptr, channel_id, sizeof(*channel_id));
}

void towire_short_channel_id(u8 **pptr,
			     const struct short_channel_id *short_channel_id)
{
	towire_u64(pptr, short_channel_id->u64);
}

void towire_sha256(u8 **pptr, const struct sha256 *sha256)
{
	towire(pptr, sha256, sizeof(*sha256));
}

void towire_sha256_double(u8 **pptr, const struct sha256_double *sha256d)
{
	towire_sha256(pptr, &sha256d->sha);
}

void towire_bitcoin_txid(u8 **pptr, const struct bitcoin_txid *txid)
{
	towire_sha256_double(pptr, &txid->shad);
}

void towire_bitcoin_blkid(u8 **pptr, const struct bitcoin_blkid *blkid)
{
	towire_sha256_double(pptr, &blkid->shad);
}

void towire_preimage(u8 **pptr, const struct preimage *preimage)
{
	towire(pptr, preimage, sizeof(*preimage));
}

void towire_ripemd160(u8 **pptr, const struct ripemd160 *ripemd)
{
	towire(pptr, ripemd, sizeof(*ripemd));
}

void towire_u8_array(u8 **pptr, const u8 *arr, size_t num)
{
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

void towire_bitcoin_tx(u8 **pptr, const struct bitcoin_tx *tx)
{
	u8 *lin = linearize_tx(tmpctx, tx);
	towire_u8_array(pptr, lin, tal_count(lin));
}

void towire_siphash_seed(u8 **pptr, const struct siphash_seed *seed)
{
	towire(pptr, seed, sizeof(*seed));
}
