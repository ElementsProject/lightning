#include "wire.h"
#include <assert.h>
#include <bitcoin/chainparams.h>
#include <bitcoin/preimage.h>
#include <bitcoin/shadouble.h>
#include <bitcoin/tx.h>
#include <ccan/crypto/ripemd160/ripemd160.h>
#include <ccan/crypto/siphash24/siphash24.h>
#include <ccan/endian/endian.h>
#include <ccan/mem/mem.h>
#include <ccan/tal/tal.h>
#include <common/amount.h>
#include <common/node_id.h>
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

static void towire_tlv_uint(u8 **pptr, u64 v)
{
	u8 bytes[8];
	size_t num_zeroes;
	be64 val;

	val = cpu_to_be64(v);
	BUILD_ASSERT(sizeof(val) == sizeof(bytes));
	memcpy(bytes, &val, sizeof(bytes));

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

void towire_double(u8 **pptr, const double *v)
{
	towire(pptr, v, sizeof(*v));
}

void towire_bool(u8 **pptr, bool v)
{
	u8 val = v;
	towire(pptr, &val, sizeof(val));
}

void towire_int(u8 **pptr, int v)
{
	towire(pptr, &v, sizeof(v));
}

void towire_bigsize(u8 **pptr, const bigsize_t val)
{
	u8 buf[BIGSIZE_MAX_LEN];
	size_t len;

	len = bigsize_put(buf, val);
	towire(pptr, buf, len);
}

void towire_pubkey(u8 **pptr, const struct pubkey *pubkey)
{
	u8 output[PUBKEY_CMPR_LEN];
	size_t outputlen = sizeof(output);

	secp256k1_ec_pubkey_serialize(secp256k1_ctx, output, &outputlen,
				      &pubkey->pubkey,
				      SECP256K1_EC_COMPRESSED);

	towire(pptr, output, outputlen);
}

void towire_node_id(u8 **pptr, const struct node_id *id)
{
	/* Cheap sanity check */
	assert(id->k[0] == 0x2 || id->k[0] == 0x3);
	towire(pptr, id->k, sizeof(id->k));
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

void towire_short_channel_id_dir(u8 **pptr,
				 const struct short_channel_id_dir *scidd)
{
	towire_short_channel_id(pptr, &scidd->scid);
	towire_bool(pptr, scidd->dir);
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

void towire_bitcoin_signature(u8 **pptr, const struct bitcoin_signature *sig)
{
	assert(sighash_type_valid(sig->sighash_type));
	towire_secp256k1_ecdsa_signature(pptr, &sig->s);
	towire_u8(pptr, sig->sighash_type);
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

void towire_amount_msat(u8 **pptr, const struct amount_msat msat)
{
	towire_u64(pptr, msat.millisatoshis); /* Raw: primitive */
}

void towire_amount_sat(u8 **pptr, const struct amount_sat sat)
{
	towire_u64(pptr, sat.satoshis); /* Raw: primitive */
}

void towire_bip32_key_version(u8 **pptr, const struct bip32_key_version *version)
{
	towire_u32(pptr, version->bip32_pubkey_version);
	towire_u32(pptr, version->bip32_privkey_version);
}

void towire_bitcoin_tx_output(u8 **pptr, const struct bitcoin_tx_output *output)
{
	towire_amount_sat(pptr, output->amount);
	towire_u16(pptr, tal_count(output->script));
	towire_u8_array(pptr, output->script, tal_count(output->script));
}

void towire_witscript(u8 **pptr, const struct witscript *script)
{
	if (script == NULL) {
		towire_u16(pptr, 0);
	} else {
		assert(script->ptr != NULL);
		towire_u16(pptr, tal_count(script->ptr));
		towire_u8_array(pptr, script->ptr, tal_count(script->ptr));
	}
}

void towire_chainparams(u8 **cursor, const struct chainparams *chainparams)
{
	towire_bitcoin_blkid(cursor, &chainparams->genesis_blockhash);
}
