#include "wire.h"
#include <bitcoin/preimage.h>
#include <bitcoin/pubkey.h>
#include <bitcoin/shadouble.h>
#include <bitcoin/tx.h>
#include <ccan/build_assert/build_assert.h>
#include <ccan/crypto/siphash24/siphash24.h>
#include <ccan/endian/endian.h>
#include <ccan/mem/mem.h>
#include <ccan/tal/str/str.h>
#include <common/type_to_string.h>
#include <common/utils.h>

/* Sets *cursor to NULL and returns NULL when extraction fails. */
const void *fromwire_fail(const u8 **cursor, size_t *max)
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

void fromwire_double(const u8 **cursor, size_t *max, double *ret)
{
	fromwire(cursor, max, ret, sizeof(*ret));
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

void fromwire_pubkey(const u8 **cursor, size_t *max, struct pubkey *pubkey)
{
	u8 der[PUBKEY_DER_LEN];

	if (!fromwire(cursor, max, der, sizeof(der)))
		return;

	if (!pubkey_from_der(der, sizeof(der), pubkey))
		fromwire_fail(cursor, max);
}

void fromwire_secret(const u8 **cursor, size_t *max, struct secret *secret)
{
	fromwire(cursor, max, secret->data, sizeof(secret->data));
}

void fromwire_privkey(const u8 **cursor, size_t *max, struct privkey *privkey)
{
	fromwire_secret(cursor, max, &privkey->secret);
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

void fromwire_channel_id(const u8 **cursor, size_t *max,
			 struct channel_id *channel_id)
{
	fromwire(cursor, max, channel_id, sizeof(*channel_id));
}

void fromwire_short_channel_id(const u8 **cursor, size_t *max,
			       struct short_channel_id *short_channel_id)
{
	short_channel_id->u64 = fromwire_u64(cursor, max);
}

void fromwire_short_channel_id_dir(const u8 **cursor, size_t *max,
				   struct short_channel_id_dir *scidd)
{
	fromwire_short_channel_id(cursor, max, &scidd->scid);
	scidd->dir = fromwire_bool(cursor, max);
}

void fromwire_sha256(const u8 **cursor, size_t *max, struct sha256 *sha256)
{
	fromwire(cursor, max, sha256, sizeof(*sha256));
}

void fromwire_sha256_double(const u8 **cursor, size_t *max,
			    struct sha256_double *sha256d)
{
	fromwire_sha256(cursor, max, &sha256d->sha);
}

void fromwire_bitcoin_txid(const u8 **cursor, size_t *max,
			   struct bitcoin_txid *txid)
{
	fromwire_sha256_double(cursor, max, &txid->shad);
}

void fromwire_bitcoin_signature(const u8 **cursor, size_t *max,
				struct bitcoin_signature *sig)
{
	fromwire_secp256k1_ecdsa_signature(cursor, max, &sig->s);
	sig->sighash_type = fromwire_u8(cursor, max);
	if (!sighash_type_valid(sig->sighash_type))
		fromwire_fail(cursor, max);
}

void fromwire_bitcoin_blkid(const u8 **cursor, size_t *max,
			    struct bitcoin_blkid *blkid)
{
	fromwire_sha256_double(cursor, max, &blkid->shad);
}

void fromwire_preimage(const u8 **cursor, size_t *max, struct preimage *preimage)
{
	fromwire(cursor, max, preimage, sizeof(*preimage));
}

void fromwire_ripemd160(const u8 **cursor, size_t *max, struct ripemd160 *ripemd)
{
	fromwire(cursor, max, ripemd, sizeof(*ripemd));
}

void fromwire_u8_array(const u8 **cursor, size_t *max, u8 *arr, size_t num)
{
	fromwire(cursor, max, arr, num);
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
	fromwire_fail(cursor, max);
	return NULL;
}

REGISTER_TYPE_TO_STRING(short_channel_id, short_channel_id_to_str);
REGISTER_TYPE_TO_STRING(short_channel_id_dir, short_channel_id_dir_to_str);
REGISTER_TYPE_TO_HEXSTR(channel_id);

/* BOLT #2:
 *
 * This message introduces the `channel_id` to identify the channel.  It's
 * derived from the funding transaction by combining the `funding_txid` and
 * the `funding_output_index`, using big-endian exclusive-OR
 * (i.e. `funding_output_index` alters the last 2 bytes).
 */
void derive_channel_id(struct channel_id *channel_id,
		       const struct bitcoin_txid *txid, u16 txout)
{
	BUILD_ASSERT(sizeof(*channel_id) == sizeof(*txid));
	memcpy(channel_id, txid, sizeof(*channel_id));
	channel_id->id[sizeof(*channel_id)-2] ^= txout >> 8;
	channel_id->id[sizeof(*channel_id)-1] ^= txout;
}

struct bitcoin_tx *fromwire_bitcoin_tx(const tal_t *ctx,
				       const u8 **cursor, size_t *max)
{
	return pull_bitcoin_tx(ctx, cursor, max);
}

void fromwire_siphash_seed(const u8 **cursor, size_t *max,
			   struct siphash_seed *seed)
{
	fromwire(cursor, max, seed, sizeof(*seed));
}
