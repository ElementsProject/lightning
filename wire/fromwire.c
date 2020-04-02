#include "wire.h"
#include <assert.h>
#include <bitcoin/chainparams.h>
#include <bitcoin/preimage.h>
#include <bitcoin/pubkey.h>
#include <bitcoin/shadouble.h>
#include <bitcoin/tx.h>
#include <ccan/build_assert/build_assert.h>
#include <ccan/crypto/siphash24/siphash24.h>
#include <ccan/endian/endian.h>
#include <ccan/mem/mem.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/str/str.h>
#include <common/amount.h>
#include <common/errcode.h>
#include <common/node_id.h>
#include <common/type_to_string.h>
#include <common/utils.h>

#ifndef SUPERVERBOSE
#define SUPERVERBOSE(...)
#endif

extern const struct chainparams *chainparams;

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

bigsize_t fromwire_bigsize(const u8 **cursor, size_t *max)
{
	bigsize_t v;
	size_t len = bigsize_get(*cursor, *max, &v);

	if (len == 0) {
		fromwire_fail(cursor, max);
		return 0;
	}
	assert(len <= *max);
	fromwire(cursor, max, NULL, len);
	return v;
}

void fromwire_pubkey(const u8 **cursor, size_t *max, struct pubkey *pubkey)
{
	u8 der[PUBKEY_CMPR_LEN];

	if (!fromwire(cursor, max, der, sizeof(der)))
		return;

	if (!pubkey_from_der(der, sizeof(der), pubkey)) {
		SUPERVERBOSE("not a valid point");
		fromwire_fail(cursor, max);
	}
}

void fromwire_node_id(const u8 **cursor, size_t *max, struct node_id *id)
{
	fromwire(cursor, max, &id->k, sizeof(id->k));
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

u8 *fromwire_tal_arrn(const tal_t *ctx,
		      const u8 **cursor, size_t *max, size_t num)
{
	u8 *arr;
	if (num > *max) {
		fromwire_fail(cursor, max);
		return NULL;
	}
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
	fromwire_fail(cursor, max);
	return NULL;
}

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
	struct bitcoin_tx *tx;
	u16 input_amts_len;
	size_t i;

	tx = pull_bitcoin_tx(ctx, cursor, max);
	input_amts_len = fromwire_u16(cursor, max);
	/* We don't serialize the amounts if they're not *all* populated */
	if (input_amts_len != tal_count(tx->input_amounts))
		return tx;

	for (i = 0; i < input_amts_len; i++) {
		struct amount_sat sat;
		sat = fromwire_amount_sat(cursor, max);
		tx->input_amounts[i] =
			tal_dup(tx, struct amount_sat, &sat);
	}

	return tx;
}

void fromwire_siphash_seed(const u8 **cursor, size_t *max,
			   struct siphash_seed *seed)
{
	fromwire(cursor, max, seed, sizeof(*seed));
}

struct amount_msat fromwire_amount_msat(const u8 **cursor, size_t *max)
{
	struct amount_msat msat;

	msat.millisatoshis = fromwire_u64(cursor, max); /* Raw: primitive */
	return msat;
}

struct amount_sat fromwire_amount_sat(const u8 **cursor, size_t *max)
{
	struct amount_sat sat;

	sat.satoshis = fromwire_u64(cursor, max); /* Raw: primitive */
	return sat;
}

void fromwire_bip32_key_version(const u8** cursor, size_t *max,
					struct bip32_key_version *version)
{
	version->bip32_pubkey_version = fromwire_u32(cursor, max);
	version->bip32_privkey_version = fromwire_u32(cursor, max);
}

struct bitcoin_tx_output *fromwire_bitcoin_tx_output(const tal_t *ctx,
						     const u8 **cursor, size_t *max)
{
	struct bitcoin_tx_output *output = tal(ctx, struct bitcoin_tx_output);
	output->amount = fromwire_amount_sat(cursor, max);
	u16 script_len = fromwire_u16(cursor, max);
	output->script = fromwire_tal_arrn(output, cursor, max, script_len);
	if (!*cursor)
		return tal_free(output);
	return output;
}

struct witscript *fromwire_witscript(const tal_t *ctx, const u8 **cursor, size_t *max)
{
	struct witscript *retval = tal(ctx, struct witscript);
	u16 len = fromwire_u16(cursor, max);
	retval->ptr = fromwire_tal_arrn(retval, cursor, max, len);
	if (!*cursor)
		return tal_free(retval);
	return retval;
}

void fromwire_chainparams(const u8 **cursor, size_t *max,
			  const struct chainparams **chainparams)
{
	struct bitcoin_blkid genesis;
	fromwire_bitcoin_blkid(cursor, max, &genesis);
	*chainparams = chainparams_by_chainhash(&genesis);
}
