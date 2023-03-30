/* This is designed to fix up malformed PBSTs, where prior to v0.12.0
 * (commit 572942c783a58e518f0a1b449412a82717594636) we would put raw
 * signatures, not DER-encoded signatures, inside our PSBT inputs'
 * PSBT_IN_PARTIAL_SIG.
 *
 * As of libwally 0.88 (and perhaps 0.87?) it will refuse to load them.
 */
#include "config.h"
#include <bitcoin/pubkey.h>
#include <bitcoin/signature.h>
#include <ccan/array_size/array_size.h>
#include <ccan/endian/endian.h>
#include <ccan/mem/mem.h>
#include <common/utils.h>
#include <wallet/psbt_fixup.h>
#include <wire/wire.h>

struct keypair {
	u64 keytype;
	u8 *key;
	u8 *value;
};

static size_t compact_size_len(u64 v)
{
	if (v < 0xfd) {
		return 1;
	} else if (v <= 0xffff) {
		return 3;
	} else if (v <= 0xffffffff) {
		return 5;
	} else {
		return 9;
	}
}

static u64 fromwire_compact_size(const u8 **cursor, size_t *max)
{
	u8 v;
	le16 v16;
	le32 v32;
	le64 v64;

	v = fromwire_u8(cursor, max);
	switch (v) {
	case 0xfd:
		fromwire(cursor, max, &v16, sizeof(v16));
		return le16_to_cpu(v16);
	case 0xfe:
		fromwire(cursor, max, &v32, sizeof(v32));
		return le32_to_cpu(v32);
	case 0xff:
		fromwire(cursor, max, &v64, sizeof(v64));
		return le64_to_cpu(v64);
	default:
		return v;
	}
}

static size_t fromwire_compact_len(const u8 **cursor, size_t *max)
{
	u64 len = fromwire_compact_size(cursor, max);
	if (len > *max) {
		fromwire_fail(cursor, max);
		return 0;
	}
	return len;
}

/* BIP-0174:
 * <keypair> := <key> <value>
 * <key> := <keylen> <keytype> <keydata>
 * <value> := <valuelen> <valuedata>
 */
static struct keypair *fromwire_keypair(const tal_t *ctx,
					const u8 **cursor,
					size_t *max)
{
	struct keypair *kp = tal(ctx, struct keypair);
	u64 len;
	size_t keylen;

	/* 0 byte terminates */
	len = fromwire_compact_len(cursor, max);
	if (len == 0)
		return tal_free(kp);

	kp->keytype = fromwire_compact_size(cursor, max);
	/* Sanity check */
	if (compact_size_len(kp->keytype) > len)
		return tal_free(kp);
	keylen = len - compact_size_len(kp->keytype);
	kp->key = tal_arr(kp, u8, keylen);
	fromwire_u8_array(cursor, max, kp->key, keylen);

	len = fromwire_compact_len(cursor, max);
	kp->value = tal_arr(kp, u8, len);
	fromwire_u8_array(cursor, max, kp->value, len);
	return kp;
}

static void towire_compact_size(u8 **pptr, u64 v)
{
	if (v < 0xfd) {
		towire_u8(pptr, v);
	} else if (v <= 0xffff) {
		le16 v16 = cpu_to_le16(v);
		towire_u8(pptr, 0xfd);
		towire(pptr, &v16, sizeof(v16));
	} else if (v <= 0xffffffff) {
		le32 v32 = cpu_to_le32(v);
		towire_u8(pptr, 0xfe);
		towire(pptr, &v32, sizeof(v32));
	} else {
		le64 v64 = cpu_to_le64(v);
		towire_u8(pptr, 0xff);
		towire(pptr, &v64, sizeof(v64));
	}
}

static void towire_keypair(u8 **pptr, const struct keypair *kp)
{
	towire_compact_size(pptr,
			    compact_size_len(kp->keytype) + tal_bytelen(kp->key));
	towire_compact_size(pptr, kp->keytype);
	towire_u8_array(pptr, kp->key, tal_bytelen(kp->key));
	towire_compact_size(pptr, tal_bytelen(kp->value));
	towire_u8_array(pptr, kp->value, tal_bytelen(kp->value));
}

static bool fixup_sig(struct keypair *kp)
{
	const u8 *valcursor = kp->value;
	size_t vallen = tal_bytelen(kp->value);
	struct bitcoin_signature sig;
	size_t derlen;
	u8 der[73];

	fromwire_secp256k1_ecdsa_signature(&valcursor, &vallen, &sig.s);
	sig.sighash_type = SIGHASH_ALL;

	/* If that didn't parse, or there are more bytes
	 * left, ignore it */
	if (valcursor == NULL || vallen != 0)
		return false;

	derlen = signature_to_der(der, &sig);
	kp->value = tal_dup_arr(kp, u8, der, derlen, 0);
	return true;
}

/* I am deeply, deeply unhappy with this code.  I initially tried parsing the
 * entire PSBT, but that turns out not to be possible without decoding the
 * tranaction.  Literally WTF */
const u8 *psbt_fixup(const tal_t *ctx, const u8 *psbtblob)
{
	const u8 *prev_cursor, *cursor = psbtblob;
	size_t max = tal_bytelen(psbtblob);
	u8 *ret;
	struct keypair *kp, *changed_kp;

	/* Skip magic */
	fromwire_pad(&cursor, &max, 5);

	/* Skip global map */
	while ((kp = fromwire_keypair(tmpctx, &cursor, &max)) != NULL);

	/* Now input map */
	changed_kp = NULL;
	prev_cursor = cursor;
	while ((kp = fromwire_keypair(tmpctx, &cursor, &max)) != NULL) {
		/* PSBT_IN_PARTIAL_SIG = 0x02 */
		if (kp->keytype == 2 && fixup_sig(kp)) {
			changed_kp = kp;
			break;
		}
		prev_cursor = cursor;
	}

	if (!changed_kp)
		return NULL;

	ret = tal_dup_arr(ctx, u8, psbtblob, prev_cursor - psbtblob, 0);
	towire_keypair(&ret, changed_kp);
	towire_u8_array(&ret, cursor, max);

	return ret;
}
