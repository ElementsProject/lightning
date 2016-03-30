#include "address.h"
#include "locktime.h"
#include "pubkey.h"
#include "script.h"
#include "signature.h"
#include <assert.h>
#include <ccan/crypto/ripemd160/ripemd160.h>
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/endian/endian.h>
#include <ccan/mem/mem.h>

/* Some standard ops */
#define OP_PUSHBYTES(val) (val)
#define OP_PUSHDATA1	0x4C
#define OP_PUSHDATA2	0x4D
#define OP_PUSHDATA4	0x4E
#define OP_NOP		0x61
#define OP_IF		0x63
#define OP_NOTIF	0x64
#define OP_ELSE		0x67
#define OP_ENDIF	0x68
#define OP_2DROP	0x6d
#define OP_DEPTH	0x74
#define OP_DROP		0x75
#define OP_DUP		0x76
#define OP_SWAP		0x7c
#define OP_EQUAL	0x87
#define OP_EQUALVERIFY	0x88
#define OP_SIZE		0x82
#define OP_1SUB		0x8C
#define OP_ADD		0x93
#define OP_CHECKSIG	0xAC
#define OP_CHECKMULTISIG	0xAE
#define OP_HASH160	0xA9

#if HAS_CSV
#define OP_CHECKSEQUENCEVERIFY	0xB2
#else
/* OP_NOP, otherwise bitcoind complains */
#define OP_CHECKSEQUENCEVERIFY	0x61
#endif

#if HAS_CLTV
#define OP_CHECKLOCKTIMEVERIFY	0xB1
#else
/* OP_NOP, otherwise bitcoind complains */
#define OP_CHECKLOCKTIMEVERIFY	0x61
#endif

static void add(u8 **scriptp, const void *mem, size_t len)
{
	size_t oldlen = tal_count(*scriptp);
	tal_resize(scriptp, oldlen + len);
	memcpy(*scriptp + oldlen, mem, len);
}

static void add_op(u8 **scriptp, u8 op)
{
	add(scriptp, &op, 1);
}

static void add_push_bytes(u8 **scriptp, const void *mem, size_t len)
{
	if (len < 76)
		add_op(scriptp, OP_PUSHBYTES(len));
	else if (len < 256) {
		char c = len;
		add_op(scriptp, OP_PUSHDATA1);
		add(scriptp, &c, 1);
	} else if (len < 65536) {
		le16 v = cpu_to_le16(len);
		add_op(scriptp, OP_PUSHDATA2);
		add(scriptp, &v, 2);
	} else {
		le32 v = cpu_to_le32(len);
		add_op(scriptp, OP_PUSHDATA4);
		add(scriptp, &v, 4);
	}

	add(scriptp, memcheck(mem, len), len);
}

static void add_number(u8 **script, u32 num)
{
	if (num == 0)
		add_op(script, 0);
	else if (num <= 16)
		add_op(script, 0x50 + num);
	else {
		le32 n = cpu_to_le32(num);

		if (num <= 0x000000FF)
			add_push_bytes(script, &n, 1);
		else if (num <= 0x0000FFFF)
			add_push_bytes(script, &n, 2);
		else if (num <= 0x00FFFFFF)
			add_push_bytes(script, &n, 3);
		else
			add_push_bytes(script, &n, 4);
	}
}

static void add_push_key(u8 **scriptp, const struct pubkey *key)
{
	add_push_bytes(scriptp, key->der, sizeof(key->der));
}

static void add_push_sig(u8 **scriptp, const struct bitcoin_signature *sig)
{
/* Bitcoin wants DER encoding. */
#if SCRIPTS_USE_DER
	u8 der[73];
	secp256k1_context *secpctx = secp256k1_context_create(0);
	size_t len = signature_to_der(secpctx, der, &sig->sig);

	/* Append sighash type */
	der[len++] = sig->stype;
	add_push_bytes(scriptp, der, len);
	secp256k1_context_destroy(secpctx);
#else /* Alpha uses raw encoding */
	u8 with_sighash[sizeof(sig->sig) + 1];
	memcpy(with_sighash, &sig->sig, sizeof(sig->sig));
	with_sighash[sizeof(sig->sig)] = sig->stype;
	add_push_bytes(scriptp, with_sighash, sizeof(with_sighash));
#endif
}

/* FIXME: permute? */
/* Is a < b? (If equal we don't care) */
static bool key_less(const struct pubkey *a, const struct pubkey *b)
{
	return memcmp(a->der, b->der, sizeof(a->der)) < 0;
}
	
/* tal_count() gives the length of the script. */
u8 *bitcoin_redeem_2of2(const tal_t *ctx,
			const struct pubkey *key1,
			const struct pubkey *key2)
{
	u8 *script = tal_arr(ctx, u8, 0);
	add_number(&script, 2);
	if (key_less(key1, key2)) {
		add_push_key(&script, key1);
		add_push_key(&script, key2);
	} else {
		add_push_key(&script, key2);
		add_push_key(&script, key1);
	}
	add_number(&script, 2);
	add_op(&script, OP_CHECKMULTISIG);
	return script;
}

/* tal_count() gives the length of the script. */
u8 *bitcoin_redeem_single(const tal_t *ctx, const struct pubkey *key)
{
	u8 *script = tal_arr(ctx, u8, 0);
	add_push_key(&script, key);
	add_op(&script, OP_CHECKSIG);
	return script;
}

/* Create p2sh for this redeem script. */
u8 *scriptpubkey_p2sh(const tal_t *ctx, const u8 *redeemscript)
{
	struct sha256 h;
	struct ripemd160 redeemhash;
	u8 *script = tal_arr(ctx, u8, 0);

	add_op(&script, OP_HASH160);
	sha256(&h, redeemscript, tal_count(redeemscript));
	ripemd160(&redeemhash, h.u.u8, sizeof(h));
	add_push_bytes(&script, redeemhash.u.u8, sizeof(redeemhash.u.u8));
	add_op(&script, OP_EQUAL);
	return script;
}

/* Create a script for our HTLC output: sending. */
u8 *scriptpubkey_htlc_send(const tal_t *ctx,
			   const struct pubkey *ourkey,
			   const struct pubkey *theirkey,
			   const struct abs_locktime *htlc_abstimeout,
			   const struct rel_locktime *locktime,
			   const struct sha256 *commit_revoke,
			   const struct sha256 *rhash)
{
	/* R value presented: -> them.
	 * Commit revocation value presented: -> them.
	 * HTLC times out -> us. */
	u8 *script = tal_arr(ctx, u8, 0);
	struct ripemd160 ripemd;

	add_op(&script, OP_HASH160);
	add_op(&script, OP_DUP);
	/* Did they supply HTLC R value? */
	ripemd160(&ripemd, rhash->u.u8, sizeof(rhash->u));
	add_push_bytes(&script, &ripemd, sizeof(ripemd));
	add_op(&script, OP_EQUAL);
	add_op(&script, OP_SWAP);
	/* How about commit revocation value? */
	ripemd160(&ripemd, commit_revoke->u.u8, sizeof(commit_revoke->u));
	add_push_bytes(&script, &ripemd, sizeof(ripemd));
	add_op(&script, OP_EQUAL);
	add_op(&script, OP_ADD);

	/* If either matched... */
	add_op(&script, OP_IF);
	add_push_key(&script, theirkey);

	add_op(&script, OP_ELSE);

	/* If HTLC times out, they can collect after a delay. */
	add_number(&script, htlc_abstimeout->locktime);
	add_op(&script, OP_CHECKLOCKTIMEVERIFY);
	add_number(&script, locktime->locktime);
	add_op(&script, OP_CHECKSEQUENCEVERIFY);
	add_op(&script, OP_2DROP);
	add_push_key(&script, ourkey);

	add_op(&script, OP_ENDIF);
	add_op(&script, OP_CHECKSIG);

	return script;
}

/* Create a script for our HTLC output: receiving. */
u8 *scriptpubkey_htlc_recv(const tal_t *ctx,
			   const struct pubkey *ourkey,
			   const struct pubkey *theirkey,
			   const struct abs_locktime *htlc_abstimeout,
			   const struct rel_locktime *locktime,
			   const struct sha256 *commit_revoke,
			   const struct sha256 *rhash)
{
	/* R value presented: -> us.
	 * Commit revocation value presented: -> them.
	 * HTLC times out -> them. */
	u8 *script = tal_arr(ctx, u8, 0);
	struct ripemd160 ripemd;

	add_op(&script, OP_HASH160);
	add_op(&script, OP_DUP);

	/* Did we supply HTLC R value? */
	ripemd160(&ripemd, rhash->u.u8, sizeof(rhash->u));
	add_push_bytes(&script, &ripemd, sizeof(ripemd));
	add_op(&script, OP_EQUAL);
	add_op(&script, OP_IF);

	add_number(&script, locktime->locktime);
	add_op(&script, OP_CHECKSEQUENCEVERIFY);
	/* Drop extra hash as well as locktime. */
	add_op(&script, OP_2DROP);

	add_push_key(&script, ourkey);

	add_op(&script, OP_ELSE);

	/* If they provided commit revocation, available immediately. */
	ripemd160(&ripemd, commit_revoke->u.u8, sizeof(commit_revoke->u));
	add_push_bytes(&script, &ripemd, sizeof(ripemd));
	add_op(&script, OP_EQUAL);

	add_op(&script, OP_NOTIF);

	/* Otherwise, they must wait for HTLC timeout. */
	add_number(&script, htlc_abstimeout->locktime);
	add_op(&script, OP_CHECKLOCKTIMEVERIFY);
	add_op(&script, OP_DROP);
	add_op(&script, OP_ENDIF);

	add_push_key(&script, theirkey);
	
	add_op(&script, OP_ENDIF);
	add_op(&script, OP_CHECKSIG);

	return script;
}

u8 *scriptsig_pay_to_pubkeyhash(const tal_t *ctx,
				const struct pubkey *key,
				const struct bitcoin_signature *sig)
{
	u8 *script = tal_arr(ctx, u8, 0);

	add_push_sig(&script, sig);
	add_push_key(&script, key);

	return script;
}

/* Assumes redeemscript contains CHECKSIG, not CHECKMULTISIG */
u8 *scriptsig_p2sh_single_sig(const tal_t *ctx,
			      const u8 *redeem_script,
			      size_t redeem_len,
			      const struct bitcoin_signature *sig)
{
	u8 *script = tal_arr(ctx, u8, 0);

	add_push_sig(&script, sig);
	add_push_bytes(&script, redeem_script, redeem_len);
	return script;
}
	
u8 *scriptsig_p2sh_2of2(const tal_t *ctx,
			const struct bitcoin_signature *sig1,
			const struct bitcoin_signature *sig2,
			const struct pubkey *key1,
			const struct pubkey *key2)
{
	u8 *script = tal_arr(ctx, u8, 0);
	u8 *redeemscript;

	/* OP_CHECKMULTISIG has an out-by-one bug, which MBZ */
	add_number(&script, 0);
	/* sig order should match key order. */
	if (key_less(key1, key2)) {
		add_push_sig(&script, sig1);
		add_push_sig(&script, sig2);
	} else {
		add_push_sig(&script, sig2);
		add_push_sig(&script, sig1);
	}
	redeemscript = bitcoin_redeem_2of2(script, key1, key2);
	add_push_bytes(&script, redeemscript, tal_count(redeemscript));
	return script;
}

/* Is this a normal pay to pubkey hash? */
bool is_pay_to_pubkey_hash(const u8 *script, size_t script_len)
{
	if (script_len != 25)
		return false;
	if (script[0] != OP_DUP)
		return false;
	if (script[1] != OP_HASH160)
		return false;
	if (script[2] != OP_PUSHBYTES(20))
		return false;
	if (script[23] != OP_EQUALVERIFY)
		return false;
	if (script[24] != OP_CHECKSIG)
		return false;
	return true;
}

bool is_p2sh(const u8 *script, size_t script_len)
{
	if (script_len != 23)
		return false;
	if (script[0] != OP_HASH160)
		return false;
	if (script[1] != OP_PUSHBYTES(20))
		return false;
	if (script[22] != OP_EQUAL)
		return false;
	return true;
}

/* A common script pattern: A can have it with secret, or B can have
 * it after delay. */
u8 *bitcoin_redeem_secret_or_delay(const tal_t *ctx,
				   const struct pubkey *delayed_key,
				   const struct rel_locktime *locktime,
				   const struct pubkey *key_if_secret_known,
				   const struct sha256 *hash_of_secret)
{
	struct ripemd160 ripemd;
	u8 *script = tal_arr(ctx, u8, 0);

	ripemd160(&ripemd, hash_of_secret->u.u8, sizeof(hash_of_secret->u));

	/* If the secret is supplied.... */
	add_op(&script, OP_HASH160);
	add_push_bytes(&script, ripemd.u.u8, sizeof(ripemd.u.u8));
	add_op(&script, OP_EQUAL);
	add_op(&script, OP_IF);
	
	/* They can collect the funds. */
	add_push_key(&script, key_if_secret_known);

	add_op(&script, OP_ELSE);

	/* Other can collect after a delay. */
	add_number(&script, locktime->locktime);
	add_op(&script, OP_CHECKSEQUENCEVERIFY);
	add_op(&script, OP_DROP);
	add_push_key(&script, delayed_key);

	add_op(&script, OP_ENDIF);
	add_op(&script, OP_CHECKSIG);

	return script;
}

u8 *scriptsig_p2sh_secret(const tal_t *ctx,
			  const void *secret, size_t secret_len,
			  const struct bitcoin_signature *sig,
			  const u8 *redeemscript,
			  size_t redeem_len)
{
	u8 *script = tal_arr(ctx, u8, 0);

	add_push_sig(&script, sig);
	add_push_bytes(&script, secret, secret_len);
	add_push_bytes(&script, redeemscript, redeem_len);

	return script;
}
