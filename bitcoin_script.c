#include "bitcoin_script.h"
#include "bitcoin_address.h"
#include "pkt.h"
#include "signature.h"
#include "pubkey.h"
#include <openssl/ripemd.h>
#include <ccan/endian/endian.h>
#include <ccan/crypto/sha256/sha256.h>

/* Some standard ops */
#define OP_PUSHBYTES(val) (val)
#define OP_LITERAL(val) (0x51 + (val))
#define OP_PUSHDATA1	0x4C
#define OP_PUSHDATA2	0x4D
#define OP_PUSHDATA4	0x4E
#define OP_NOP		0x61
#define OP_IF		0x63
#define OP_ELSE		0x67
#define OP_ENDIF	0x68
#define OP_DEPTH	0x74
#define OP_DUP		0x76
#define OP_EQUAL	0x87
#define OP_EQUALVERIFY	0x88
#define OP_SIZE		0x82
#define OP_1SUB		0x8C
#define OP_CHECKSIG	0xAC
#define OP_CHECKMULTISIG	0xAE
#define OP_HASH160	0xA9
#define OP_CHECKSEQUENCEVERIFY	0xB2

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

	add(scriptp, mem, len);
}

static void add_push_key(u8 **scriptp, const struct pubkey *key)
{
	add_push_bytes(scriptp, key->key, pubkey_len(key));
}

/* Bitcoin wants DER encoding. */
static void add_push_sig(u8 **scriptp, const struct signature *sig)
{
	u8 der[2 + 2 + sizeof(sig->r) + 2 + sizeof(sig->s)];

	der[0] = 0x30; /* Type */
	der[1] = sizeof(der) - 2; /* Total length */

	der[2] = 0x2; /* r value type. */
	der[3] = sizeof(sig->r); /* r length */
	memcpy(der+4, sig->r, sizeof(sig->r));

	der[4 + sizeof(sig->r)] = 0x2; /* s value type. */
	der[4 + sizeof(sig->r) + 1] = sizeof(sig->s); /* s value length. */
	memcpy(der+4+sizeof(sig->r)+2, sig->s, sizeof(sig->s));

	add_push_bytes(scriptp, der, sizeof(der));
}

/* FIXME: permute? */
/* Is a < b? (If equal we don't care) */
static bool key_less(const struct pubkey *a, const struct pubkey *b)
{
	/* Shorter one wins. */
	if (pubkey_len(a) != pubkey_len(b))
		return pubkey_len(a) < pubkey_len(b);

	return memcmp(a->key, b->key, pubkey_len(a)) < 0;
}
	
/* tal_count() gives the length of the script. */
u8 *bitcoin_redeem_2of2(const tal_t *ctx,
			const struct pubkey *key1,
			const struct pubkey *key2)
{
	u8 *script = tal_arr(ctx, u8, 0);
	add_op(&script, OP_LITERAL(2));
	if (key_less(key1, key2)) {
		add_push_key(&script, key1);
		add_push_key(&script, key2);
	} else {
		add_push_key(&script, key2);
		add_push_key(&script, key1);
	}
	add_op(&script, OP_LITERAL(2));
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
	u8 redeemhash[RIPEMD160_DIGEST_LENGTH];
	u8 *script = tal_arr(ctx, u8, 0);

	add_op(&script, OP_HASH160);
	sha256(&h, redeemscript, tal_count(redeemscript));
	RIPEMD160(h.u.u8, sizeof(h), redeemhash);
	add_push_bytes(&script, redeemhash, sizeof(redeemhash));
	add_op(&script, OP_EQUAL);
	return script;
}

u8 *scriptpubkey_pay_to_pubkeyhash(const tal_t *ctx,
				   const struct bitcoin_address *addr)
{
	u8 *script = tal_arr(ctx, u8, 0);

	add_op(&script, OP_DUP);
	add_op(&script, OP_HASH160);
	add_push_bytes(&script, addr, sizeof(*addr));
	add_op(&script, OP_EQUALVERIFY);
	add_op(&script, OP_CHECKSIG);

	return script;
}

u8 *scriptsig_pay_to_pubkeyhash(const tal_t *ctx,
				const struct pubkey *key,
				const struct signature *sig)
{
	u8 *script = tal_arr(ctx, u8, 0);

	add_push_sig(&script, sig);
	add_push_key(&script, key);

	return script;
}

u8 *scriptsig_p2sh_2of2(const tal_t *ctx,
			const struct signature *sig1,
			const struct signature *sig2,
			const struct pubkey *key1,
			const struct pubkey *key2)
{
	u8 *script = tal_arr(ctx, u8, 0);
	u8 *redeemscript;

	add_push_sig(&script, sig1);
	add_push_sig(&script, sig2);

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
		
/* One of:
 * mysig and theirsig, OR
 * mysig and relative locktime passed, OR
 * theirsig and hash preimage. */
u8 *bitcoin_redeem_revocable(const tal_t *ctx,
			     const struct pubkey *mykey,
			     u32 locktime,
			     const struct pubkey *theirkey,
			     const struct sha256 *rhash)
{
	u8 *script = tal_arr(ctx, u8, 0);
	u8 rhash_ripemd[RIPEMD160_DIGEST_LENGTH];
	le32 locktime_le = cpu_to_le32(locktime);

	/* If there are two args: */
	add_op(&script, OP_DEPTH);
	add_op(&script, OP_1SUB);
	add_op(&script, OP_IF);

	/* If the top arg is a hashpreimage. */
	add_op(&script, OP_SIZE);
	add_op(&script, OP_LITERAL(32));
	add_op(&script, OP_EQUAL);
	add_op(&script, OP_IF);

	/* Must hash to revocation_hash, and be signed by them. */
	RIPEMD160(rhash->u.u8, sizeof(rhash->u), rhash_ripemd);
	add_op(&script, OP_HASH160);
	add_push_bytes(&script, rhash_ripemd, sizeof(rhash_ripemd));
	add_op(&script, OP_EQUALVERIFY);
	add_push_key(&script, theirkey);
	add_op(&script, OP_CHECKSIG);

	/* Otherwise, it should be both our sigs. */

	/* FIXME: Perhaps this is a bad idea?  We don't need it to
	 * close, and without this we force the blockchain to commit
	 * to the timeout: that may make a flood of transactions due
	 * to hub collapse less likely (as some optimists hope hub
	 * will return). */
	add_op(&script, OP_ELSE);

	add_op(&script, OP_LITERAL(2));
	/* This obscures whose key is whose.  Probably unnecessary? */
	if (key_less(mykey, theirkey)) {
		add_push_key(&script, mykey);
		add_push_key(&script, theirkey);
	} else {
		add_push_key(&script, theirkey);
		add_push_key(&script, mykey);
	}	
	add_op(&script, OP_LITERAL(2));
	add_op(&script, OP_CHECKMULTISIG);
	add_op(&script, OP_ENDIF);

	/* Not two args?  Must be us using timeout. */
	add_op(&script, OP_ELSE);
	add_push_bytes(&script, &locktime_le, sizeof(locktime_le));
	add_op(&script, OP_CHECKSEQUENCEVERIFY);
	add_push_key(&script, mykey);
	add_op(&script, OP_CHECKSIG);
	add_op(&script, OP_ENDIF);

	return script;
}
