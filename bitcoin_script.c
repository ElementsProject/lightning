#include "bitcoin_script.h"
#include "bitcoin_address.h"
#include "pkt.h"
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

/* FIXME: permute? */
/* Is a < b? (If equal we don't care) */
static bool key_less(const BitcoinPubkey *a, const BitcoinPubkey *b)
{
	size_t len;
	int cmp;

	if (a->key.len < b->key.len)
		len = a->key.len;
	else
		len = b->key.len;

	cmp = memcmp(a->key.data, b->key.data, len);
	if (cmp < 0)
		return true;
	else if (cmp > 0)
		return false;

	/* Corner case: if it's shorter, it's less. */
	return a->key.len < b->key.len;
}
	
/* tal_count() gives the length of the script. */
u8 *bitcoin_redeem_2of2(const tal_t *ctx,
			const BitcoinPubkey *key1,
			const BitcoinPubkey *key2)
{
	u8 *script = tal_arr(ctx, u8, 0);
	add_op(&script, OP_LITERAL(2));
	if (key_less(key1, key2)) {
		add_push_bytes(&script, key1->key.data, key1->key.len);
		add_push_bytes(&script, key2->key.data, key2->key.len);
	} else {
		add_push_bytes(&script, key2->key.data, key2->key.len);
		add_push_bytes(&script, key1->key.data, key1->key.len);
	}
	add_op(&script, OP_LITERAL(2));
	add_op(&script, OP_CHECKMULTISIG);
	return script;
}

/* tal_count() gives the length of the script. */
u8 *bitcoin_redeem_single(const tal_t *ctx, const u8 *key, size_t keylen)
{
	u8 *script = tal_arr(ctx, u8, 0);
	add_push_bytes(&script, key, keylen);
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
	add_push_bytes(&script, addr, sizeof(addr));
	add_op(&script, OP_EQUALVERIFY);
	add_op(&script, OP_CHECKSIG);

	return script;
}

u8 *scriptsig_pay_to_pubkeyhash(const tal_t *ctx,
				const struct bitcoin_address *addr,
				const u8 *signature,
				size_t sig_len)
{
	u8 *script = tal_arr(ctx, u8, 0);

	add_push_bytes(&script, signature, sig_len);
	add_push_bytes(&script, addr, sizeof(*addr));

	return script;
}

/* Is this a normal pay to pubkey hash? */
bool is_pay_to_pubkey_hash(const ProtobufCBinaryData *script)
{
	if (script->len != 25)
		return false;
	if (script->data[0] != OP_DUP)
		return false;
	if (script->data[1] != OP_HASH160)
		return false;
	if (script->data[2] != OP_PUSHBYTES(20))
		return false;
	if (script->data[23] != OP_EQUALVERIFY)
		return false;
	if (script->data[24] != OP_CHECKSIG)
		return false;
	return true;
}

/* One of:
 * mysig and theirsig, OR
 * mysig and relative locktime passed, OR
 * theirsig and hash preimage. */
u8 *bitcoin_redeem_revocable(const tal_t *ctx,
			     const BitcoinPubkey *mykey,
			     u32 locktime,
			     const BitcoinPubkey *theirkey,
			     const Sha256Hash *revocation_hash)
{
	u8 *script = tal_arr(ctx, u8, 0);
	struct sha256 rhash;
	u8 rhash_ripemd[RIPEMD160_DIGEST_LENGTH];
	le32 locktime_le = cpu_to_le32(locktime);

	proto_to_sha256(revocation_hash, &rhash);

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
	RIPEMD160(rhash.u.u8, sizeof(rhash.u), rhash_ripemd);
	add_op(&script, OP_HASH160);
	add_push_bytes(&script, rhash_ripemd, sizeof(rhash_ripemd));
	add_op(&script, OP_EQUALVERIFY);
	add_push_bytes(&script, theirkey->key.data, theirkey->key.len);
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
		add_push_bytes(&script, mykey->key.data, mykey->key.len);
		add_push_bytes(&script, theirkey->key.data, theirkey->key.len);
	} else {
		add_push_bytes(&script, theirkey->key.data, theirkey->key.len);
		add_push_bytes(&script, mykey->key.data, mykey->key.len);
	}	
	add_op(&script, OP_LITERAL(2));
	add_op(&script, OP_CHECKMULTISIG);
	add_op(&script, OP_ENDIF);

	/* Not two args?  Must be us using timeout. */
	add_op(&script, OP_ELSE);
	add_push_bytes(&script, &locktime_le, sizeof(locktime_le));
	add_op(&script, OP_CHECKSEQUENCEVERIFY);
	add_push_bytes(&script, mykey->key.data, mykey->key.len);
	add_op(&script, OP_CHECKSIG);
	add_op(&script, OP_ENDIF);

	return script;
}
