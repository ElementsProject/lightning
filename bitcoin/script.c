#include "locktime.h"
#include "pubkey.h"
#include "script.h"
#include <assert.h>
#include <ccan/crypto/ripemd160/ripemd160.h>
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/endian/endian.h>
#include <ccan/mem/mem.h>

/* Some standard ops */
#define OP_0		0x00
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
#define OP_CHECKSEQUENCEVERIFY	0xB2
#define OP_CHECKLOCKTIMEVERIFY	0xB1

/* Bitcoin's OP_HASH160 is RIPEMD(SHA256()) */
static void hash160(struct ripemd160 *redeemhash, const void *mem, size_t len)
{
	struct sha256 h;

	sha256(&h, mem, len);
	ripemd160(redeemhash, h.u.u8, sizeof(h));
}

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
	u8 der[PUBKEY_DER_LEN];
	pubkey_to_der(der, key);

	add_push_bytes(scriptp, der, sizeof(der));
}

static u8 *stack_key(const tal_t *ctx, const struct pubkey *key)
{
	u8 der[PUBKEY_DER_LEN];
	pubkey_to_der(der, key);

	return tal_dup_arr(ctx, u8, der, sizeof(der), 0);
}

/* Bitcoin wants DER encoding. */
static u8 *stack_sig(const tal_t *ctx, const struct bitcoin_signature *sig)
{
	u8 der[73];
	size_t len = signature_to_der(der, &sig->sig);

	/* Append sighash type */
	der[len++] = sig->stype;
	return tal_dup_arr(ctx, u8, der, len, 0);
}

/* Bitcoin script stack values are a special, special snowflake.
 *
 * They're little endian values, but 0 is an empty value.  We only
 * handle single byte values here. */
static u8 *stack_number(const tal_t *ctx, unsigned int num)
{
	u8 val;

	if (num == 0)
		return tal_arr(ctx, u8, 0);

	val = num;
	assert(val == num);

	/* We use tal_dup_arr since we want tal_count() to work */
	return tal_dup_arr(ctx, u8, &val, 1, 0);
}

/* Is a < b? (If equal we don't care) */
static bool key_less(const struct pubkey *a, const struct pubkey *b)
{
	u8 a_der[PUBKEY_DER_LEN], b_der[PUBKEY_DER_LEN];
	pubkey_to_der(a_der, a);
	pubkey_to_der(b_der, b);

	return memcmp(a_der, b_der, sizeof(a_der)) < 0;
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
	struct ripemd160 redeemhash;
	u8 *script = tal_arr(ctx, u8, 0);

	add_op(&script, OP_HASH160);
	hash160(&redeemhash, redeemscript, tal_count(redeemscript));
	add_push_bytes(&script, redeemhash.u.u8, sizeof(redeemhash.u.u8));
	add_op(&script, OP_EQUAL);
	return script;
}

/* Create the redeemscript for a P2SH + P2WPKH (for signing tx) */
u8 *bitcoin_redeem_p2wpkh(const tal_t *ctx, const struct pubkey *key)
{
	struct ripemd160 keyhash;
	u8 der[PUBKEY_DER_LEN];
	u8 *script = tal_arr(ctx, u8, 0);

	/* BIP141: BIP16 redeemScript pushed in the scriptSig is exactly a
	 * push of a version byte plus a push of a witness program. */
	add_number(&script, 0);
	pubkey_to_der(der, key);
	hash160(&keyhash, der, sizeof(der));
	add_push_bytes(&script, &keyhash, sizeof(keyhash));
	return script;
}

/* Create an input which spends the p2sh-p2wpkh. */
void bitcoin_witness_p2sh_p2wpkh(const tal_t *ctx,
				 struct bitcoin_tx_input *input,
				 const struct bitcoin_signature *sig,
				 const struct pubkey *key)
{
	u8 *redeemscript = bitcoin_redeem_p2wpkh(ctx, key);

	/* BIP141: The scriptSig must be exactly a push of the BIP16 redeemScript
	 * or validation fails. */
	input->script = tal_arr(ctx, u8, 0);
	add_push_bytes(&input->script, redeemscript, tal_count(redeemscript));
	input->script_length = tal_count(input->script);
	tal_free(redeemscript);

	/* BIP141: The witness must consist of exactly 2 items (≤ 520
	 * bytes each). The first one a signature, and the second one
	 * a public key. */
	input->witness = tal_arr(ctx, u8 *, 2);
	input->witness[0] = stack_sig(input->witness, sig);
	input->witness[1] = stack_key(input->witness, key);
}

/* Create an output script for a 32-byte witness. */
u8 *scriptpubkey_p2wsh(const tal_t *ctx, const u8 *witnessscript)
{
	struct sha256 h;
	u8 *script = tal_arr(ctx, u8, 0);

	add_op(&script, OP_0);
	sha256(&h, witnessscript, tal_count(witnessscript));
	add_push_bytes(&script, h.u.u8, sizeof(h.u.u8));
	return script;
}

/* Create an output script for a 20-byte witness. */
u8 *scriptpubkey_p2wpkh(const tal_t *ctx, const struct pubkey *key)
{
	struct ripemd160 h;
	u8 der[PUBKEY_DER_LEN];
	u8 *script = tal_arr(ctx, u8, 0);

	add_op(&script, OP_0);
	pubkey_to_der(der, key);
	hash160(&h, der, sizeof(der));
	add_push_bytes(&script, &h, sizeof(h));
	return script;
}

/* Create a witness which spends the 2of2. */
u8 **bitcoin_witness_2of2(const tal_t *ctx,
			  const struct bitcoin_signature *sig1,
			  const struct bitcoin_signature *sig2,
			  const struct pubkey *key1,
			  const struct pubkey *key2)
{
	u8 **witness = tal_arr(ctx, u8 *, 4);

	/* OP_CHECKMULTISIG has an out-by-one bug, which MBZ */
	witness[0] = stack_number(witness, 0);

	/* sig order should match key order. */
	if (key_less(key1, key2)) {
		witness[1] = stack_sig(witness, sig1);
		witness[2] = stack_sig(witness, sig2);
	} else {
		witness[1] = stack_sig(witness, sig2);
		witness[2] = stack_sig(witness, sig1);
	}

	witness[3] = bitcoin_redeem_2of2(witness, key1, key2);
	return witness;
}

/* Create a script for our HTLC output: sending. */
u8 *bitcoin_redeem_htlc_send(const tal_t *ctx,
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

	/* Must be 32 bytes long. */
	add_op(&script, OP_SIZE);
	add_number(&script, 32);
	add_op(&script, OP_EQUALVERIFY);

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
u8 *bitcoin_redeem_htlc_recv(const tal_t *ctx,
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

	add_op(&script, OP_SIZE);
	add_number(&script, 32);
	add_op(&script, OP_EQUALVERIFY);

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

/* Create scriptcode (fake witness, basically) for P2WPKH */
u8 *p2wpkh_scriptcode(const tal_t *ctx, const struct pubkey *key)
{
	struct sha256 h;
	struct ripemd160 pkhash;
	u8 der[PUBKEY_DER_LEN];
	u8 *script = tal_arr(ctx, u8, 0);

	pubkey_to_der(der, key);
	sha256(&h, der, sizeof(der));
	ripemd160(&pkhash, h.u.u8, sizeof(h));
	/* BIP143:
	 *
	 * For P2WPKH witness program, the scriptCode is
	 * 0x1976a914{20-byte-pubkey-hash}88ac.
	 */

	/* PUSH(25): OP_DUP OP_HASH160 PUSH(20) 20-byte-pubkey-hash
	 * OP_EQUALVERIFY OP_CHECKSIG */
	add_op(&script, OP_DUP);
	add_op(&script, OP_HASH160);
	add_push_bytes(&script, &pkhash, sizeof(pkhash));
	add_op(&script, OP_EQUALVERIFY);
	add_op(&script, OP_CHECKSIG);

	return script;
}

bool is_p2pkh(const u8 *script, size_t script_len)
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

bool is_p2wsh(const u8 *script, size_t script_len)
{
	if (script_len != 1 + 1 + sizeof(struct sha256))
		return false;
	if (script[0] != OP_0)
		return false;
	if (script[1] != OP_PUSHBYTES(sizeof(struct sha256)))
		return false;
	return true;
}

bool is_p2wpkh(const u8 *script, size_t script_len)
{
	if (script_len != 1 + 1 + sizeof(struct ripemd160))
		return false;
	if (script[0] != OP_0)
		return false;
	if (script[1] != OP_PUSHBYTES(sizeof(struct ripemd160)))
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

u8 **bitcoin_witness_secret(const tal_t *ctx,
			    const void *secret, size_t secret_len,
			    const struct bitcoin_signature *sig,
			    const u8 *witnessscript)
{
	u8 **witness = tal_arr(ctx, u8 *, 3);

	witness[0] = stack_sig(witness, sig);
	witness[1] = tal_dup_arr(witness, u8, secret, secret_len, 0);
	witness[2] = tal_dup_arr(witness, u8,
				 witnessscript, tal_count(witnessscript), 0);

	return witness;
}

u8 **bitcoin_witness_htlc(const tal_t *ctx,
			  const void *htlc_or_revocation_preimage,
			  const struct bitcoin_signature *sig,
			  const u8 *witnessscript)
{
	static const struct sha256 no_preimage;

	/* Use 32 zeroes if no preimage. */
	if (!htlc_or_revocation_preimage)
		htlc_or_revocation_preimage = &no_preimage;

	return bitcoin_witness_secret(ctx,
				      htlc_or_revocation_preimage,
				      32, sig, witnessscript);
}

bool scripteq(const u8 *s1, size_t s1len, const u8 *s2, size_t s2len)
{
	memcheck(s1, s1len);
	memcheck(s2, s2len);

	if (s1len != s2len)
		return false;
	return memcmp(s1, s2, s1len) == 0;
}
