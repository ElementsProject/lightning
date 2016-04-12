#ifndef LIGHTNING_BITCOIN_SCRIPT_H
#define LIGHTNING_BITCOIN_SCRIPT_H
#include "config.h"
#include "signature.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

struct bitcoin_address;
struct pubkey;
struct sha256;
struct rel_locktime;
struct abs_locktime;

/* A bitcoin signature includes one byte for the type. */
struct bitcoin_signature {
	struct signature sig;
	enum sighash_type stype;
};

/* tal_count() gives the length of the script. */
u8 *bitcoin_redeem_2of2(const tal_t *ctx,
			const struct pubkey *key1,
			const struct pubkey *key2);

/* tal_count() gives the length of the script. */
u8 *bitcoin_redeem_single(const tal_t *ctx, const struct pubkey *key);

/* A common script pattern: A can have it with secret, or B can have
 * it after delay. */
u8 *bitcoin_redeem_secret_or_delay(const tal_t *ctx,
				   const struct pubkey *delayed_key,
				   const struct rel_locktime *locktime,
				   const struct pubkey *key_if_secret_known,
				   const struct sha256 *hash_of_secret);

/* Create an output script using p2sh for this redeem script. */
u8 *scriptpubkey_p2sh(const tal_t *ctx, const u8 *redeemscript);

/* Create an input script to accept pay to pubkey */
u8 *scriptsig_pay_to_pubkeyhash(const tal_t *ctx,
				const struct pubkey *key,
				const struct bitcoin_signature *sig);

/* Create scriptcode (fake witness, basically) for P2WPKH */
u8 *p2wpkh_scriptcode(const tal_t *ctx, const struct pubkey *key);

u8 *scriptpubkey_htlc_send(const tal_t *ctx,
			   const struct pubkey *ourkey,
			   const struct pubkey *theirkey,
			   const struct abs_locktime *htlc_abstimeout,
			   const struct rel_locktime *locktime,
			   const struct sha256 *commit_revoke,
			   const struct sha256 *rhash);

/* Create a script for our HTLC output: receiving. */
u8 *scriptpubkey_htlc_recv(const tal_t *ctx,
			   const struct pubkey *ourkey,
			   const struct pubkey *theirkey,
			   const struct abs_locktime *htlc_abstimeout,
			   const struct rel_locktime *locktime,
			   const struct sha256 *commit_revoke,
			   const struct sha256 *rhash);

/* Create an input script to accept pay to pubkey */
u8 *scriptsig_p2sh_2of2(const tal_t *ctx,
			const struct bitcoin_signature *sig1,
			const struct bitcoin_signature *sig2,
			const struct pubkey *key1,
			const struct pubkey *key2);

/* Create an input script to solve by secret */
u8 *scriptsig_p2sh_secret(const tal_t *ctx,
			  const void *secret, size_t secret_len,
			  const struct bitcoin_signature *sig,
			  const u8 *redeemscript,
			  size_t redeem_len);

/* Create an input script which pushes sigs then redeem script. */
u8 *scriptsig_p2sh_single_sig(const tal_t *ctx,
			      const u8 *redeem_script,
			      size_t redeem_len,
			      const struct bitcoin_signature *sig);

/* Is this a normal pay to pubkey hash? */
bool is_pay_to_pubkey_hash(const u8 *script, size_t script_len);

/* Is this a pay to script hash? */
bool is_p2sh(const u8 *script, size_t script_len);

#endif /* LIGHTNING_BITCOIN_SCRIPT_H */
