#ifndef LIGHTNING_BITCOIN_SCRIPT_H
#define LIGHTNING_BITCOIN_SCRIPT_H
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include "signature.h"

struct bitcoin_address;
struct pubkey;
struct sha256;

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

/* One of:
 * mysig and theirsig, OR
 * mysig and relative locktime passed, OR
 * theirsig and hash preimage. */
u8 *bitcoin_redeem_revocable(const tal_t *ctx,
			     const struct pubkey *mykey,
			     u32 locktime,
			     const struct pubkey *theirkey,
			     const struct sha256 *revocation_hash);

/* Create an output script using p2sh for this redeem script. */
u8 *scriptpubkey_p2sh(const tal_t *ctx, const u8 *redeemscript);

/* Create an input script to accept pay to pubkey */
u8 *scriptsig_pay_to_pubkeyhash(const tal_t *ctx,
				const struct pubkey *key,
				const struct bitcoin_signature *sig);

/* Create an input script to accept pay to pubkey */
u8 *scriptsig_p2sh_2of2(const tal_t *ctx,
			const struct bitcoin_signature *sig1,
			const struct bitcoin_signature *sig2,
			const struct pubkey *key1,
			const struct pubkey *key2);

/* Create an input script to solve by revokehash */
u8 *scriptsig_p2sh_revoke(const tal_t *ctx,
			  const struct sha256 *preimage,
			  const struct bitcoin_signature *sig,
			  const u8 *revocable_redeem,
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
