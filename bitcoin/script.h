#ifndef LIGHTNING_BITCOIN_SCRIPT_H
#define LIGHTNING_BITCOIN_SCRIPT_H
#include "config.h"
#include "signature.h"
#include "tx.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

struct bitcoin_address;
struct bitcoin_tx_input;
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
			secp256k1_context *secpctx,
			const struct pubkey *key1,
			const struct pubkey *key2);

/* tal_count() gives the length of the script. */
u8 *bitcoin_redeem_single(const tal_t *ctx,
			  secp256k1_context *secpctx,
			  const struct pubkey *key);

/* A common script pattern: A can have it with secret, or B can have
 * it after delay. */
u8 *bitcoin_redeem_secret_or_delay(const tal_t *ctx,
				   secp256k1_context *secpctx,
				   const struct pubkey *delayed_key,
				   const struct rel_locktime *locktime,
				   const struct pubkey *key_if_secret_known,
				   const struct sha256 *hash_of_secret);

/* Create an output script using p2sh for this redeem script. */
u8 *scriptpubkey_p2sh(const tal_t *ctx, const u8 *redeemscript);

/* Create the redeemscript for a P2SH + P2WPKH. */
u8 *bitcoin_redeem_p2wpkh(const tal_t *ctx,
			  secp256k1_context *secpctx,
			  const struct pubkey *key);

/* Create a witness which spends the 2of2. */
void bitcoin_witness_p2sh_p2wpkh(const tal_t *ctx,
				 secp256k1_context *secpctx,
				 struct bitcoin_tx_input *input,
				 const struct bitcoin_signature *sig,
				 const struct pubkey *key);

/* Create scriptcode (fake witness, basically) for P2WPKH */
u8 *p2wpkh_scriptcode(const tal_t *ctx,
		      secp256k1_context *secpctx,
		      const struct pubkey *key);

/* Create a script for our HTLC output: sending. */
u8 *bitcoin_redeem_htlc_send(const tal_t *ctx,
			     secp256k1_context *secpctx,
			     const struct pubkey *ourkey,
			     const struct pubkey *theirkey,
			     const struct abs_locktime *htlc_abstimeout,
			     const struct rel_locktime *locktime,
			     const struct sha256 *commit_revoke,
			     const struct sha256 *rhash);

/* Create a script for our HTLC output: receiving. */
u8 *bitcoin_redeem_htlc_recv(const tal_t *ctx,
			     secp256k1_context *secpctx,
			     const struct pubkey *ourkey,
			     const struct pubkey *theirkey,
			     const struct abs_locktime *htlc_abstimeout,
			     const struct rel_locktime *locktime,
			     const struct sha256 *commit_revoke,
			     const struct sha256 *rhash);

/* Create an output script for a 32-byte witness program. */
u8 *scriptpubkey_p2wsh(const tal_t *ctx, const u8 *witnessscript);

/* Create an output script for a 20-byte witness program. */
u8 *scriptpubkey_p2wpkh(const tal_t *ctx,
			secp256k1_context *secpctx,
			const struct pubkey *key);

/* Create a witness which spends the 2of2. */
u8 **bitcoin_witness_2of2(const tal_t *ctx,
			  secp256k1_context *secpctx,
			  const struct bitcoin_signature *sig1,
			  const struct bitcoin_signature *sig2,
			  const struct pubkey *key1,
			  const struct pubkey *key2);

/* Create a witness which spends a "secret_or_delay" scriptpubkey */
u8 **bitcoin_witness_secret(const tal_t *ctx,
			    secp256k1_context *secpctx,
			    const void *secret, size_t secret_len,
			    const struct bitcoin_signature *sig,
			    const u8 *witnessscript);

/* Create a witness which spends bitcoin_redeeem_htlc_recv/send */
u8 **bitcoin_witness_htlc(const tal_t *ctx,
			  secp256k1_context *secpctx,
			  const void *htlc_or_revocation_preimage,
			  const struct bitcoin_signature *sig,
			  const u8 *witnessscript);

/* Is this a pay to script hash? */
bool is_p2sh(const u8 *script, size_t script_len);

/* Are these two scripts equal? */
bool scripteq(const u8 *s1, size_t s1len, const u8 *s2, size_t s2len);

#endif /* LIGHTNING_BITCOIN_SCRIPT_H */
