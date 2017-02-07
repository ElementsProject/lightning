#ifndef LIGHTNING_BITCOIN_SCRIPT_H
#define LIGHTNING_BITCOIN_SCRIPT_H
#include "config.h"
#include "signature.h"
#include "tx.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

struct bitcoin_address;
struct bitcoin_tx_input;
struct preimage;
struct pubkey;
struct sha256;
struct rel_locktime;
struct abs_locktime;

/* tal_count() gives the length of the script. */
u8 *bitcoin_redeem_2of2(const tal_t *ctx,
			const struct pubkey *key1,
			const struct pubkey *key2);

/* tal_count() gives the length of the script. */
u8 *bitcoin_redeem_single(const tal_t *ctx,
			  const struct pubkey *key);

/* A common script pattern: A can have it with secret, or B can have
 * it after delay. */
u8 *bitcoin_redeem_secret_or_delay(const tal_t *ctx,
				   const struct pubkey *delayed_key,
				   const struct rel_locktime *locktime,
				   const struct pubkey *key_if_secret_known,
				   const struct sha256 *hash_of_secret);

/* Create an output script using p2sh for this redeem script. */
u8 *scriptpubkey_p2sh(const tal_t *ctx, const u8 *redeemscript);

/* Create an output script using p2pkh */
u8 *scriptpubkey_p2pkh(const tal_t *ctx, const struct pubkey *pubkey);

/* Create an input script which spends p2pkh */
u8 *bitcoin_redeem_p2pkh(const tal_t *ctx, const struct pubkey *pubkey,
			 const secp256k1_ecdsa_signature *sig);

/* Create the redeemscript for a P2SH + P2WPKH. */
u8 *bitcoin_redeem_p2wpkh(const tal_t *ctx,
			  const struct pubkey *key);

/* Create a witness which spends the 2of2. */
void bitcoin_witness_p2sh_p2wpkh(const tal_t *ctx,
				 struct bitcoin_tx_input *input,
				 const secp256k1_ecdsa_signature *sig,
				 const struct pubkey *key);

/* Create scriptcode (fake witness, basically) for P2WPKH */
u8 *p2wpkh_scriptcode(const tal_t *ctx, const struct pubkey *key);

/* Create a script for our HTLC output: sending. */
u8 *bitcoin_redeem_htlc_send(const tal_t *ctx,
			     const struct pubkey *ourkey,
			     const struct pubkey *theirkey,
			     const struct abs_locktime *htlc_abstimeout,
			     const struct rel_locktime *locktime,
			     const struct sha256 *commit_revoke,
			     const struct sha256 *rhash);

/* Create a script for our HTLC output: receiving. */
u8 *bitcoin_redeem_htlc_recv(const tal_t *ctx,
			     const struct pubkey *ourkey,
			     const struct pubkey *theirkey,
			     const struct abs_locktime *htlc_abstimeout,
			     const struct rel_locktime *locktime,
			     const struct sha256 *commit_revoke,
			     const struct sha256 *rhash);

/* Create an output script for a 32-byte witness program. */
u8 *scriptpubkey_p2wsh(const tal_t *ctx, const u8 *witnessscript);

/* Create an output script for a 20-byte witness program. */
u8 *scriptpubkey_p2wpkh(const tal_t *ctx, const struct pubkey *key);

/* Create a witness which spends the 2of2. */
u8 **bitcoin_witness_2of2(const tal_t *ctx,
			  const secp256k1_ecdsa_signature *sig1,
			  const secp256k1_ecdsa_signature *sig2,
			  const struct pubkey *key1,
			  const struct pubkey *key2);

/* Create a witness which spends a "secret_or_delay" scriptpubkey */
u8 **bitcoin_witness_secret(const tal_t *ctx,
			    const void *secret, size_t secret_len,
			    const secp256k1_ecdsa_signature *sig,
			    const u8 *witnessscript);

/* Create a witness which spends bitcoin_redeeem_htlc_recv/send */
u8 **bitcoin_witness_htlc(const tal_t *ctx,
			  const void *htlc_or_revocation_preimage,
			  const secp256k1_ecdsa_signature *sig,
			  const u8 *witnessscript);

/* BOLT #3 to-local output */
u8 *bitcoin_wscript_to_local(const tal_t *ctx,
			     u16 to_self_delay,
			     const struct pubkey *revocation_pubkey,
			     const struct pubkey *local_delayedkey);
u8 **bitcoin_to_local_spend_delayedkey(const tal_t *ctx,
			const secp256k1_ecdsa_signature *local_delayedsig,
			const u8 *wscript);
u8 **bitcoin_to_local_spend_revocation(const tal_t *ctx,
		const secp256k1_ecdsa_signature *revocation_sig,
		const u8 *wscript);

/* BOLT #3 offered/accepted HTLC outputs */
u8 *bitcoin_wscript_htlc_offer(const tal_t *ctx,
			       const struct pubkey *localkey,
			       const struct pubkey *remotekey,
			       const struct sha256 *payment_hash);
u8 **bitcoin_htlc_offer_spend_timeout(const tal_t *ctx,
				      const secp256k1_ecdsa_signature *localsig,
				      const secp256k1_ecdsa_signature *remotesig,
				      const u8 *wscript);
u8 *bitcoin_wscript_htlc_receive(const tal_t *ctx,
				 const struct abs_locktime *htlc_abstimeout,
				 const struct pubkey *localkey,
				 const struct pubkey *remotekey,
				 const struct sha256 *payment_hash);
u8 **bitcoin_htlc_receive_spend_preimage(const tal_t *ctx,
				const secp256k1_ecdsa_signature *localsig,
				const secp256k1_ecdsa_signature *remotesig,
				const struct preimage *preimage,
				const u8 *wscript);

/* BOLT #3 HTLC-success/HTLC-timeout output */
u8 *bitcoin_wscript_htlc_tx(const tal_t *ctx,
			    u16 to_self_delay,
			    const struct pubkey *revocation_pubkey,
			    const struct pubkey *local_delayedkey);

/* Is this a pay to pubkey hash? */
bool is_p2pkh(const u8 *script);

/* Is this a pay to script hash? */
bool is_p2sh(const u8 *script);

/* Is this (version 0) pay to witness script hash? */
bool is_p2wsh(const u8 *script);

/* Is this (version 0) pay to witness pubkey hash? */
bool is_p2wpkh(const u8 *script);

/* Are these two scripts equal? */
bool scripteq(const tal_t *s1, const tal_t *s2);

#endif /* LIGHTNING_BITCOIN_SCRIPT_H */
