#ifndef LIGHTNING_BITCOIN_SCRIPT_H
#define LIGHTNING_BITCOIN_SCRIPT_H
#include "config.h"
#include "signature.h"
#include "tx.h"
#include <wally_script.h>

struct bitcoin_address;
struct preimage;
struct pubkey;
struct sha256;
struct ripemd160;
struct rel_locktime;
struct abs_locktime;

/* tal_count() gives the length of the script. */
u8 *bitcoin_redeem_2of2(const tal_t *ctx,
			const struct pubkey *key1,
			const struct pubkey *key2);

/* Create an output script using p2sh for this redeem script. */
u8 *scriptpubkey_p2sh(const tal_t *ctx, const u8 *redeemscript);

/* Create an output script using p2sh for this hash. */
u8 *scriptpubkey_p2sh_hash(const tal_t *ctx, const struct ripemd160 *redeemhash);

/* Create an output script using p2pkh */
u8 *scriptpubkey_p2pkh(const tal_t *ctx, const struct bitcoin_address *addr);

/* Create a prunable output script with 20 random bytes.
 * This is needed since a spend from a p2wpkh to an `OP_RETURN` without
 * any other outputs would result in a transaction smaller than the
 * minimum size.  */
u8 *scriptpubkey_opreturn_padded(const tal_t *ctx);

/* Create an input script which spends p2pkh */
u8 *bitcoin_redeem_p2pkh(const tal_t *ctx, const struct pubkey *pubkey,
			 const struct bitcoin_signature *sig);

/* Create the redeemscript for a P2SH + P2WPKH. */
u8 *bitcoin_redeem_p2sh_p2wpkh(const tal_t *ctx, const struct pubkey *key);

/* Create the scriptsig for a redeemscript */
u8 *bitcoin_scriptsig_redeem(const tal_t *ctx,
			     const u8 *redeemscript TAKES);

/* Create scriptsig for p2sh-p2wpkh */
u8 *bitcoin_scriptsig_p2sh_p2wpkh(const tal_t *ctx, const struct pubkey *key);

/* Create scriptcode (fake witness, basically) for P2WPKH */
u8 *p2wpkh_scriptcode(const tal_t *ctx, const struct pubkey *key);

/* Create an output script for a 32-byte witness program. */
u8 *scriptpubkey_p2wsh(const tal_t *ctx, const u8 *witnessscript);

/* Create an output script for a 20-byte witness program. */
u8 *scriptpubkey_p2wpkh(const tal_t *ctx, const struct pubkey *key);

/* Same as above, but compressed key is already DER-encoded. */
u8 *scriptpubkey_p2wpkh_derkey(const tal_t *ctx, const u8 der[33]);

/* Encode an arbitrary witness as <version> <push:wprog> */
u8 *scriptpubkey_witness_raw(const tal_t *ctx, u8 version,
			     const u8 *wprog, size_t wprog_size);

/* To-remotekey with csv max(lease_expiry - blockheight, 1) delay. */
u8 *anchor_to_remote_redeem(const tal_t *ctx,
			    const struct pubkey *remote_key,
			    u32 csv_lock);

/* Create a witness which spends the 2of2. */
u8 **bitcoin_witness_2of2(const tal_t *ctx,
			  const struct bitcoin_signature *sig1,
			  const struct bitcoin_signature *sig2,
			  const struct pubkey *key1,
			  const struct pubkey *key2);

/* Create a witness which spends a p2wpkh. */
u8 **bitcoin_witness_p2wpkh(const tal_t *ctx,
			    const struct bitcoin_signature *sig,
			    const struct pubkey *key);

/* Create a witness which contains sig, another entry, and the witnessscript */
u8 **bitcoin_witness_sig_and_element(const tal_t *ctx,
				     const struct bitcoin_signature *sig,
				     const void *elem, size_t elemsize,
				     const u8 *witnessscript);

/* BOLT #3 to-local output */
u8 *bitcoin_wscript_to_local(const tal_t *ctx, u16 to_self_delay,
			     u32 lease_remaining,
			     const struct pubkey *revocation_pubkey,
			     const struct pubkey *local_delayedkey);

/* BOLT #3 offered/accepted HTLC outputs */
u8 *bitcoin_wscript_htlc_offer(const tal_t *ctx,
			       const struct pubkey *localhtlckey,
			       const struct pubkey *remotehtlckey,
			       const struct sha256 *payment_hash,
			       const struct pubkey *revocationkey,
			       bool option_anchor_outputs);
u8 **bitcoin_witness_htlc_timeout_tx(const tal_t *ctx,
				     const struct bitcoin_signature *localsig,
				     const struct bitcoin_signature *remotesig,
				     const u8 *wscript);
u8 *bitcoin_wscript_htlc_receive(const tal_t *ctx,
				 const struct abs_locktime *htlc_abstimeout,
				 const struct pubkey *localkey,
				 const struct pubkey *remotekey,
				 const struct sha256 *payment_hash,
				 const struct pubkey *revocationkey,
				 bool option_anchor_outputs);
u8 **bitcoin_witness_htlc_success_tx(const tal_t *ctx,
				     const struct bitcoin_signature *localsig,
				     const struct bitcoin_signature *remotesig,
				     const struct preimage *preimage,
				     const u8 *wscript);

/* Underlying functions for penalties, where we only keep ripemd160 */
u8 *bitcoin_wscript_htlc_offer_ripemd160(const tal_t *ctx,
					 const struct pubkey *localhtlckey,
					 const struct pubkey *remotehtlckey,
					 const struct ripemd160 *payment_ripemd,
					 const struct pubkey *revocationkey,
					 bool option_anchor_outputs);
u8 *bitcoin_wscript_htlc_receive_ripemd(const tal_t *ctx,
					const struct abs_locktime *htlc_abstimeout,
					const struct pubkey *localkey,
					const struct pubkey *remotekey,
					const struct ripemd160 *payment_ripemd,
					const struct pubkey *revocationkey,
					bool option_anchor_outputs);

/* BOLT #3 HTLC-success/HTLC-timeout output */
u8 *bitcoin_wscript_htlc_tx(const tal_t *ctx,
			    u16 to_self_delay,
			    const struct pubkey *revocation_pubkey,
			    const struct pubkey *local_delayedkey);

/* Anchor outputs */
u8 *bitcoin_wscript_anchor(const tal_t *ctx,
			   const struct pubkey *funding_pubkey);

/* Is this a pay to pubkey hash? (extract addr if not NULL) */
bool is_p2pkh(const u8 *script, struct bitcoin_address *addr);

/* Is this a pay to script hash? (extract addr if not NULL) */
bool is_p2sh(const u8 *script, struct ripemd160 *addr);

/* Is this (version 0) pay to witness script hash? (extract addr if not NULL) */
bool is_p2wsh(const u8 *script, struct sha256 *addr);

/* Is this (version 0) pay to witness pubkey hash? (extract addr if not NULL) */
bool is_p2wpkh(const u8 *script, struct bitcoin_address *addr);

/* Is this one of the four above script types? */
bool is_known_scripttype(const u8 *script);

/* Is this an anchor witness script? */
bool is_anchor_witness_script(const u8 *script, size_t script_len);

/* Are these two scripts equal? */
bool scripteq(const u8 *s1, const u8 *s2);

/* Raw "push these bytes" accessor. */
void script_push_bytes(u8 **scriptp, const void *mem, size_t len);

/* OP_DUP + OP_HASH160 + PUSH(20-byte-hash) + OP_EQUALVERIFY + OP_CHECKSIG */
#define BITCOIN_SCRIPTPUBKEY_P2PKH_LEN (1 + 1 + 1 + 20 + 1 + 1)

/* OP_HASH160 + PUSH(20-byte-hash) + OP_EQUAL */
#define BITCOIN_SCRIPTPUBKEY_P2SH_LEN (1 + 1 + 20 + 1)

/* OP_0 + PUSH(20-byte-hash) */
#define BITCOIN_SCRIPTPUBKEY_P2WPKH_LEN (1 + 1 + 20)

/* OP_0 + PUSH(32-byte-hash) */
#define BITCOIN_SCRIPTPUBKEY_P2WSH_LEN (1 + 1 + 32)

#endif /* LIGHTNING_BITCOIN_SCRIPT_H */
