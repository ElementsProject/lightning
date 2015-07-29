#ifndef LIGHTNING_PKT_H
#define LIGHTNING_PKT_H
/* Simple (non-threadsafe!) wrapper for protobufs.
 *
 * This could be a simple set of macros, if the protobuf-c people hadn't
 * insisted on "prettifing" the names they generate into CamelCase.
 */
#include <ccan/endian/endian.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include "lightning.pb-c.h"

/* A packet, ready to be de-protobuf'ed. */
struct pkt {
	le32 len;
	u8 data[];
};

/* Utility helper: dies if there's a problem. */
Pkt *pkt_from_file(const char *filename, Pkt__PktCase expect);
Pkt *any_pkt_from_file(const char *filename);

/* Total length of packet, including header. */
size_t pkt_totlen(const struct pkt *pkt);

struct sha256;
struct bitcoin_compressed_pubkey;
struct signature;
struct pubkey;

/**
 * openchannel_pkt - create an openchannel message
 * @ctx: tal context to allocate off.
 * @revocation_hash: first hash value generated from seed.
 * @commit: the pubkey for the anchor transactions' P2SH output.
 * @final: the pubkey for the commit transactions' P2SH output.
 * @commitment_fee: the fee to use for commitment tx.
 * @rel_locktime_seconds: relative seconds for commitment locktime.
 * @anchor: the anchor transaction details.
 */
struct pkt *openchannel_pkt(const tal_t *ctx,
			    const struct sha256 *revocation_hash,
			    const struct pubkey *commit,
			    const struct pubkey *final,
			    u64 commitment_fee,
			    u32 rel_locktime_seconds,
			    Anchor *anchor);

/**
 * open_anchor_sig_pkt - create an open_anchor_sig message
 * @ctx: tal context to allocate off.
 * @sigs: the der-encoded signatures (tal_count() gives len).
 * @num_sigs: the number of sigs.
 */
struct pkt *open_anchor_sig_pkt(const tal_t *ctx, u8 **sigs, size_t num_sigs);

/**
 * open_commit_sig_pkt - create an open_commit_sig message
 * @ctx: tal context to allocate off.
 * @sig: the signature for the commit transaction input.
 */
struct pkt *open_commit_sig_pkt(const tal_t *ctx, const struct signature *sig);

/**
 * close_channel_pkt - create an close_channel message
 * @ctx: tal context to allocate off.
 * @sig: the signature for the close transaction input.
 */
struct pkt *close_channel_pkt(const tal_t *ctx, const struct signature *sig);

/**
 * close_channel_complete_pkt - create an close_channel_complete message
 * @ctx: tal context to allocate off.
 * @sig: the signature for the close transaction input.
 */
struct pkt *close_channel_complete_pkt(const tal_t *ctx,
				       const struct signature *sig);

/**
 * update_pkt - create an update message
 * @ctx: tal context to allocate off.
 * @revocation_hash: the revocation hash for the next tx.
 * @delta: the change in satoshis (to me).
 */
struct pkt *update_pkt(const tal_t *ctx,
		       const struct sha256 *revocation_hash,
		       s64 delta);

/**
 * update_accept_pkt - create an update_accept message
 * @ctx: tal context to allocate off.
 * @sig: the signature for the close transaction input.
 * @revocation_hash: hash to revoke the next tx.
 */
struct pkt *update_accept_pkt(const tal_t *ctx,
			      struct signature *sig,
			      const struct sha256 *revocation_hash);

/**
 * update_signature_pkt - create an update_signature message
 * @ctx: tal context to allocate off.
 * @sig: the signature for the close transaction input.
 * @revocation_preimage: preimage to revoke existing (now-obsolete) tx.
 */
struct pkt *update_signature_pkt(const tal_t *ctx,
				 const struct signature *sig,
				 const struct sha256 *revocation_preimage);
/**
 * update_complete_pkt - create an update_accept message
 * @ctx: tal context to allocate off.
 * @revocation_preimage: preimage to revoke existing (now-obsolete) tx.
 */
struct pkt *update_complete_pkt(const tal_t *ctx,
				const struct sha256 *revocation_preimage);

#endif /* LIGHTNING_PKT_H */
