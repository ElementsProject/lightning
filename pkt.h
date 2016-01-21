#ifndef LIGHTNING_PKT_H
#define LIGHTNING_PKT_H
#include "config.h"

/* Simple (non-threadsafe!) wrapper for protobufs.
 *
 * This could be a simple set of macros, if the protobuf-c people hadn't
 * insisted on "prettifing" the names they generate into CamelCase.
 */
#include "lightning.pb-c.h"
#include <ccan/endian/endian.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

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
 * open_channel_pkt - create an openchannel message
 * @ctx: tal context to allocate off.
 * @revocation_hash: first hash value generated from seed.
 * @commit: the pubkey for the anchor transactions' P2SH output.
 * @final: the pubkey for the commit transactions' P2SH output.
 * @rel_locktime_seconds: relative seconds for commitment locktime.
 * @offer_anchor: whether we will offer anchor.
 * @min_depth: minimum depth to insist on (if non-zero)
 * @commitment_fee: fee we would like for commitment txs.
 */
struct pkt *open_channel_pkt(const tal_t *ctx,
			     const struct sha256 *revocation_hash,
			     const struct pubkey *commit,
			     const struct pubkey *final,
			     u32 rel_locktime_seconds,
			     bool offer_anchor,
			     u32 min_depth,
			     u64 commitment_fee);

/**
 * open_anchor_pkt - create an open_anchor message packet
 * @ctx: tal context to allocate off.
 * @oa_msg: the OpenAnchor message.
 */
struct pkt *open_anchor_pkt(const tal_t *ctx, const OpenAnchor *oa_msg);

/**
 * open_commit_sig_pkt - create an open_commit_sig message
 * @ctx: tal context to allocate off.
 * @sig: the signature for the commit transaction input.
 */
struct pkt *open_commit_sig_pkt(const tal_t *ctx, const struct signature *sig);

/**
 * close_channel_pkt - create an close_channel message
 * @ctx: tal context to allocate off.
 * @fee: the fee for the transaction.
 * @sig: the signature for the close transaction input.
 */
struct pkt *close_channel_pkt(const tal_t *ctx,
			      uint64_t fee,
			      const struct signature *sig);

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
 * update_htlc_add_pkt - create an update message adding a HTLC
 * @ctx: tal context to allocate off.
 * @revocation_hash: the revocation hash for the next commitment tx.
 * @val: the change in satoshis (from me).
 * @htlc_rhash: the hash of the htlc secret.
 * @abs_locktime_seconds: the HTLC timeout.
 */
struct pkt *update_htlc_add_pkt(const tal_t *ctx,
				const struct sha256 *revocation_hash,
				u32 value,
				const struct sha256 *htlc_rhash,
				u32 abs_locktime_seconds);

/**
 * update_htlc_complete_pkt - create an update message completing a HTLC
 * @ctx: tal context to allocate off.
 * @revocation_hash: the revocation hash for the next commitment tx.
 * @rval: the r value for the HTLC
 */
struct pkt *update_htlc_complete_pkt(const tal_t *ctx,
				     const struct sha256 *revocation_hash,
				     const struct sha256 *rval);

/**
 * update_htlc_timedout_pkt - create an update message removing a HTLC
 * @ctx: tal context to allocate off.
 * @revocation_hash: the revocation hash for the next commitment tx.
 * @htlc_rhash: the hash of the htlc secret.
 */
struct pkt *update_htlc_timedout_pkt(const tal_t *ctx,
				     const struct sha256 *revocation_hash,
				     const struct sha256 *htlc_rhash);

/**
 * update_htlc_routefail_pkt - create an update message removing a HTLC
 * @ctx: tal context to allocate off.
 * @revocation_hash: the revocation hash for the next commitment tx.
 * @htlc_rhash: the hash of the htlc secret.
 */
struct pkt *update_htlc_routefail_pkt(const tal_t *ctx,
				      const struct sha256 *revocation_hash,
				      const struct sha256 *htlc_rhash);

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
