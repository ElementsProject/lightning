#ifndef LIGHTNING_PKT_H
#define LIGHTNING_PKT_H
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

struct sha256;
struct bitcoin_compressed_pubkey;
struct signature;
struct pubkey;

/**
 * openchannel_pkt - create an openchannel message
 * @ctx: tal context to allocate off.
 * @seed: psuedo-random seed to shuffle inputs.
 * @revocation_hash: first hash value generated from seed.
 * @to_me: the pubkey for the commit transactions' P2SH output.
 * @commitment_fee: the fee to use for commitment tx.
 * @rel_locktime_seconds: relative seconds for commitment locktime.
 * @anchor: the anchor transaction details.
 */
struct pkt *openchannel_pkt(const tal_t *ctx,
			    u64 seed,
			    const struct sha256 *revocation_hash,
			    const struct pubkey *to_me,
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
 * leak_anchor_sigs_and_pretend_we_didnt_pkt - leak anchor scriptsigs
 * @ctx: tal context to allocate off.
 * @s: OpenAnchorSig.
 */
struct pkt *leak_anchor_sigs_and_pretend_we_didnt_pkt(const tal_t *ctx,
						      OpenAnchorScriptsigs *s);


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

/* Useful helper for allocating & populating a protobuf Sha256Hash */
Sha256Hash *sha256_to_proto(const tal_t *ctx, const struct sha256 *hash);
void proto_to_sha256(const Sha256Hash *pb, struct sha256 *hash);
#endif /* LIGHTNING_PKT_H */
