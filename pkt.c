#include <ccan/crypto/sha256/sha256.h>
#include <ccan/err/err.h>
#include <ccan/tal/grab_file/grab_file.h>
#include "bitcoin/address.h"
#include "bitcoin/pubkey.h"
#include "bitcoin/signature.h"
#include "bitcoin/tx.h"
#include "pkt.h"
#include "protobuf_convert.h"

size_t pkt_totlen(const struct pkt *pkt)
{
	return sizeof(pkt->len) + le32_to_cpu(pkt->len);
}

static struct pkt *to_pkt(const tal_t *ctx, Pkt__PktCase type, const void *msg)
{
	struct pkt *ret;
	size_t len;
	Pkt p = PKT__INIT;
	
	p.pkt_case = type;
	/* This is a union, so doesn't matter which we assign. */
	p.error = (Error *)msg;

	len = pkt__get_packed_size(&p);
	ret = (struct pkt *)tal_arr(ctx, u8, sizeof(ret->len) + len);
	ret->len = cpu_to_le32(len);

	pkt__pack(&p, ret->data);
	return ret;
}

struct pkt *open_channel_pkt(const tal_t *ctx,
			     const struct sha256 *revocation_hash,
			     const struct pubkey *commit,
			     const struct pubkey *final,
			     u32 rel_locktime_seconds,
			     bool offer_anchor,
			     u32 min_depth,
			     u64 commitment_fee)
{
	OpenChannel o = OPEN_CHANNEL__INIT;
	Locktime lt = LOCKTIME__INIT;

	o.revocation_hash = sha256_to_proto(ctx, revocation_hash);
	o.commit_key = pubkey_to_proto(ctx, commit);
	o.final_key = pubkey_to_proto(ctx, final);
	lt.locktime_case = LOCKTIME__LOCKTIME_SECONDS;
	lt.seconds = rel_locktime_seconds;
	o.delay = &lt;
	o.commitment_fee = commitment_fee;
	if (offer_anchor)
		o.anch = OPEN_CHANNEL__ANCHOR_OFFER__WILL_CREATE_ANCHOR;
	else
		o.anch = OPEN_CHANNEL__ANCHOR_OFFER__WONT_CREATE_ANCHOR;

	o.min_depth = min_depth;

	{
		size_t len = open_channel__get_packed_size(&o);
		unsigned char *pb = malloc(len);
		open_channel__pack(&o, pb);
		assert(open_channel__unpack(NULL, len, pb));
		free(pb);
	}
		
	return to_pkt(ctx, PKT__PKT_OPEN, &o);
}

struct pkt *open_anchor_pkt(const tal_t *ctx, const OpenAnchor *oa_msg)
{
	return to_pkt(ctx, PKT__PKT_OPEN_ANCHOR, oa_msg);
}

Pkt *any_pkt_from_file(const char *filename)
{
	struct pkt *pkt;
	Pkt *ret;
	size_t len;

	pkt = grab_file(NULL, filename);
	if (!pkt)
		err(1, "Opening %s", filename);

	len = tal_count(pkt) - 1;
	if (len < sizeof(pkt->len)
	    || len != sizeof(pkt->len) + le32_to_cpu(pkt->len))
		errx(1, "%s length is wrong", filename);
	len -= sizeof(pkt->len);

	ret = pkt__unpack(NULL, len, pkt->data);
	if (!ret)
		errx(1, "Unpack failed for %s", filename);
	return ret;
}
	
Pkt *pkt_from_file(const char *filename, Pkt__PktCase expect)
{
	Pkt *ret = any_pkt_from_file(filename);

	if (ret->pkt_case != expect)
		errx(1, "Unexpected type %i in %s", ret->pkt_case, filename);
	return ret;
}

struct pkt *open_commit_sig_pkt(const tal_t *ctx, const struct signature *sig)
{
	OpenCommitSig o = OPEN_COMMIT_SIG__INIT;

	o.sig = signature_to_proto(ctx, sig);
	return to_pkt(ctx, PKT__PKT_OPEN_COMMIT_SIG, &o);
}

struct pkt *close_channel_pkt(const tal_t *ctx,
			      uint64_t fee,
			      const struct signature *sig)
{
	CloseChannel c = CLOSE_CHANNEL__INIT;
	c.close_fee = fee;
	c.sig = signature_to_proto(ctx, sig);
	return to_pkt(ctx, PKT__PKT_CLOSE, &c);
}

struct pkt *close_channel_complete_pkt(const tal_t *ctx,
				       const struct signature *sig)
{
	CloseChannelComplete c = CLOSE_CHANNEL_COMPLETE__INIT;
	c.sig = signature_to_proto(ctx, sig);
	return to_pkt(ctx, PKT__PKT_CLOSE_COMPLETE, &c);
}

struct pkt *update_pkt(const tal_t *ctx,
		       const struct sha256 *revocation_hash,
		       s64 delta)
{
	Update u = UPDATE__INIT;
	u.revocation_hash = sha256_to_proto(ctx, revocation_hash);
	u.delta_msat = delta * 1000;
	return to_pkt(ctx, PKT__PKT_UPDATE, &u);
}

struct pkt *update_htlc_add_pkt(const tal_t *ctx,
				const struct sha256 *revocation_hash,
				u32 value,
				const struct sha256 *htlc_rhash,
				u32 abs_locktime_seconds)
{
	UpdateAddHtlc u = UPDATE_ADD_HTLC__INIT;
	Locktime l = LOCKTIME__INIT;

	/* HTLC total must fit in 32 bits. */
	if (value > (1ULL << 32) / 1000)
		return NULL;
	
	u.revocation_hash = sha256_to_proto(ctx, revocation_hash);
	u.amount_msat = value * 1000;
	u.r_hash = sha256_to_proto(ctx, htlc_rhash);
	l.locktime_case = LOCKTIME__LOCKTIME_SECONDS;
	l.seconds = abs_locktime_seconds;
	u.expiry = &l;

	return to_pkt(ctx, PKT__PKT_UPDATE_ADD_HTLC, &u);
}

struct pkt *update_htlc_complete_pkt(const tal_t *ctx,
				     const struct sha256 *revocation_hash,
				     const struct sha256 *rval)
{
	UpdateCompleteHtlc u = UPDATE_COMPLETE_HTLC__INIT;

	u.revocation_hash = sha256_to_proto(ctx, revocation_hash);
	u.r = sha256_to_proto(ctx, rval);

	return to_pkt(ctx, PKT__PKT_UPDATE_COMPLETE_HTLC, &u);
}

struct pkt *update_htlc_timedout_pkt(const tal_t *ctx,
				     const struct sha256 *revocation_hash,
				     const struct sha256 *htlc_rhash)
{
	UpdateTimedoutHtlc u = UPDATE_TIMEDOUT_HTLC__INIT;

	u.revocation_hash = sha256_to_proto(ctx, revocation_hash);
	u.r_hash = sha256_to_proto(ctx, htlc_rhash);

	return to_pkt(ctx, PKT__PKT_UPDATE_TIMEDOUT_HTLC, &u);
}

struct pkt *update_htlc_routefail_pkt(const tal_t *ctx,
				      const struct sha256 *revocation_hash,
				      const struct sha256 *htlc_rhash)
{
	UpdateRoutefailHtlc u = UPDATE_ROUTEFAIL_HTLC__INIT;

	u.revocation_hash = sha256_to_proto(ctx, revocation_hash);
	u.r_hash = sha256_to_proto(ctx, htlc_rhash);

	return to_pkt(ctx, PKT__PKT_UPDATE_ROUTEFAIL_HTLC, &u);
}

struct pkt *update_accept_pkt(const tal_t *ctx,
			      struct signature *sig,
			      const struct sha256 *revocation_hash)
{
	UpdateAccept ua = UPDATE_ACCEPT__INIT;
	ua.sig = signature_to_proto(ctx, sig);
	ua.revocation_hash = sha256_to_proto(ctx, revocation_hash);
	return to_pkt(ctx, PKT__PKT_UPDATE_ACCEPT, &ua);
}

struct pkt *update_signature_pkt(const tal_t *ctx,
				 const struct signature *sig,
				 const struct sha256 *revocation_preimage)
{
	UpdateSignature us = UPDATE_SIGNATURE__INIT;
	us.sig = signature_to_proto(ctx, sig);
	us.revocation_preimage = sha256_to_proto(ctx, revocation_preimage);
	return to_pkt(ctx, PKT__PKT_UPDATE_SIGNATURE, &us);
}

struct pkt *update_complete_pkt(const tal_t *ctx,
				const struct sha256 *revocation_preimage)
{
	UpdateComplete uc = UPDATE_COMPLETE__INIT;
	uc.revocation_preimage = sha256_to_proto(ctx, revocation_preimage);
	return to_pkt(ctx, PKT__PKT_UPDATE_COMPLETE, &uc);
}
