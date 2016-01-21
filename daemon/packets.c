#include "bitcoin/script.h"
#include "find_p2sh_out.h"
#include "lightningd.h"
#include "log.h"
#include "names.h"
#include "peer.h"
#include "protobuf_convert.h"
#include "secrets.h"
#include "state.h"
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/mem/mem.h>

#define FIXME_STUB(peer) do { log_broken((peer)->dstate->base_log, "%s:%u: Implement %s!", __FILE__, __LINE__, __func__); abort(); } while(0)

/* Wrap (and own!) member inside Pkt */
static Pkt *make_pkt(const tal_t *ctx, Pkt__PktCase type, const void *msg)
{
	Pkt *pkt = tal(ctx, Pkt);

	pkt__init(pkt);
	pkt->pkt_case = type;
	/* This is a union, so doesn't matter which we assign. */
	pkt->error = (Error *)tal_steal(ctx, msg);

	/* This makes sure all packets are valid. */
#ifndef NDEBUG
	{
		size_t len;
		u8 *packed;
		Pkt *cpy;
		
		len = pkt__get_packed_size(pkt);
		packed = tal_arr(pkt, u8, len);
		pkt__pack(pkt, packed);
		cpy = pkt__unpack(NULL, len, memcheck(packed, len));
		assert(cpy);
		pkt__free_unpacked(cpy, NULL);
		tal_free(packed);
	}
#endif
	return pkt;
}

Pkt *pkt_open(const tal_t *ctx, const struct peer *peer,
	      OpenChannel__AnchorOffer anchor)
{
	OpenChannel *o = tal(ctx, OpenChannel);

	open_channel__init(o);
	o->revocation_hash = sha256_to_proto(ctx, &peer->us.revocation_hash);
	o->commit_key = pubkey_to_proto(o, &peer->us.commitkey);
	o->final_key = pubkey_to_proto(o, &peer->us.finalkey);
	o->delay = tal(o, Locktime);
	locktime__init(o->delay);
	o->delay->locktime_case = LOCKTIME__LOCKTIME_SECONDS;
	o->delay->seconds = rel_locktime_to_seconds(&peer->us.locktime);
	o->commitment_fee = peer->us.commit_fee;
	if (anchor == OPEN_CHANNEL__ANCHOR_OFFER__WILL_CREATE_ANCHOR)
		assert(peer->us.offer_anchor == CMD_OPEN_WITH_ANCHOR);
	else {
		assert(anchor == OPEN_CHANNEL__ANCHOR_OFFER__WONT_CREATE_ANCHOR);
		assert(peer->us.offer_anchor == CMD_OPEN_WITHOUT_ANCHOR);
	}
		
	o->anch = anchor;
	o->min_depth = peer->us.mindepth;
	return make_pkt(ctx, PKT__PKT_OPEN, o);
}
	
Pkt *pkt_anchor(const tal_t *ctx, const struct peer *peer)
{
	struct signature sig;
	OpenAnchor *a = tal(ctx, OpenAnchor);

	open_anchor__init(a);
	a->txid = sha256_to_proto(a, &peer->anchor.txid.sha);
	a->output_index = peer->anchor.index;
	a->amount = peer->anchor.satoshis;

	/* Sign their commit sig */
	peer_sign_theircommit(peer, &sig);
	a->commit_sig = signature_to_proto(a, &sig);

	return make_pkt(ctx, PKT__PKT_OPEN_ANCHOR, a);
}

Pkt *pkt_open_commit_sig(const tal_t *ctx, const struct peer *peer)
{
	FIXME_STUB(peer);
}

Pkt *pkt_open_complete(const tal_t *ctx, const struct peer *peer)
{
	FIXME_STUB(peer);
}

Pkt *pkt_htlc_update(const tal_t *ctx, const struct peer *peer,
		     const struct htlc_progress *htlc_prog)
{
	FIXME_STUB(peer);
}

Pkt *pkt_htlc_fulfill(const tal_t *ctx, const struct peer *peer,
		      const struct htlc_progress *htlc_prog)
{
	FIXME_STUB(peer);
}

Pkt *pkt_htlc_timedout(const tal_t *ctx, const struct peer *peer,
		       const struct htlc_progress *htlc_prog)
{
	FIXME_STUB(peer);
}

Pkt *pkt_htlc_routefail(const tal_t *ctx, const struct peer *peer,
			const struct htlc_progress *htlc_prog)
{
	FIXME_STUB(peer);
}

Pkt *pkt_update_accept(const tal_t *ctx, const struct peer *peer)
{
	FIXME_STUB(peer);
}

Pkt *pkt_update_signature(const tal_t *ctx, const struct peer *peer)
{
	FIXME_STUB(peer);
}

Pkt *pkt_update_complete(const tal_t *ctx, const struct peer *peer)
{
	FIXME_STUB(peer);
}

Pkt *pkt_err(const tal_t *ctx, const char *msg, ...)
{
	abort();
}

Pkt *pkt_close(const tal_t *ctx, const struct peer *peer)
{
	FIXME_STUB(peer);
}

Pkt *pkt_close_complete(const tal_t *ctx, const struct peer *peer)
{
	FIXME_STUB(peer);
}

Pkt *pkt_close_ack(const tal_t *ctx, const struct peer *peer)
{
	FIXME_STUB(peer);
}

Pkt *pkt_err_unexpected(const tal_t *ctx, const Pkt *pkt)
{
	return pkt_err(ctx, "Unexpected packet %s", state_name(pkt->pkt_case));
}

/* Process various packets: return an error packet on failure. */
Pkt *accept_pkt_open(const tal_t *ctx,
		     struct peer *peer, const Pkt *pkt)
{
	struct rel_locktime locktime;
	const OpenChannel *o = pkt->open;

	if (!proto_to_rel_locktime(o->delay, &locktime))
		return pkt_err(ctx, "Invalid delay");
	/* FIXME: handle blocks in locktime */
	if (o->delay->locktime_case != LOCKTIME__LOCKTIME_SECONDS)
		return pkt_err(ctx, "Delay in blocks not accepted");
	if (o->delay->seconds > peer->dstate->config.rel_locktime_max)
		return pkt_err(ctx, "Delay too great");
	if (o->min_depth > peer->dstate->config.anchor_confirms_max)
		return pkt_err(ctx, "min_depth too great");
	if (o->commitment_fee < peer->dstate->config.commitment_fee_min)
		return pkt_err(ctx, "Commitment fee too low");
	if (o->anch == OPEN_CHANNEL__ANCHOR_OFFER__WILL_CREATE_ANCHOR)
		peer->them.offer_anchor = CMD_OPEN_WITH_ANCHOR;
	else if (o->anch == OPEN_CHANNEL__ANCHOR_OFFER__WONT_CREATE_ANCHOR)
		peer->them.offer_anchor = CMD_OPEN_WITHOUT_ANCHOR;
	else
		return pkt_err(ctx, "Unknown offer anchor value");

	if (peer->them.offer_anchor == peer->us.offer_anchor)
		return pkt_err(ctx, "Only one side can offer anchor");

	if (!proto_to_rel_locktime(o->delay, &peer->them.locktime))
		return pkt_err(ctx, "Malformed locktime");
	peer->them.mindepth = o->min_depth;
	peer->them.commit_fee = o->commitment_fee;
	if (!proto_to_pubkey(peer->dstate->secpctx,
			     o->commit_key, &peer->them.commitkey))
		return pkt_err(ctx, "Bad commitkey");
	if (!proto_to_pubkey(peer->dstate->secpctx,
			     o->final_key, &peer->them.finalkey))
		return pkt_err(ctx, "Bad finalkey");
	proto_to_sha256(o->revocation_hash, &peer->them.revocation_hash);

	/* Redeemscript for anchor. */
	peer->anchor.redeemscript
		= bitcoin_redeem_2of2(peer, &peer->us.commitkey,
				      &peer->them.commitkey);
	return NULL;
}

Pkt *accept_pkt_anchor(const tal_t *ctx,
		       struct peer *peer,
		       const Pkt *pkt)
{
	const OpenAnchor *a = pkt->open_anchor;
	u64 commitfee;

	/* They must be offering anchor for us to try accepting */
	assert(peer->us.offer_anchor == CMD_OPEN_WITHOUT_ANCHOR);
	assert(peer->them.offer_anchor == CMD_OPEN_WITH_ANCHOR);

	proto_to_sha256(a->txid, &peer->anchor.txid.sha);
	peer->anchor.index = a->output_index;
	peer->anchor.satoshis = a->amount;

	/* Create funder's cstate, invert to get ours. */
	commitfee = commit_fee(peer->them.commit_fee, peer->us.commit_fee);
	peer->cstate = initial_funding(peer,
				       peer->us.offer_anchor,
				       peer->anchor.satoshis,
				       commitfee);
	if (!peer->cstate)
		return pkt_err(ctx, "Insufficient funds for fee");
	invert_cstate(peer->cstate);

	/* Now we can make initial (unsigned!) commit txs. */
	peer_make_commit_txs(peer);

	peer->cur_commit_theirsig.stype = SIGHASH_ALL;
	if (!proto_to_signature(a->commit_sig, &peer->cur_commit_theirsig.sig))
		return pkt_err(ctx, "Malformed signature");

	/* Their sig should sign our commit tx. */
	if (!check_tx_sig(peer->dstate->secpctx,
			  peer->us.commit, 0,
			  peer->anchor.redeemscript,
			  tal_count(peer->anchor.redeemscript),
			  &peer->them.commitkey,
			  &peer->cur_commit_theirsig))
		return pkt_err(ctx, "Bad signature");

	return NULL;
}

Pkt *accept_pkt_open_commit_sig(const tal_t *ctx,
				struct peer *peer, const Pkt *pkt)
{
	FIXME_STUB(peer);
}
	
Pkt *accept_pkt_htlc_update(const tal_t *ctx,
			    struct peer *peer, const Pkt *pkt,
			    Pkt **decline)
{
	FIXME_STUB(peer);
}

Pkt *accept_pkt_htlc_routefail(const tal_t *ctx,
			       struct peer *peer, const Pkt *pkt)
{
	FIXME_STUB(peer);
}

Pkt *accept_pkt_htlc_timedout(const tal_t *ctx,
			      struct peer *peer, const Pkt *pkt)
{
	FIXME_STUB(peer);
}

Pkt *accept_pkt_htlc_fulfill(const tal_t *ctx,
			     struct peer *peer, const Pkt *pkt)
{
	FIXME_STUB(peer);
}

Pkt *accept_pkt_update_accept(const tal_t *ctx,
			      struct peer *peer, const Pkt *pkt)
{
	FIXME_STUB(peer);
}

Pkt *accept_pkt_update_complete(const tal_t *ctx,
				struct peer *peer, const Pkt *pkt)
{
	FIXME_STUB(peer);
}

Pkt *accept_pkt_update_signature(const tal_t *ctx,
				 struct peer *peer,
				 const Pkt *pkt)
{
	FIXME_STUB(peer);
}

Pkt *accept_pkt_close(const tal_t *ctx, struct peer *peer, const Pkt *pkt)
{
	FIXME_STUB(peer);
}

Pkt *accept_pkt_close_complete(const tal_t *ctx,
			       struct peer *peer, const Pkt *pkt)
{
	FIXME_STUB(peer);
}

Pkt *accept_pkt_simultaneous_close(const tal_t *ctx,
				   struct peer *peer,
				   const Pkt *pkt)
{
	FIXME_STUB(peer);
}

Pkt *accept_pkt_close_ack(const tal_t *ctx, struct peer *peer, const Pkt *pkt)
{
	FIXME_STUB(peer);
}
