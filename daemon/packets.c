#include "bitcoin/script.h"
#include "bitcoin/tx.h"
#include "close_tx.h"
#include "controlled_time.h"
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
#include <ccan/str/hex/hex.h>
#include <ccan/structeq/structeq.h>
#include <ccan/tal/str/str.h>
#include <inttypes.h>

#define FIXME_STUB(peer) do { log_broken((peer)->dstate->base_log, "%s:%u: Implement %s!", __FILE__, __LINE__, __func__); abort(); } while(0)

static char *hex_of(const tal_t *ctx, const void *p, size_t n)
{
	char *hex = tal_arr(ctx, char, hex_str_size(n));
	hex_encode(p, n, hex, hex_str_size(n));
	return hex;
}

static void dump_tx(const char *str, const struct bitcoin_tx *tx)
{
	u8 *linear = linearize_tx(NULL, tx);
	printf("%s:%s\n", str, hex_of(linear, linear, tal_count(linear)));
	tal_free(linear);
}

static void dump_key(const char *str, const struct pubkey *key)
{
	printf("%s:%s\n", str, hex_of(NULL, key->der, pubkey_derlen(key)));
}

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
	peer_sign_theircommit(peer, peer->them.commit, &sig);
	a->commit_sig = signature_to_proto(a, &sig);

	return make_pkt(ctx, PKT__PKT_OPEN_ANCHOR, a);
}

Pkt *pkt_open_commit_sig(const tal_t *ctx, const struct peer *peer)
{
	struct signature sig;
	OpenCommitSig *s = tal(ctx, OpenCommitSig);

	open_commit_sig__init(s);

	dump_tx("Creating sig for:", peer->them.commit);
	dump_key("Using key:", &peer->us.commitkey);

	peer_sign_theircommit(peer, peer->them.commit, &sig);
	s->sig = signature_to_proto(s, &sig);

	return make_pkt(ctx, PKT__PKT_OPEN_COMMIT_SIG, s);
}

Pkt *pkt_open_complete(const tal_t *ctx, const struct peer *peer)
{
	OpenComplete *o = tal(ctx, OpenComplete);

	open_complete__init(o);
	return make_pkt(ctx, PKT__PKT_OPEN_COMPLETE, o);
}

Pkt *pkt_htlc_add(const tal_t *ctx, const struct peer *peer,
		  const struct htlc_progress *htlc_prog)
{
	UpdateAddHtlc *u = tal(ctx, UpdateAddHtlc);

	update_add_htlc__init(u);

	u->revocation_hash = sha256_to_proto(u, &htlc_prog->our_revocation_hash);
	u->amount_msat = htlc_prog->htlc->msatoshis;
	u->r_hash = sha256_to_proto(u, &htlc_prog->htlc->rhash);
	u->expiry = abs_locktime_to_proto(u, &htlc_prog->htlc->expiry);

	return make_pkt(ctx, PKT__PKT_UPDATE_ADD_HTLC, u);
}

Pkt *pkt_htlc_fulfill(const tal_t *ctx, const struct peer *peer,
		      const struct htlc_progress *htlc_prog)
{
	UpdateFulfillHtlc *f = tal(ctx, UpdateFulfillHtlc);

	update_fulfill_htlc__init(f);

	f->revocation_hash = sha256_to_proto(f, &htlc_prog->our_revocation_hash);
	f->r = sha256_to_proto(f, &htlc_prog->r);

	return make_pkt(ctx, PKT__PKT_UPDATE_FULFILL_HTLC, f);
}

Pkt *pkt_htlc_fail(const tal_t *ctx, const struct peer *peer,
		   const struct htlc_progress *htlc_prog)
{
	UpdateFailHtlc *f = tal(ctx, UpdateFailHtlc);

	update_fail_htlc__init(f);

	f->revocation_hash = sha256_to_proto(f, &htlc_prog->our_revocation_hash);
	f->r_hash = sha256_to_proto(f, &htlc_prog->htlc->rhash);

	return make_pkt(ctx, PKT__PKT_UPDATE_FAIL_HTLC, f);
}

Pkt *pkt_update_accept(const tal_t *ctx, const struct peer *peer)
{
	UpdateAccept *u = tal(ctx, UpdateAccept);
	const struct htlc_progress *cur = peer->current_htlc;
	struct signature sig;

	update_accept__init(u);

	dump_tx("Signing tx", cur->their_commit);
	peer_sign_theircommit(peer, cur->their_commit, &sig);
	u->sig = signature_to_proto(u, &sig);
	u->revocation_hash
		= sha256_to_proto(u, &cur->our_revocation_hash);

	return make_pkt(ctx, PKT__PKT_UPDATE_ACCEPT, u);
}

Pkt *pkt_update_signature(const tal_t *ctx, const struct peer *peer)
{
	UpdateSignature *u = tal(ctx, UpdateSignature);
	const struct htlc_progress *cur = peer->current_htlc;
	struct signature sig;
	struct sha256 preimage;

	update_signature__init(u);

	peer_sign_theircommit(peer, cur->their_commit, &sig);
	u->sig = signature_to_proto(u, &sig);
	assert(peer->commit_tx_counter > 0);
	peer_get_revocation_preimage(peer, peer->commit_tx_counter-1, &preimage);
	u->revocation_preimage = sha256_to_proto(u, &preimage);

	return make_pkt(ctx, PKT__PKT_UPDATE_SIGNATURE, u);
}

Pkt *pkt_update_complete(const tal_t *ctx, const struct peer *peer)
{
	UpdateComplete *u = tal(ctx, UpdateComplete);
	struct sha256 preimage;

	update_complete__init(u);

	assert(peer->commit_tx_counter > 0);
	peer_get_revocation_preimage(peer, peer->commit_tx_counter-1, &preimage);
	u->revocation_preimage = sha256_to_proto(u, &preimage);

	return make_pkt(ctx, PKT__PKT_UPDATE_COMPLETE, u);
}

Pkt *pkt_err(const tal_t *ctx, const char *msg, ...)
{
	Error *e = tal(ctx, Error);
	va_list ap;

	error__init(e);
	va_start(ap, msg);
	e->problem = tal_vfmt(ctx, msg, ap);
	va_end(ap);

	return make_pkt(ctx, PKT__PKT_ERROR, e);
}

Pkt *pkt_close(const tal_t *ctx, const struct peer *peer)
{
	CloseChannel *c = tal(ctx, CloseChannel);

	close_channel__init(c);

	c->close_fee = peer->close_tx->fee;
	c->sig = signature_to_proto(c, &peer->our_close_sig.sig);

	return make_pkt(ctx, PKT__PKT_CLOSE, c);
}

Pkt *pkt_close_complete(const tal_t *ctx, const struct peer *peer)
{
	CloseChannelComplete *c = tal(ctx, CloseChannelComplete);

	close_channel_complete__init(c);
	assert(peer->close_tx);
	c->sig = signature_to_proto(c, &peer->our_close_sig.sig);

	return make_pkt(ctx, PKT__PKT_CLOSE_COMPLETE, c);
}

Pkt *pkt_close_ack(const tal_t *ctx, const struct peer *peer)
{
	CloseChannelAck *a = tal(ctx, CloseChannelAck);

	close_channel_ack__init(a);
	return make_pkt(ctx, PKT__PKT_CLOSE_ACK, a);
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
	make_commit_txs(peer, peer,
			&peer->us.revocation_hash,
			&peer->them.revocation_hash,
			peer->cstate,
			&peer->us.commit,
			&peer->them.commit);

	peer->cur_commit.theirsig.stype = SIGHASH_ALL;
	if (!proto_to_signature(a->commit_sig, &peer->cur_commit.theirsig.sig))
		return pkt_err(ctx, "Malformed signature");

	/* Their sig should sign our commit tx. */
	if (!check_tx_sig(peer->dstate->secpctx,
			  peer->us.commit, 0,
			  peer->anchor.redeemscript,
			  tal_count(peer->anchor.redeemscript),
			  &peer->them.commitkey,
			  &peer->cur_commit.theirsig))
		return pkt_err(ctx, "Bad signature");

	return NULL;
}

Pkt *accept_pkt_open_commit_sig(const tal_t *ctx,
				struct peer *peer, const Pkt *pkt)
{
	const OpenCommitSig *s = pkt->open_commit_sig;

	peer->cur_commit.theirsig.stype = SIGHASH_ALL;
	if (!proto_to_signature(s->sig, &peer->cur_commit.theirsig.sig))
		return pkt_err(ctx, "Malformed signature");

	dump_tx("Checking sig for:", peer->us.commit);
	dump_key("Using key:", &peer->them.commitkey);

	/* Their sig should sign our commit tx. */
	if (!check_tx_sig(peer->dstate->secpctx,
			  peer->us.commit, 0,
			  peer->anchor.redeemscript,
			  tal_count(peer->anchor.redeemscript),
			  &peer->them.commitkey,
			  &peer->cur_commit.theirsig))
		return pkt_err(ctx, "Bad signature");

	return NULL;
}

Pkt *accept_pkt_open_complete(const tal_t *ctx,
			      struct peer *peer, const Pkt *pkt)
{
	return NULL;
}

static Pkt *decline_htlc(const tal_t *ctx, const char *why)
{
	UpdateDeclineHtlc *d = tal(ctx, UpdateDeclineHtlc);

	update_decline_htlc__init(d);
	/* FIXME: Define why in protocol! */
	d->reason_case = UPDATE_DECLINE_HTLC__REASON_CANNOT_ROUTE;
	d->cannot_route = true;

	return make_pkt(ctx, PKT__PKT_UPDATE_DECLINE_HTLC, d);
}

Pkt *accept_pkt_htlc_add(const tal_t *ctx,
			 struct peer *peer, const Pkt *pkt,
			 Pkt **decline)
{
	const UpdateAddHtlc *u = pkt->update_add_htlc;
	struct htlc_progress *cur = tal(peer, struct htlc_progress);
	Pkt *err;

	cur->htlc = tal(cur, struct channel_htlc);
	cur->htlc->msatoshis = u->amount_msat;
	proto_to_sha256(u->r_hash, &cur->htlc->rhash);
	proto_to_sha256(u->revocation_hash, &cur->their_revocation_hash);
	if (!proto_to_abs_locktime(u->expiry, &cur->htlc->expiry)) {
		err = pkt_err(ctx, "Invalid HTLC expiry");
		goto fail;
	}

	/* FIXME: Handle block-based expiry! */
	if (!abs_locktime_is_seconds(&cur->htlc->expiry)) {
		*decline = decline_htlc(ctx, 
					"HTLC expiry in blocks not supported!");
		goto decline;
	}

	if (abs_locktime_to_seconds(&cur->htlc->expiry) <
	    controlled_time().ts.tv_sec + peer->dstate->config.min_expiry) {
		*decline = decline_htlc(ctx, "HTLC expiry too soon!");
		goto decline;
	}

	if (abs_locktime_to_seconds(&cur->htlc->expiry) >
	    controlled_time().ts.tv_sec + peer->dstate->config.max_expiry) {
		*decline = decline_htlc(ctx, "HTLC expiry too far!");
		goto decline;
	}

	cur->cstate = copy_funding(cur, peer->cstate);
	if (!funding_delta(peer->anchor.satoshis,
			   0, cur->htlc->msatoshis,
			   &cur->cstate->b, &cur->cstate->a)) {
		err = pkt_err(ctx, "Cannot afford %"PRIu64" milli-satoshis",
			      cur->htlc->msatoshis);
		goto fail;
	}
	/* Add the htlc to their side of channel. */
	funding_add_htlc(&cur->cstate->b, cur->htlc->msatoshis,
			 &cur->htlc->expiry, &cur->htlc->rhash);
	peer_add_htlc_expiry(peer, &cur->htlc->expiry);
	
	peer_get_revocation_hash(peer, peer->commit_tx_counter+1,
				 &cur->our_revocation_hash);
	memcheck(&cur->their_revocation_hash, sizeof(cur->their_revocation_hash));

	/* Now we create the commit tx pair. */
	make_commit_txs(cur, peer,
			memcheck(&cur->our_revocation_hash,
				 sizeof(cur->our_revocation_hash)),
			&cur->their_revocation_hash,
			cur->cstate,
			&cur->our_commit, &cur->their_commit);

	/* FIXME: Fees must be sufficient. */
	*decline = NULL;
	assert(!peer->current_htlc);
	peer->current_htlc = cur;
	return NULL;

fail:
	tal_free(cur);
	return err;

decline:
	assert(*decline);
	tal_free(cur);
	return NULL;
};

Pkt *accept_pkt_htlc_fail(const tal_t *ctx, struct peer *peer, const Pkt *pkt)
{
	const UpdateFailHtlc *f = pkt->update_fail_htlc;
	struct htlc_progress *cur = tal(peer, struct htlc_progress);
	Pkt *err;
	size_t i;
	struct sha256 rhash;

	proto_to_sha256(f->revocation_hash, &cur->their_revocation_hash);
	proto_to_sha256(f->r_hash, &rhash);

	i = funding_find_htlc(&peer->cstate->a, &rhash);
	if (i == tal_count(peer->cstate->a.htlcs)) {
		err = pkt_err(ctx, "Unknown HTLC");
		goto fail;
	}

	cur->htlc = tal_dup(cur, struct channel_htlc, &peer->cstate->a.htlcs[i]);

	/* Removing it should not fail: we regain HTLC amount */
	cur->cstate = copy_funding(cur, peer->cstate);
	if (!funding_delta(peer->anchor.satoshis,
			   0, -cur->htlc->msatoshis,
			   &cur->cstate->a, &cur->cstate->b)) {
		fatal("Unexpected failure fulfilling HTLC of %"PRIu64
		      " milli-satoshis", cur->htlc->msatoshis);
	}
	funding_remove_htlc(&cur->cstate->a, i);
	/* FIXME: Remove timer. */
	
	peer_get_revocation_hash(peer, peer->commit_tx_counter+1,
				 &cur->our_revocation_hash);

	/* Now we create the commit tx pair. */
	make_commit_txs(cur, peer, &cur->our_revocation_hash,
			&cur->their_revocation_hash,
			cur->cstate,
			&cur->our_commit, &cur->their_commit);

	assert(!peer->current_htlc);
	peer->current_htlc = cur;
	return NULL;

fail:
	tal_free(cur);
	return err;
}

Pkt *accept_pkt_htlc_fulfill(const tal_t *ctx,
			     struct peer *peer, const Pkt *pkt)
{
	const UpdateFulfillHtlc *f = pkt->update_fulfill_htlc;
	struct htlc_progress *cur = tal(peer, struct htlc_progress);
	Pkt *err;
	size_t i;
	struct sha256 rhash, r;

	proto_to_sha256(f->r, &r);
	proto_to_sha256(f->revocation_hash, &cur->their_revocation_hash);
	sha256(&rhash, &r, sizeof(r));
	i = funding_find_htlc(&peer->cstate->a, &rhash);
	if (i == tal_count(peer->cstate->a.htlcs)) {
		err = pkt_err(ctx, "Unknown HTLC");
		goto fail;
	}

	cur->htlc = tal_dup(cur, struct channel_htlc, &peer->cstate->a.htlcs[i]);

	/* Removing it should not fail: they gain HTLC amount */
	cur->cstate = copy_funding(cur, peer->cstate);
	if (!funding_delta(peer->anchor.satoshis,
			   -cur->htlc->msatoshis,
			   -cur->htlc->msatoshis,
			   &cur->cstate->a, &cur->cstate->b)) {
		fatal("Unexpected failure fulfilling HTLC of %"PRIu64
		      " milli-satoshis", cur->htlc->msatoshis);
	}
	funding_remove_htlc(&cur->cstate->a, i);
	
	peer_get_revocation_hash(peer, peer->commit_tx_counter+1,
				 &cur->our_revocation_hash);

	/* Now we create the commit tx pair. */
	make_commit_txs(cur, peer, &cur->our_revocation_hash,
			&cur->their_revocation_hash,
			cur->cstate,
			&cur->our_commit, &cur->their_commit);

	assert(!peer->current_htlc);
	peer->current_htlc = cur;
	return NULL;

fail:
	tal_free(cur);
	return err;
}

static u64 total_funds(const struct channel_oneside *c)
{
	u64 total = (u64)c->pay_msat + c->fee_msat;
	size_t i, n = tal_count(c->htlcs);

	for (i = 0; i < n; i++)
		total += c->htlcs[i].msatoshis;
	return total;
}

static void update_to_new_htlcs(struct peer *peer)
{
	struct htlc_progress *cur = peer->current_htlc;

	/* FIXME: Add to shachain too. */

	/* HTLCs can't change total balance in channel! */
	if (total_funds(&peer->cstate->a) + total_funds(&peer->cstate->b)
	    != total_funds(&cur->cstate->a) + total_funds(&cur->cstate->b))
		fatal("Illegal funding transition from %u/%u (total %"PRIu64")"
		      " to %u/%u (total %"PRIu64")",
		      peer->cstate->a.pay_msat, peer->cstate->a.fee_msat,
		      total_funds(&peer->cstate->a),
		      peer->cstate->b.pay_msat, peer->cstate->b.fee_msat,
		      total_funds(&peer->cstate->b));

	/* Now, we consider this channel_state current one. */
	tal_free(peer->cstate);
	peer->cstate = tal_steal(peer, cur->cstate);

	tal_free(peer->us.commit);
	peer->us.commit = tal_steal(peer, cur->our_commit);
	/* FIXME: Save their old commit details, to steal funds. */
	tal_free(peer->them.commit);
	peer->them.commit = tal_steal(peer, cur->their_commit);
	peer->us.revocation_hash = cur->our_revocation_hash;
	peer->them.revocation_hash = cur->their_revocation_hash;

	peer->commit_tx_counter++;
}

Pkt *accept_pkt_update_accept(const tal_t *ctx,
			      struct peer *peer, const Pkt *pkt)
{
	const UpdateAccept *a = pkt->update_accept;
	struct htlc_progress *cur = peer->current_htlc;
	
	proto_to_sha256(a->revocation_hash, &cur->their_revocation_hash);

	cur->their_sig.stype = SIGHASH_ALL;
	if (!proto_to_signature(a->sig, &cur->their_sig.sig))
		return pkt_err(ctx, "Malformed signature");

	/* Now we can make commit tx pair. */
	make_commit_txs(cur, peer, &cur->our_revocation_hash,
			&cur->their_revocation_hash,
			cur->cstate,
			&cur->our_commit, &cur->their_commit);

	/* Their sig should sign our new commit tx. */
	if (!check_tx_sig(peer->dstate->secpctx,
			  cur->our_commit, 0,
			  peer->anchor.redeemscript,
			  tal_count(peer->anchor.redeemscript),
			  &peer->them.commitkey,
			  &cur->their_sig))
		return pkt_err(ctx, "Bad signature");

	/* Our next step will be to send the revocation preimage, so
	 * update to new HTLC now so we never use the old one. */
	update_to_new_htlcs(peer);
	return NULL;
}	

static bool check_preimage(const Sha256Hash *preimage, const struct sha256 *hash)
{
	struct sha256 h;

	proto_to_sha256(preimage, &h);
	sha256(&h, &h, sizeof(h));
	return structeq(&h, hash);
}

Pkt *accept_pkt_update_complete(const tal_t *ctx,
				struct peer *peer, const Pkt *pkt)
{
	/* FIXME: Check preimage against old tx! */
	return NULL;
}

Pkt *accept_pkt_update_signature(const tal_t *ctx,
				 struct peer *peer,
				 const Pkt *pkt)
{
	const UpdateSignature *s = pkt->update_signature;
	struct htlc_progress *cur = peer->current_htlc;

	cur->their_sig.stype = SIGHASH_ALL;
	if (!proto_to_signature(s->sig, &cur->their_sig.sig))
		return pkt_err(ctx, "Malformed signature");

	/* Their sig should sign our new commit tx. */
	if (!check_tx_sig(peer->dstate->secpctx,
			  cur->our_commit, 0,
			  peer->anchor.redeemscript,
			  tal_count(peer->anchor.redeemscript),
			  &peer->them.commitkey,
			  &cur->their_sig))
		return pkt_err(ctx, "Bad signature");

	/* Check their revocation preimage. */
	if (!check_preimage(s->revocation_preimage, &peer->them.revocation_hash))
		return pkt_err(ctx, "Bad revocation preimage");

	/* Our next step will be to send the revocation preimage, so
	 * update to new HTLC now so we never use the old one. */
	update_to_new_htlcs(peer);
	return NULL;
}

static bool peer_sign_close_tx(struct peer *peer, const Signature *theirs)
{
	struct bitcoin_signature theirsig;

	/* We never sign twice! */
	assert(peer->close_tx->input[0].script_length == 0);

	theirsig.stype = SIGHASH_ALL;
	if (!proto_to_signature(theirs, &theirsig.sig))
		return false;

	/* Their sig + ours should sign the close tx. */
	if (!check_2of2_sig(peer->dstate->secpctx,
			    peer->close_tx, 0,
			    peer->anchor.redeemscript,
			    tal_count(peer->anchor.redeemscript),
			    &peer->them.commitkey, &peer->us.commitkey,
			    &theirsig, &peer->our_close_sig))
		return false;

	/* Complete the close_tx, using signatures. */
	peer->close_tx->input[0].script
		= scriptsig_p2sh_2of2(peer->close_tx,
				      &theirsig, &peer->our_close_sig,
				      &peer->them.commitkey,
				      &peer->us.commitkey);
	peer->close_tx->input[0].script_length
		= tal_count(peer->close_tx->input[0].script);
	return true;
}

Pkt *accept_pkt_close(const tal_t *ctx, struct peer *peer, const Pkt *pkt)
{
	const CloseChannel *c = pkt->close;

	/* FIXME: Don't accept tiny close fee! */
	if (!peer_create_close_tx(peer, c->close_fee))
		return pkt_err(ctx, "Invalid close fee");

	if (!peer_sign_close_tx(peer, c->sig))
		return pkt_err(ctx, "Invalid signature");
	return NULL;
}

Pkt *accept_pkt_close_complete(const tal_t *ctx,
			       struct peer *peer, const Pkt *pkt)
{
	const CloseChannelComplete *c = pkt->close_complete;
	if (!peer_sign_close_tx(peer, c->sig))
		return pkt_err(ctx, "Invalid signature");
	return NULL;
}

Pkt *accept_pkt_simultaneous_close(const tal_t *ctx,
				   struct peer *peer,
				   const Pkt *pkt)
{
	FIXME_STUB(peer);
}

/* FIXME: Since this packet is empty, is it worth having? */
Pkt *accept_pkt_close_ack(const tal_t *ctx, struct peer *peer, const Pkt *pkt)
{
	return NULL;
}
