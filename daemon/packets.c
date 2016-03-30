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
#include <ccan/io/io.h>
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
	printf("%s:%s\n", str, hex_of(NULL, key->der, sizeof(key->der)));
}

/* Wrap (and own!) member inside Pkt */
static Pkt *make_pkt(const tal_t *ctx, Pkt__PktCase type, const void *msg)
{
	Pkt *pkt = tal(ctx, Pkt);

	pkt__init(pkt);
	pkt->pkt_case = type;
	/* This is a union, so doesn't matter which we assign. */
	pkt->error = (Error *)tal_steal(pkt, msg);

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

static void queue_raw_pkt(struct peer *peer, Pkt *pkt)
{
	size_t n = tal_count(peer->outpkt);
	tal_resize(&peer->outpkt, n+1);
	peer->outpkt[n].pkt = pkt;
	peer->outpkt[n].ack_cb = NULL;
	peer->outpkt[n].ack_arg = NULL;

	/* In case it was waiting for output. */
	io_wake(peer);
}

static void queue_pkt(struct peer *peer, Pkt__PktCase type, const void *msg)
{
	queue_raw_pkt(peer, make_pkt(peer, type, msg));
}

void queue_pkt_open(struct peer *peer, OpenChannel__AnchorOffer anchor)
{
	OpenChannel *o = tal(peer, OpenChannel);

	open_channel__init(o);
	o->revocation_hash = sha256_to_proto(o, &peer->us.revocation_hash);
	o->next_revocation_hash = sha256_to_proto(o, &peer->us.next_revocation_hash);
	o->commit_key = pubkey_to_proto(o, &peer->us.commitkey);
	o->final_key = pubkey_to_proto(o, &peer->us.finalkey);
	o->delay = tal(o, Locktime);
	locktime__init(o->delay);
	o->delay->locktime_case = LOCKTIME__LOCKTIME_SECONDS;
	o->delay->seconds = rel_locktime_to_seconds(&peer->us.locktime);
	o->initial_fee_rate = peer->us.commit_fee_rate;
	if (anchor == OPEN_CHANNEL__ANCHOR_OFFER__WILL_CREATE_ANCHOR)
		assert(peer->us.offer_anchor == CMD_OPEN_WITH_ANCHOR);
	else {
		assert(anchor == OPEN_CHANNEL__ANCHOR_OFFER__WONT_CREATE_ANCHOR);
		assert(peer->us.offer_anchor == CMD_OPEN_WITHOUT_ANCHOR);
	}
		
	o->anch = anchor;
	o->min_depth = peer->us.mindepth;
	queue_pkt(peer, PKT__PKT_OPEN, o);
}

void queue_pkt_anchor(struct peer *peer)
{
	struct signature sig;
	OpenAnchor *a = tal(peer, OpenAnchor);

	open_anchor__init(a);
	a->txid = sha256_to_proto(a, &peer->anchor.txid.sha);
	a->output_index = peer->anchor.index;
	a->amount = peer->anchor.satoshis;

	/* Sign their commit sig */
	peer_sign_theircommit(peer, peer->them.commit, &sig);
	a->commit_sig = signature_to_proto(a, &sig);

	queue_pkt(peer, PKT__PKT_OPEN_ANCHOR, a);
}

void queue_pkt_open_commit_sig(struct peer *peer)
{
	struct signature sig;
	OpenCommitSig *s = tal(peer, OpenCommitSig);

	open_commit_sig__init(s);

	dump_tx("Creating sig for:", peer->them.commit);
	dump_key("Using key:", &peer->us.commitkey);

	peer_sign_theircommit(peer, peer->them.commit, &sig);
	s->sig = signature_to_proto(s, &sig);

	queue_pkt(peer, PKT__PKT_OPEN_COMMIT_SIG, s);
}

void queue_pkt_open_complete(struct peer *peer)
{
	OpenComplete *o = tal(peer, OpenComplete);

	open_complete__init(o);
	queue_pkt(peer, PKT__PKT_OPEN_COMPLETE, o);
}

void queue_pkt_htlc_add(struct peer *peer,
		  const struct htlc_progress *htlc_prog)
{
	UpdateAddHtlc *u = tal(peer, UpdateAddHtlc);

	update_add_htlc__init(u);
	assert(htlc_prog->stage.type == HTLC_ADD);

	u->revocation_hash = sha256_to_proto(u, &htlc_prog->our_revocation_hash);
	u->amount_msat = htlc_prog->stage.add.htlc.msatoshis;
	u->r_hash = sha256_to_proto(u, &htlc_prog->stage.add.htlc.rhash);
	u->expiry = abs_locktime_to_proto(u, &htlc_prog->stage.add.htlc.expiry);

	queue_pkt(peer, PKT__PKT_UPDATE_ADD_HTLC, u);
}

void queue_pkt_htlc_fulfill(struct peer *peer,
		      const struct htlc_progress *htlc_prog)
{
	UpdateFulfillHtlc *f = tal(peer, UpdateFulfillHtlc);

	update_fulfill_htlc__init(f);
	assert(htlc_prog->stage.type == HTLC_FULFILL);

	f->revocation_hash = sha256_to_proto(f, &htlc_prog->our_revocation_hash);
	f->r = sha256_to_proto(f, &htlc_prog->stage.fulfill.r);

	queue_pkt(peer, PKT__PKT_UPDATE_FULFILL_HTLC, f);
}

void queue_pkt_htlc_fail(struct peer *peer,
		   const struct htlc_progress *htlc_prog)
{
	UpdateFailHtlc *f = tal(peer, UpdateFailHtlc);
	const struct channel_htlc *htlc;

	update_fail_htlc__init(f);
	assert(htlc_prog->stage.type == HTLC_FAIL);

	htlc = &peer->cstate->b.htlcs[htlc_prog->stage.fail.index];
	f->revocation_hash = sha256_to_proto(f, &htlc_prog->our_revocation_hash);
	f->r_hash = sha256_to_proto(f, &htlc->rhash);

	queue_pkt(peer, PKT__PKT_UPDATE_FAIL_HTLC, f);
}

void queue_pkt_update_accept(struct peer *peer)
{
	UpdateAccept *u = tal(peer, UpdateAccept);
	const struct htlc_progress *cur = peer->current_htlc;
	struct signature sig;

	update_accept__init(u);

	dump_tx("Signing tx", cur->their_commit);
	peer_sign_theircommit(peer, cur->their_commit, &sig);
	u->sig = signature_to_proto(u, &sig);
	u->revocation_hash
		= sha256_to_proto(u, &cur->our_revocation_hash);

	queue_pkt(peer, PKT__PKT_UPDATE_ACCEPT, u);
}

void queue_pkt_update_signature(struct peer *peer)
{
	UpdateSignature *u = tal(peer, UpdateSignature);
	const struct htlc_progress *cur = peer->current_htlc;
	struct signature sig;
	struct sha256 preimage;

	update_signature__init(u);

	peer_sign_theircommit(peer, cur->their_commit, &sig);
	u->sig = signature_to_proto(u, &sig);
	assert(peer->commit_tx_counter > 0);
	peer_get_revocation_preimage(peer, peer->commit_tx_counter-1, &preimage);
	u->revocation_preimage = sha256_to_proto(u, &preimage);

	queue_pkt(peer, PKT__PKT_UPDATE_SIGNATURE, u);
}

void queue_pkt_update_complete(struct peer *peer)
{
	UpdateComplete *u = tal(peer, UpdateComplete);
	struct sha256 preimage;

	update_complete__init(u);

	assert(peer->commit_tx_counter > 0);
	peer_get_revocation_preimage(peer, peer->commit_tx_counter-1, &preimage);
	u->revocation_preimage = sha256_to_proto(u, &preimage);

	queue_pkt(peer, PKT__PKT_UPDATE_COMPLETE, u);
}

Pkt *pkt_err(struct peer *peer, const char *msg, ...)
{
	Error *e = tal(peer, Error);
	va_list ap;

	error__init(e);
	va_start(ap, msg);
	e->problem = tal_vfmt(e, msg, ap);
	va_end(ap);

	return make_pkt(peer, PKT__PKT_ERROR, e);
}

void queue_pkt_err(struct peer *peer, Pkt *err)
{
	queue_raw_pkt(peer, err);
}

void queue_pkt_close_clearing(struct peer *peer)
{
	CloseClearing *c = tal(peer, CloseClearing);

	close_clearing__init(c);

	queue_pkt(peer, PKT__PKT_CLOSE_CLEARING, c);
}

void queue_pkt_close_signature(struct peer *peer)
{
	CloseSignature *c = tal(peer, CloseSignature);
	struct bitcoin_tx *close_tx;
	struct signature our_close_sig;

	close_signature__init(c);
	close_tx = peer_create_close_tx(peer, peer->closing.our_fee);

	peer_sign_mutual_close(peer, close_tx, &our_close_sig);
	c->sig = signature_to_proto(c, &our_close_sig);
	c->close_fee = peer->closing.our_fee;

	queue_pkt(peer, PKT__PKT_CLOSE_SIGNATURE, c);
}

Pkt *pkt_err_unexpected(struct peer *peer, const Pkt *pkt)
{
	return pkt_err(peer, "Unexpected packet %s", state_name(pkt->pkt_case));
}

/* Process various packets: return an error packet on failure. */
Pkt *accept_pkt_open(struct peer *peer, const Pkt *pkt)
{
	struct rel_locktime locktime;
	const OpenChannel *o = pkt->open;

	if (!proto_to_rel_locktime(o->delay, &locktime))
		return pkt_err(peer, "Invalid delay");
	/* FIXME: handle blocks in locktime */
	if (o->delay->locktime_case != LOCKTIME__LOCKTIME_SECONDS)
		return pkt_err(peer, "Delay in blocks not accepted");
	if (o->delay->seconds > peer->dstate->config.rel_locktime_max)
		return pkt_err(peer, "Delay too great");
	if (o->min_depth > peer->dstate->config.anchor_confirms_max)
		return pkt_err(peer, "min_depth too great");
	if (o->initial_fee_rate < peer->dstate->config.commitment_fee_rate_min)
		return pkt_err(peer, "Commitment fee rate too low");
	if (o->anch == OPEN_CHANNEL__ANCHOR_OFFER__WILL_CREATE_ANCHOR)
		peer->them.offer_anchor = CMD_OPEN_WITH_ANCHOR;
	else if (o->anch == OPEN_CHANNEL__ANCHOR_OFFER__WONT_CREATE_ANCHOR)
		peer->them.offer_anchor = CMD_OPEN_WITHOUT_ANCHOR;
	else
		return pkt_err(peer, "Unknown offer anchor value");

	if (peer->them.offer_anchor == peer->us.offer_anchor)
		return pkt_err(peer, "Only one side can offer anchor");

	if (!proto_to_rel_locktime(o->delay, &peer->them.locktime))
		return pkt_err(peer, "Malformed locktime");
	peer->them.mindepth = o->min_depth;
	peer->them.commit_fee_rate = o->initial_fee_rate;
	if (!proto_to_pubkey(peer->dstate->secpctx,
			     o->commit_key, &peer->them.commitkey))
		return pkt_err(peer, "Bad commitkey");
	if (!proto_to_pubkey(peer->dstate->secpctx,
			     o->final_key, &peer->them.finalkey))
		return pkt_err(peer, "Bad finalkey");
	proto_to_sha256(o->revocation_hash, &peer->them.revocation_hash);
	proto_to_sha256(o->next_revocation_hash, &peer->them.next_revocation_hash);

	/* Redeemscript for anchor. */
	peer->anchor.redeemscript
		= bitcoin_redeem_2of2(peer, &peer->us.commitkey,
				      &peer->them.commitkey);
	return NULL;
}

Pkt *accept_pkt_anchor(struct peer *peer, const Pkt *pkt)
{
	const OpenAnchor *a = pkt->open_anchor;

	/* They must be offering anchor for us to try accepting */
	assert(peer->us.offer_anchor == CMD_OPEN_WITHOUT_ANCHOR);
	assert(peer->them.offer_anchor == CMD_OPEN_WITH_ANCHOR);

	proto_to_sha256(a->txid, &peer->anchor.txid.sha);
	peer->anchor.index = a->output_index;
	peer->anchor.satoshis = a->amount;

	/* Create our cstate. */
	peer->cstate = initial_funding(peer,
				       peer->us.offer_anchor == CMD_OPEN_WITH_ANCHOR,
				       peer->anchor.satoshis,
				       peer->us.commit_fee_rate);
	if (!peer->cstate)
		return pkt_err(peer, "Insufficient funds for fee");

	/* Now we can make initial (unsigned!) commit txs. */
	make_commit_txs(peer, peer,
			&peer->us.revocation_hash,
			&peer->them.revocation_hash,
			peer->cstate,
			&peer->us.commit,
			&peer->them.commit);

	peer->cur_commit.theirsig.stype = SIGHASH_ALL;
	if (!proto_to_signature(a->commit_sig, &peer->cur_commit.theirsig.sig))
		return pkt_err(peer, "Malformed signature");

	/* Their sig should sign our commit tx. */
	if (!check_tx_sig(peer->dstate->secpctx,
			  peer->us.commit, 0,
			  peer->anchor.redeemscript,
			  tal_count(peer->anchor.redeemscript),
			  &peer->them.commitkey,
			  &peer->cur_commit.theirsig))
		return pkt_err(peer, "Bad signature");

	return NULL;
}

Pkt *accept_pkt_open_commit_sig(struct peer *peer, const Pkt *pkt)
{
	const OpenCommitSig *s = pkt->open_commit_sig;

	peer->cur_commit.theirsig.stype = SIGHASH_ALL;
	if (!proto_to_signature(s->sig, &peer->cur_commit.theirsig.sig))
		return pkt_err(peer, "Malformed signature");

	dump_tx("Checking sig for:", peer->us.commit);
	dump_key("Using key:", &peer->them.commitkey);

	/* Their sig should sign our commit tx. */
	if (!check_tx_sig(peer->dstate->secpctx,
			  peer->us.commit, 0,
			  peer->anchor.redeemscript,
			  tal_count(peer->anchor.redeemscript),
			  &peer->them.commitkey,
			  &peer->cur_commit.theirsig))
		return pkt_err(peer, "Bad signature");

	return NULL;
}

Pkt *accept_pkt_open_complete(struct peer *peer, const Pkt *pkt)
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

Pkt *accept_pkt_htlc_add(struct peer *peer, const Pkt *pkt,
			 Pkt **decline)
{
	const UpdateAddHtlc *u = pkt->update_add_htlc;
	struct htlc_progress *cur = tal(peer, struct htlc_progress);
	Pkt *err;

	cur->stage.add.add = HTLC_ADD;
	cur->stage.add.htlc.msatoshis = u->amount_msat;
	proto_to_sha256(u->r_hash, &cur->stage.add.htlc.rhash);
	proto_to_sha256(u->revocation_hash, &cur->their_revocation_hash);
	if (!proto_to_abs_locktime(u->expiry, &cur->stage.add.htlc.expiry)) {
		err = pkt_err(peer, "Invalid HTLC expiry");
		goto fail;
	}

	/* FIXME: Handle block-based expiry! */
	if (!abs_locktime_is_seconds(&cur->stage.add.htlc.expiry)) {
		*decline = decline_htlc(peer, 
					"HTLC expiry in blocks not supported!");
		goto decline;
	}

	if (abs_locktime_to_seconds(&cur->stage.add.htlc.expiry) <
	    controlled_time().ts.tv_sec + peer->dstate->config.min_expiry) {
		*decline = decline_htlc(peer, "HTLC expiry too soon!");
		goto decline;
	}

	if (abs_locktime_to_seconds(&cur->stage.add.htlc.expiry) >
	    controlled_time().ts.tv_sec + peer->dstate->config.max_expiry) {
		*decline = decline_htlc(peer, "HTLC expiry too far!");
		goto decline;
	}

	cur->cstate = copy_funding(cur, peer->cstate);
	if (!funding_b_add_htlc(cur->cstate,
				cur->stage.add.htlc.msatoshis,
				&cur->stage.add.htlc.expiry,
				&cur->stage.add.htlc.rhash, 0)) {
		err = pkt_err(peer, "Cannot afford %"PRIu64" milli-satoshis",
			      cur->stage.add.htlc.msatoshis);
		goto fail;
	}
	peer_add_htlc_expiry(peer, &cur->stage.add.htlc.expiry);
	
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

Pkt *accept_pkt_htlc_fail(struct peer *peer, const Pkt *pkt)
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
		err = pkt_err(peer, "Unknown HTLC");
		goto fail;
	}

	cur->stage.fail.fail = HTLC_FAIL;
	cur->stage.fail.index = i;

	/* We regain HTLC amount */
	cur->cstate = copy_funding(cur, peer->cstate);
	funding_a_fail_htlc(cur->cstate, i);
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

Pkt *accept_pkt_htlc_fulfill(struct peer *peer, const Pkt *pkt)
{
	const UpdateFulfillHtlc *f = pkt->update_fulfill_htlc;
	struct htlc_progress *cur = tal(peer, struct htlc_progress);
	Pkt *err;
	size_t i;
	struct sha256 rhash;

	cur->stage.fulfill.fulfill = HTLC_FULFILL;
	proto_to_sha256(f->r, &cur->stage.fulfill.r);

	proto_to_sha256(f->revocation_hash, &cur->their_revocation_hash);
	sha256(&rhash, &cur->stage.fulfill.r, sizeof(cur->stage.fulfill.r));
	i = funding_find_htlc(&peer->cstate->a, &rhash);
	if (i == tal_count(peer->cstate->a.htlcs)) {
		err = pkt_err(peer, "Unknown HTLC");
		goto fail;
	}
	cur->stage.fulfill.index = i;

	/* Removing it: they gain HTLC amount */
	cur->cstate = copy_funding(cur, peer->cstate);
	funding_a_fulfill_htlc(cur->cstate, i);

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

Pkt *accept_pkt_update_accept(struct peer *peer, const Pkt *pkt)
{
	const UpdateAccept *a = pkt->update_accept;
	struct htlc_progress *cur = peer->current_htlc;
	
	proto_to_sha256(a->revocation_hash, &cur->their_revocation_hash);

	cur->their_sig.stype = SIGHASH_ALL;
	if (!proto_to_signature(a->sig, &cur->their_sig.sig))
		return pkt_err(peer, "Malformed signature");

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
		return pkt_err(peer, "Bad signature");

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

Pkt *accept_pkt_update_complete(struct peer *peer, const Pkt *pkt)
{
	/* FIXME: Check preimage against old tx! */
	return NULL;
}

Pkt *accept_pkt_update_signature(struct peer *peer,
				 const Pkt *pkt)
{
	const UpdateSignature *s = pkt->update_signature;
	struct htlc_progress *cur = peer->current_htlc;

	cur->their_sig.stype = SIGHASH_ALL;
	if (!proto_to_signature(s->sig, &cur->their_sig.sig))
		return pkt_err(peer, "Malformed signature");

	/* Their sig should sign our new commit tx. */
	if (!check_tx_sig(peer->dstate->secpctx,
			  cur->our_commit, 0,
			  peer->anchor.redeemscript,
			  tal_count(peer->anchor.redeemscript),
			  &peer->them.commitkey,
			  &cur->their_sig))
		return pkt_err(peer, "Bad signature");

	/* Check their revocation preimage. */
	if (!check_preimage(s->revocation_preimage, &peer->them.revocation_hash))
		return pkt_err(peer, "Bad revocation preimage");

	/* Our next step will be to send the revocation preimage, so
	 * update to new HTLC now so we never use the old one. */
	update_to_new_htlcs(peer);
	return NULL;
}

Pkt *accept_pkt_close_clearing(struct peer *peer, const Pkt *pkt)
{
	/* FIXME: Reject unknown odd fields? */
	return NULL;
}

Pkt *accept_pkt_close_sig(struct peer *peer, const Pkt *pkt, bool *matches)
{
	const CloseSignature *c = pkt->close_signature;
	struct bitcoin_tx *close_tx;
	struct bitcoin_signature theirsig;

	/* BOLT #2:
	 *
	 * The sender MUST set `close_fee` lower than or equal to the fee of the
	 * final commitment transaction, and MUST set `close_fee` to an even
	 * number of satoshis.
	 */
	if ((c->close_fee & 1)
	    || c->close_fee > commit_tx_fee(peer->them.commit,
					    peer->anchor.satoshis)) {
		return pkt_err(peer, "Invalid close fee");
	}

	/* FIXME: Don't accept tiny fee at all? */

	/* BOLT #2:
	   ... otherwise it SHOULD propose a
	   value strictly between the received `close_fee` and its
	   previously-sent `close_fee`.
	*/
	if (peer->closing.their_sig) {
		/* We want more, they should give more. */
		if (peer->closing.our_fee > peer->closing.their_fee) {
			if (c->close_fee <= peer->closing.their_fee)
				return pkt_err(peer, "Didn't increase close fee");
		} else {
			if (c->close_fee >= peer->closing.their_fee)
				return pkt_err(peer, "Didn't decrease close fee");
		}
	}

	/* BOLT #2:
	 *
	 * The receiver MUST check `sig` is valid for the close
	 * transaction, and MUST fail the connection if it is not. */
	theirsig.stype = SIGHASH_ALL;
	if (!proto_to_signature(c->sig, &theirsig.sig))
		return pkt_err(peer, "Invalid signature format");

	close_tx = peer_create_close_tx(peer, c->close_fee);
	if (!check_tx_sig(peer->dstate->secpctx, close_tx, 0,
			  peer->anchor.redeemscript,
			  tal_count(peer->anchor.redeemscript),
			  &peer->them.commitkey, &theirsig))
		return pkt_err(peer, "Invalid signature");

	tal_free(peer->closing.their_sig);
	peer->closing.their_sig = tal_dup(peer,
					  struct bitcoin_signature, &theirsig);
	peer->closing.their_fee = c->close_fee;

	if (peer->closing.our_fee == peer->closing.their_fee) {
		*matches = true;
	} else {
		/* Adjust our fee to close on their fee. */
		u64 sum;

		/* Beware overflow! */
		sum = (u64)peer->closing.our_fee + peer->closing.their_fee;

		peer->closing.our_fee = sum / 2;
		if (peer->closing.our_fee & 1)
			peer->closing.our_fee++;

		/* FIXME: Fees may *now* be equal, and they'll
		 * consider this an ACK! */
	}
	*matches = false;

	/* FIXME: Dynamic fee! */
	return NULL;
}
