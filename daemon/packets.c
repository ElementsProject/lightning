#include "bitcoin/script.h"
#include "bitcoin/tx.h"
#include "close_tx.h"
#include "commit_tx.h"
#include "controlled_time.h"
#include "cryptopkt.h"
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
#include <ccan/ptrint/ptrint.h>
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

static void queue_raw_pkt(struct peer *peer, Pkt *pkt,
			  void (*ack_cb)(struct peer *peer, void *arg),
			  void *ack_arg)
{
	size_t n = tal_count(peer->outpkt);
	tal_resize(&peer->outpkt, n+1);
	peer->outpkt[n].pkt = pkt;
	peer->outpkt[n].ack_cb = ack_cb;
	peer->outpkt[n].ack_arg = ack_arg;

	/* In case it was waiting for output. */
	io_wake(peer);
}

static void queue_pkt(struct peer *peer, Pkt__PktCase type, const void *msg)
{
	queue_raw_pkt(peer, make_pkt(peer, type, msg), NULL, NULL);
}

static void queue_pkt_with_ack(struct peer *peer, Pkt__PktCase type,
			       const void *msg,
			       void (*ack_cb)(struct peer *peer, void *arg),
			       void *ack_arg)
{
	queue_raw_pkt(peer, make_pkt(peer, type, msg), ack_cb, ack_arg);
}

void queue_pkt_open(struct peer *peer, OpenChannel__AnchorOffer anchor)
{
	OpenChannel *o = tal(peer, OpenChannel);

	/* Set up out commit info now: rest gets done in setup_first_commit
	 * once anchor is established. */
	peer->us.commit = talz(peer, struct commit_info);
	peer->us.commit->revocation_hash = peer->us.next_revocation_hash;
	peer_get_revocation_hash(peer, 1, &peer->us.next_revocation_hash);

	open_channel__init(o);
	o->revocation_hash = sha256_to_proto(o, &peer->us.commit->revocation_hash);
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
	OpenAnchor *a = tal(peer, OpenAnchor);

	open_anchor__init(a);
	a->txid = sha256_to_proto(a, &peer->anchor.txid.sha);
	a->output_index = peer->anchor.index;
	a->amount = peer->anchor.satoshis;

	/* This shouldn't happen! */
	if (!setup_first_commit(peer)) {
		queue_pkt_err(peer,
			      pkt_err(peer,
				      "Own anchor has insufficient funds"));
		return;
	}

	/* Sign their commit sig */
	peer->them.commit->sig = tal(peer->them.commit,
				     struct bitcoin_signature);
	peer->them.commit->sig->stype = SIGHASH_ALL;
	peer_sign_theircommit(peer, peer->them.commit->tx,
			      &peer->them.commit->sig->sig);
	a->commit_sig = signature_to_proto(a, &peer->them.commit->sig->sig);

	queue_pkt(peer, PKT__PKT_OPEN_ANCHOR, a);
}

void queue_pkt_open_commit_sig(struct peer *peer)
{
	OpenCommitSig *s = tal(peer, OpenCommitSig);

	open_commit_sig__init(s);

	dump_tx("Creating sig for:", peer->them.commit->tx);
	dump_key("Using key:", &peer->us.commitkey);

	peer->them.commit->sig = tal(peer->them.commit,
				     struct bitcoin_signature);
	peer->them.commit->sig->stype = SIGHASH_ALL;
	peer_sign_theircommit(peer, peer->them.commit->tx,
			      &peer->them.commit->sig->sig);
	s->sig = signature_to_proto(s, &peer->them.commit->sig->sig);

	queue_pkt(peer, PKT__PKT_OPEN_COMMIT_SIG, s);
}

void queue_pkt_open_complete(struct peer *peer)
{
	OpenComplete *o = tal(peer, OpenComplete);

	open_complete__init(o);
	queue_pkt(peer, PKT__PKT_OPEN_COMPLETE, o);
}

/* Once they ack, we can add it on our side. */
static void add_our_htlc_ourside(struct peer *peer, void *arg)
{
	struct channel_htlc *htlc = arg;

	/* FIXME: must add even if can't pay fee any more! */
	if (!funding_a_add_htlc(peer->us.staging_cstate,
				htlc->msatoshis, &htlc->expiry,
				&htlc->rhash, htlc->id))
		fatal("FIXME: Failed to add htlc %"PRIu64" to self on ack",
		      htlc->id);
	tal_free(htlc);
}

void queue_pkt_htlc_add(struct peer *peer,
		  const struct htlc_progress *htlc_prog)
{
	UpdateAddHtlc *u = tal(peer, UpdateAddHtlc);

	update_add_htlc__init(u);
	assert(htlc_prog->stage.type == HTLC_ADD);

	u->id = htlc_prog->stage.add.htlc.id;
	u->amount_msat = htlc_prog->stage.add.htlc.msatoshis;
	u->r_hash = sha256_to_proto(u, &htlc_prog->stage.add.htlc.rhash);
	u->expiry = abs_locktime_to_proto(u, &htlc_prog->stage.add.htlc.expiry);
	/* FIXME: routing! */
	u->route = tal(u, Routing);
	routing__init(u->route);

	/* We're about to send this, so their side will have it from now on. */
	if (!funding_b_add_htlc(peer->them.staging_cstate,
				htlc_prog->stage.add.htlc.msatoshis,
				&htlc_prog->stage.add.htlc.expiry,
				&htlc_prog->stage.add.htlc.rhash,
				htlc_prog->stage.add.htlc.id))
		fatal("Could not add HTLC?");

	peer_add_htlc_expiry(peer, &htlc_prog->stage.add.htlc.expiry);
	
	queue_pkt_with_ack(peer, PKT__PKT_UPDATE_ADD_HTLC, u,
			   add_our_htlc_ourside,
			   tal_dup(peer, struct channel_htlc,
				   &htlc_prog->stage.add.htlc));
}

/* Once they ack, we can fulfill it on our side. */
static void fulfill_their_htlc_ourside(struct peer *peer, void *arg)
{
	size_t n;

	n = funding_htlc_by_id(&peer->us.staging_cstate->b, ptr2int(arg));
	funding_b_fulfill_htlc(peer->us.staging_cstate, n);
}

void queue_pkt_htlc_fulfill(struct peer *peer,
		      const struct htlc_progress *htlc_prog)
{
	UpdateFulfillHtlc *f = tal(peer, UpdateFulfillHtlc);
	size_t n;

	update_fulfill_htlc__init(f);
	assert(htlc_prog->stage.type == HTLC_FULFILL);

	f->id = htlc_prog->stage.fulfill.id;
	f->r = sha256_to_proto(f, &htlc_prog->stage.fulfill.r);

	/* We're about to send this, so their side will have it from now on. */
	n = funding_htlc_by_id(&peer->them.staging_cstate->a, f->id);
	funding_a_fulfill_htlc(peer->them.staging_cstate, n);

	queue_pkt_with_ack(peer, PKT__PKT_UPDATE_FULFILL_HTLC, f,
			   fulfill_their_htlc_ourside, int2ptr(f->id));
}

/* Once they ack, we can fail it on our side. */
static void fail_their_htlc_ourside(struct peer *peer, void *arg)
{
	size_t n;

	n = funding_htlc_by_id(&peer->us.staging_cstate->b, ptr2int(arg));
	funding_b_fail_htlc(peer->us.staging_cstate, n);
}

void queue_pkt_htlc_fail(struct peer *peer,
		   const struct htlc_progress *htlc_prog)
{
	UpdateFailHtlc *f = tal(peer, UpdateFailHtlc);
	size_t n;

	update_fail_htlc__init(f);
	assert(htlc_prog->stage.type == HTLC_FAIL);

	f->id = htlc_prog->stage.fail.id;
	/* FIXME: reason! */
	f->reason = tal(f, FailReason);
	fail_reason__init(f->reason);

	/* We're about to send this, so their side will have it from now on. */
	n = funding_htlc_by_id(&peer->them.staging_cstate->a, f->id);
	funding_a_fail_htlc(peer->them.staging_cstate, n);

	queue_pkt_with_ack(peer, PKT__PKT_UPDATE_FAIL_HTLC, f,
			   fail_their_htlc_ourside, int2ptr(f->id));
}

/* OK, we're sending a signature for their pending changes. */
void queue_pkt_commit(struct peer *peer)
{
	UpdateCommit *u = tal(peer, UpdateCommit);
	struct commit_info *ci = talz(peer, struct commit_info);

	/* Create new commit info for this commit tx. */
	ci->prev = peer->them.commit;
	ci->revocation_hash = peer->them.next_revocation_hash;
	ci->cstate = copy_funding(ci, peer->them.staging_cstate);
	ci->tx = create_commit_tx(ci,
				  &peer->them.finalkey,
				  &peer->us.finalkey,
				  &peer->us.locktime,
				  &peer->anchor.txid,
				  peer->anchor.index,
				  peer->anchor.satoshis,
				  &ci->revocation_hash,
				  ci->cstate);

	log_debug(peer->log, "Signing tx for %u/%u msatoshis, %zu/%zu htlcs",
		  ci->cstate->a.pay_msat,
		  ci->cstate->b.pay_msat,
		  tal_count(ci->cstate->a.htlcs),
		  tal_count(ci->cstate->b.htlcs));

	/* BOLT #2:
	 *
	 * A node MUST NOT send an `update_commit` message which does
	 * not include any updates.
	 */
	assert(ci->prev->cstate->changes != ci->cstate->changes);

	ci->sig = tal(ci, struct bitcoin_signature);
	ci->sig->stype = SIGHASH_ALL;
	peer_sign_theircommit(peer, ci->tx, &ci->sig->sig);

	/* Switch to the new commitment. */
	peer->them.commit = ci;

	/* Now send message */
	update_commit__init(u);
	u->sig = signature_to_proto(u, &ci->sig->sig);
	u->ack = peer_outgoing_ack(peer);

	queue_pkt(peer, PKT__PKT_UPDATE_COMMIT, u);
}

/* Send a preimage for the old commit tx.  The one we've just committed to is
 * in peer->us.commit. */
void queue_pkt_revocation(struct peer *peer)
{
	UpdateRevocation *u = tal(peer, UpdateRevocation);

	update_revocation__init(u);

	assert(peer->commit_tx_counter > 0);
	assert(peer->us.commit);
	assert(peer->us.commit->prev);
	assert(!peer->us.commit->prev->revocation_preimage);

	/* We have their signature on the current one, right? */
	assert(peer->us.commit->sig);

	peer->us.commit->prev->revocation_preimage
		= tal(peer->us.commit->prev, struct sha256);
	peer_get_revocation_preimage(peer, peer->commit_tx_counter-1,
				     peer->us.commit->prev->revocation_preimage);
	u->revocation_preimage
		= sha256_to_proto(u, peer->us.commit->prev->revocation_preimage);

	u->next_revocation_hash = sha256_to_proto(u,
						  &peer->us.next_revocation_hash);
	u->ack = peer_outgoing_ack(peer);

	queue_pkt(peer, PKT__PKT_UPDATE_REVOCATION, u);
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
	queue_raw_pkt(peer, err, NULL, NULL);
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
	log_info(peer->log, "queue_pkt_close_signature: offered close fee %"
		 PRIu64, c->close_fee);

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

	/* Set up their commit info now: rest gets done in setup_first_commit
	 * once anchor is established. */
	peer->them.commit = talz(peer, struct commit_info);
	proto_to_sha256(o->revocation_hash, &peer->them.commit->revocation_hash);
	proto_to_sha256(o->next_revocation_hash,
			&peer->them.next_revocation_hash);

	/* Witness script for anchor. */
	peer->anchor.witnessscript
		= bitcoin_redeem_2of2(peer, &peer->us.commitkey,
				      &peer->them.commitkey);
	return NULL;
}

/* Save and check signature. */
static Pkt *check_and_save_commit_sig(struct peer *peer,
				      struct commit_info *ci,
				      const Signature *pb)
{
	assert(!ci->sig);
	ci->sig = tal(ci, struct bitcoin_signature);
	ci->sig->stype = SIGHASH_ALL;
	if (!proto_to_signature(pb, &ci->sig->sig))
		return pkt_err(peer, "Malformed signature");

	/* Their sig should sign our commit tx. */
	if (!check_tx_sig(peer->dstate->secpctx,
			  ci->tx, 0,
			  NULL, 0,
			  peer->anchor.witnessscript,
			  &peer->them.commitkey,
			  ci->sig))
		return pkt_err(peer, "Bad signature");

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

	if (!setup_first_commit(peer))
		return pkt_err(peer, "Insufficient funds for fee");

	return check_and_save_commit_sig(peer, peer->us.commit, a->commit_sig);
}

Pkt *accept_pkt_open_commit_sig(struct peer *peer, const Pkt *pkt)
{
	const OpenCommitSig *s = pkt->open_commit_sig;

	return check_and_save_commit_sig(peer, peer->us.commit, s->sig);
}

Pkt *accept_pkt_open_complete(struct peer *peer, const Pkt *pkt)
{
	return NULL;
}

/*
 * We add changes to both our staging cstate (as they did when they sent
 * it) and theirs (as they will when we ack it).
 */
Pkt *accept_pkt_htlc_add(struct peer *peer, const Pkt *pkt)
{
	const UpdateAddHtlc *u = pkt->update_add_htlc;
	struct sha256 rhash;
	struct abs_locktime expiry;

	/* BOLT #2:
	 *
	 * `amount_msat` MUST BE greater than 0.
	 */
	if (u->amount_msat == 0)
		return pkt_err(peer, "Invalid amount_msat");

	proto_to_sha256(u->r_hash, &rhash);
	if (!proto_to_abs_locktime(u->expiry, &expiry))
		return pkt_err(peer, "Invalid HTLC expiry");

	/* FIXME: Handle block-based expiry! */
	if (!abs_locktime_is_seconds(&expiry))
		return pkt_err(peer, "HTLC expiry in blocks not supported!");

	/* BOLT #2:
	 *
	 * A node MUST NOT add a HTLC if it would result in it
	 * offering more than 1500 HTLCs in either commitment transaction.
	 */
	if (tal_count(peer->them.staging_cstate->a.htlcs) == 1500
	    || tal_count(peer->us.staging_cstate->b.htlcs) == 1500)
		return pkt_err(peer, "Too many HTLCs");

	/* BOLT #2:
	 *
	 * A node MUST NOT set `id` equal to another HTLC which is in
	 * the current staged commitment transaction.
	 */
	if (funding_htlc_by_id(&peer->them.staging_cstate->a, u->id)
	    < tal_count(peer->them.staging_cstate->a.htlcs))
		return pkt_err(peer, "HTLC id %"PRIu64" clashes for you", u->id);

	/* FIXME: Assert this... */
	/* Note: these should be in sync, so this should be redundant! */
	if (funding_htlc_by_id(&peer->us.staging_cstate->b, u->id)
	    < tal_count(peer->us.staging_cstate->b.htlcs))
		return pkt_err(peer, "HTLC id %"PRIu64" clashes for us", u->id);

	/* BOLT #2:
	 *
	 * A node MUST NOT offer `amount_msat` it cannot pay for in
	 * both commitment transactions at the current `fee_rate` (see
	 * "Fee Calculation" ).  A node SHOULD fail the connection if
	 * this occurs.
	 */

	/* FIXME: This is wrong!  We may have already added more txs to
	 * them.staging_cstate, driving that fee up.
	 * We should check against the last version they acknowledged. */
	if (!funding_a_add_htlc(peer->them.staging_cstate,
				u->amount_msat, &expiry, &rhash, u->id))
		return pkt_err(peer, "Cannot afford %"PRIu64" milli-satoshis"
			       " in your commitment tx",
			       u->amount_msat);

	/* If we fail here, we've already changed them.staging_cstate, so
	 * MUST terminate. */
	if (!funding_b_add_htlc(peer->us.staging_cstate,
				u->amount_msat, &expiry, &rhash, u->id))
		return pkt_err(peer, "Cannot afford %"PRIu64" milli-satoshis"
			       " in our commitment tx",
			       u->amount_msat);

	peer_add_htlc_expiry(peer, &expiry);

	/* FIXME: Fees must be sufficient. */
	return NULL;
}

static Pkt *find_commited_htlc(struct peer *peer, uint64_t id,
			       size_t *n_us, size_t *n_them)
{
	/* BOLT #2:
	 *
	 * A node MUST check that `id` corresponds to an HTLC in its
	 * current commitment transaction, and MUST fail the
	 * connection if it does not.
	 */
	*n_us = funding_htlc_by_id(&peer->us.commit->cstate->a, id);
	if (*n_us == tal_count(peer->us.commit->cstate->a.htlcs))
		return pkt_err(peer, "Did not find HTLC %"PRIu64, id);

	/* They must not fail/fulfill twice, so it should be in staging, too. */
	*n_us = funding_htlc_by_id(&peer->us.staging_cstate->a, id);
	if (*n_us == tal_count(peer->us.staging_cstate->a.htlcs))
		return pkt_err(peer, "Already removed HTLC %"PRIu64, id);

	/* FIXME: Assert this... */
	/* Note: these should match. */
	*n_them = funding_htlc_by_id(&peer->them.staging_cstate->b, id);
	if (*n_them == tal_count(peer->them.staging_cstate->b.htlcs))
		return pkt_err(peer, "Did not find your HTLC %"PRIu64, id);

	return NULL;
}

Pkt *accept_pkt_htlc_fail(struct peer *peer, const Pkt *pkt)
{
	const UpdateFailHtlc *f = pkt->update_fail_htlc;
	size_t n_us, n_them;
	Pkt *err;

	err = find_commited_htlc(peer, f->id, &n_us, &n_them);
	if (err)
		return err;

	/* FIXME: Save reason. */

	funding_a_fail_htlc(peer->us.staging_cstate, n_us);
	funding_b_fail_htlc(peer->them.staging_cstate, n_them);
	return NULL;
}

Pkt *accept_pkt_htlc_fulfill(struct peer *peer, const Pkt *pkt)
{
	const UpdateFulfillHtlc *f = pkt->update_fulfill_htlc;
	size_t n_us, n_them;
	struct sha256 r, rhash;
	Pkt *err;

	err = find_commited_htlc(peer, f->id, &n_us, &n_them);
	if (err)
		return err;

	/* Now, it must solve the HTLC rhash puzzle. */
	proto_to_sha256(f->r, &r);
	sha256(&rhash, &r, sizeof(r));

	if (!structeq(&rhash, &peer->us.staging_cstate->a.htlcs[n_us].rhash))
		return pkt_err(peer, "Invalid r for %"PRIu64, f->id);

	/* Same ID must have same rhash */
	assert(structeq(&rhash, &peer->them.staging_cstate->b.htlcs[n_them].rhash));

	funding_a_fulfill_htlc(peer->us.staging_cstate, n_us);
	funding_b_fulfill_htlc(peer->them.staging_cstate, n_them);
	return NULL;
}

Pkt *accept_pkt_commit(struct peer *peer, const Pkt *pkt)
{
	const UpdateCommit *c = pkt->update_commit;
	Pkt *err;
	struct commit_info *ci = talz(peer, struct commit_info);

	/* Create new commit info for this commit tx. */
	ci->prev = peer->us.commit;
	ci->revocation_hash = peer->us.next_revocation_hash;
	ci->cstate = copy_funding(ci, peer->us.staging_cstate);
	ci->tx = create_commit_tx(ci,
				  &peer->us.finalkey,
				  &peer->them.finalkey,
				  &peer->them.locktime,
				  &peer->anchor.txid,
				  peer->anchor.index,
				  peer->anchor.satoshis,
				  &ci->revocation_hash,
				  ci->cstate);

	/* BOLT #2:
	 *
	 * A node MUST NOT send an `update_commit` message which does
	 * not include any updates.
	 */
	if (ci->prev->cstate->changes == ci->cstate->changes)
		return pkt_err(peer, "Empty commit");
			
	err = check_and_save_commit_sig(peer, ci, c->sig);
	if (err)
		return err;

	/* Switch to the new commitment. */
	peer->us.commit = ci;
	peer->commit_tx_counter++;
	peer_get_revocation_hash(peer, peer->commit_tx_counter + 1,
				 &peer->us.next_revocation_hash);
	return NULL;
}

static bool check_preimage(const Sha256Hash *preimage, const struct sha256 *hash)
{
	struct sha256 h;

	proto_to_sha256(preimage, &h);
	sha256(&h, &h, sizeof(h));
	return structeq(&h, hash);
}

Pkt *accept_pkt_revocation(struct peer *peer, const Pkt *pkt)
{
	const UpdateRevocation *r = pkt->update_revocation;

	/* FIXME: Save preimage in shachain too. */
	if (!check_preimage(r->revocation_preimage,
			    &peer->them.commit->prev->revocation_hash))
		return pkt_err(peer, "complete preimage incorrect");

	/* They're revoking the previous one. */
	assert(!peer->them.commit->prev->revocation_preimage);
	peer->them.commit->prev->revocation_preimage
		= tal(peer->them.commit->prev, struct sha256);

	proto_to_sha256(r->revocation_preimage,
			peer->them.commit->prev->revocation_preimage);

	/* Save next revocation hash. */
	proto_to_sha256(r->next_revocation_hash,
			&peer->them.next_revocation_hash);

	return NULL;
}
	
Pkt *accept_pkt_close_clearing(struct peer *peer, const Pkt *pkt)
{
	/* FIXME: Reject unknown odd fields? */
	return NULL;
}

Pkt *accept_pkt_close_sig(struct peer *peer, const Pkt *pkt, bool *acked,
			  bool *we_agree)
{
	const CloseSignature *c = pkt->close_signature;
	struct bitcoin_tx *close_tx;
	struct bitcoin_signature theirsig;

	log_info(peer->log, "accept_pkt_close_sig: they offered close fee %"
		 PRIu64, c->close_fee);
	*acked = *we_agree = false;

	/* BOLT #2:
	 *
	 * The sender MUST set `close_fee` lower than or equal to the fee of the
	 * final commitment transaction, and MUST set `close_fee` to an even
	 * number of satoshis.
	 */
	if ((c->close_fee & 1)
	    || c->close_fee > commit_tx_fee(peer->them.commit->tx,
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
			  NULL, 0,
			  peer->anchor.witnessscript,
			  &peer->them.commitkey, &theirsig))
		return pkt_err(peer, "Invalid signature");

	tal_free(peer->closing.their_sig);
	peer->closing.their_sig = tal_dup(peer,
					  struct bitcoin_signature, &theirsig);
	peer->closing.their_fee = c->close_fee;

	if (peer->closing.our_fee == peer->closing.their_fee) {
		log_info(peer->log, "accept_pkt_close_sig: That's an ack");
		*acked = true;
	} else {
		/* Adjust our fee to close on their fee. */
		u64 sum;

		/* Beware overflow! */
		sum = (u64)peer->closing.our_fee + peer->closing.their_fee;

		peer->closing.our_fee = sum / 2;
		if (peer->closing.our_fee & 1)
			peer->closing.our_fee++;

		log_info(peer->log, "accept_pkt_close_sig: we change to %"PRIu64,
			 peer->closing.our_fee);

		/* Corner case: we may now agree with them. */
		if (peer->closing.our_fee == peer->closing.their_fee)
			*we_agree = true;
	}

	/* FIXME: Dynamic fee! */
	return NULL;
}
