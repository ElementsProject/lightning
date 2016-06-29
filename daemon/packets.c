#include "bitcoin/script.h"
#include "bitcoin/tx.h"
#include "close_tx.h"
#include "commit_tx.h"
#include "controlled_time.h"
#include "cryptopkt.h"
#include "htlc.h"
#include "lightningd.h"
#include "log.h"
#include "names.h"
#include "peer.h"
#include "protobuf_convert.h"
#include "secrets.h"
#include "state.h"
#include "utils.h"
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/io/io.h>
#include <ccan/mem/mem.h>
#include <ccan/ptrint/ptrint.h>
#include <ccan/str/hex/hex.h>
#include <ccan/structeq/structeq.h>
#include <ccan/tal/str/str.h>
#include <inttypes.h>

#define FIXME_STUB(peer) do { log_broken((peer)->dstate->base_log, "%s:%u: Implement %s!", __FILE__, __LINE__, __func__); abort(); } while(0)

static void dump_tx(const char *str, const struct bitcoin_tx *tx)
{
	u8 *linear = linearize_tx(NULL, tx);
	printf("%s:%s\n", str, tal_hexstr(linear, linear, tal_count(linear)));
	tal_free(linear);
}

static void dump_key(const char *str, const struct pubkey *key)
{
	printf("%s:%s\n", str, tal_hexstr(NULL, key->der, sizeof(key->der)));
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
	peer->outpkt[n] = pkt;

	log_debug(peer->log, "Queued pkt %s", pkt_name(pkt->pkt_case));

	/* In case it was waiting for output. */
	io_wake(peer);
}

static void queue_pkt(struct peer *peer, Pkt__PktCase type, const void *msg)
{
	queue_raw_pkt(peer, make_pkt(peer, type, msg));
}

static struct commit_info *new_commit_info(const tal_t *ctx)
{
	struct commit_info *ci = talz(ctx, struct commit_info);
	ci->unacked_changes = tal_arr(ci, union htlc_staging, 0);
	ci->acked_changes = tal_arr(ci, union htlc_staging, 0);
	return ci;
}

void queue_pkt_open(struct peer *peer, OpenChannel__AnchorOffer anchor)
{
	OpenChannel *o = tal(peer, OpenChannel);

	/* Set up out commit info now: rest gets done in setup_first_commit
	 * once anchor is established. */
	peer->local.commit = new_commit_info(peer);
	peer->local.commit->revocation_hash = peer->local.next_revocation_hash;
	peer_get_revocation_hash(peer, 1, &peer->local.next_revocation_hash);

	open_channel__init(o);
	o->revocation_hash = sha256_to_proto(o, &peer->local.commit->revocation_hash);
	o->next_revocation_hash = sha256_to_proto(o, &peer->local.next_revocation_hash);
	o->commit_key = pubkey_to_proto(o, &peer->local.commitkey);
	o->final_key = pubkey_to_proto(o, &peer->local.finalkey);
	o->delay = tal(o, Locktime);
	locktime__init(o->delay);
	o->delay->locktime_case = LOCKTIME__LOCKTIME_BLOCKS;
	o->delay->blocks = rel_locktime_to_blocks(&peer->local.locktime);
	o->initial_fee_rate = peer->local.commit_fee_rate;
	if (anchor == OPEN_CHANNEL__ANCHOR_OFFER__WILL_CREATE_ANCHOR)
		assert(peer->local.offer_anchor == CMD_OPEN_WITH_ANCHOR);
	else {
		assert(anchor == OPEN_CHANNEL__ANCHOR_OFFER__WONT_CREATE_ANCHOR);
		assert(peer->local.offer_anchor == CMD_OPEN_WITHOUT_ANCHOR);
	}
		
	o->anch = anchor;
	o->min_depth = peer->local.mindepth;
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

	queue_pkt(peer, PKT__PKT_OPEN_ANCHOR, a);
}

void queue_pkt_open_commit_sig(struct peer *peer)
{
	OpenCommitSig *s = tal(peer, OpenCommitSig);

	open_commit_sig__init(s);

	dump_tx("Creating sig for:", peer->remote.commit->tx);
	dump_key("Using key:", &peer->local.commitkey);

	peer->remote.commit->sig = tal(peer->remote.commit,
				     struct bitcoin_signature);
	peer->remote.commit->sig->stype = SIGHASH_ALL;
	peer_sign_theircommit(peer, peer->remote.commit->tx,
			      &peer->remote.commit->sig->sig);
	s->sig = signature_to_proto(s, &peer->remote.commit->sig->sig);

	queue_pkt(peer, PKT__PKT_OPEN_COMMIT_SIG, s);
}

void queue_pkt_open_complete(struct peer *peer)
{
	OpenComplete *o = tal(peer, OpenComplete);

	open_complete__init(o);
	queue_pkt(peer, PKT__PKT_OPEN_COMPLETE, o);
}

void queue_pkt_htlc_add(struct peer *peer, struct htlc *htlc)
{
	UpdateAddHtlc *u = tal(peer, UpdateAddHtlc);
	union htlc_staging stage;

	update_add_htlc__init(u);

	u->id = htlc->id;
	u->amount_msat = htlc->msatoshis;
	u->r_hash = sha256_to_proto(u, &htlc->rhash);
	u->expiry = abs_locktime_to_proto(u, &htlc->expiry);
	u->route = tal(u, Routing);
	routing__init(u->route);
	u->route->info.data = tal_dup_arr(u, u8,
					  htlc->routing,
					  tal_count(htlc->routing),
					  0);
	u->route->info.len = tal_count(u->route->info.data);

	/* BOLT #2:
	 *
	 * The sending node MUST add the HTLC addition to the unacked
	 * changeset for its remote commitment
	 */
	if (!cstate_add_htlc(peer->remote.staging_cstate, htlc, OURS))
		fatal("Could not add HTLC?");

	stage.add.add = HTLC_ADD;
	stage.add.htlc = htlc;
	add_unacked(&peer->remote, &stage);

	remote_changes_pending(peer);

	queue_pkt(peer, PKT__PKT_UPDATE_ADD_HTLC, u);
}

void queue_pkt_htlc_fulfill(struct peer *peer, struct htlc *htlc,
			    const struct rval *r)
{
	UpdateFulfillHtlc *f = tal(peer, UpdateFulfillHtlc);
	union htlc_staging stage;

	update_fulfill_htlc__init(f);
	f->id = htlc->id;
	f->r = rval_to_proto(f, r);

	/* BOLT #2:
	 *
	 * The sending node MUST add the HTLC fulfill/fail to the
	 * unacked changeset for its remote commitment
	 */
	assert(cstate_htlc_by_id(peer->remote.staging_cstate, f->id, THEIRS)
	       == htlc);
	cstate_fulfill_htlc(peer->remote.staging_cstate, htlc, THEIRS);

	stage.fulfill.fulfill = HTLC_FULFILL;
	stage.fulfill.htlc = htlc;
	stage.fulfill.r = *r;
	add_unacked(&peer->remote, &stage);

	remote_changes_pending(peer);

	queue_pkt(peer, PKT__PKT_UPDATE_FULFILL_HTLC, f);
}

void queue_pkt_htlc_fail(struct peer *peer, struct htlc *htlc)
{
	UpdateFailHtlc *f = tal(peer, UpdateFailHtlc);
	union htlc_staging stage;

	update_fail_htlc__init(f);
	f->id = htlc->id;

	/* FIXME: reason! */
	f->reason = tal(f, FailReason);
	fail_reason__init(f->reason);

	/* BOLT #2:
	 *
	 * The sending node MUST add the HTLC fulfill/fail to the
	 * unacked changeset for its remote commitment
	 */
	assert(cstate_htlc_by_id(peer->remote.staging_cstate, f->id, THEIRS)
	       == htlc);
	cstate_fail_htlc(peer->remote.staging_cstate, htlc, THEIRS);

	stage.fail.fail = HTLC_FAIL;
	stage.fail.htlc = htlc;
	add_unacked(&peer->remote, &stage);

	remote_changes_pending(peer);
	queue_pkt(peer, PKT__PKT_UPDATE_FAIL_HTLC, f);
}

/* OK, we're sending a signature for their pending changes. */
void queue_pkt_commit(struct peer *peer)
{
	UpdateCommit *u = tal(peer, UpdateCommit);
	struct commit_info *ci = new_commit_info(peer);

	/* Create new commit info for this commit tx. */
	ci->prev = peer->remote.commit;
	ci->commit_num = ci->prev->commit_num + 1;
	ci->revocation_hash = peer->remote.next_revocation_hash;
	/* BOLT #2:
	 *
	 * A sending node MUST apply all remote acked and unacked
	 * changes except unacked fee changes to the remote commitment
	 * before generating `sig`. */
	ci->cstate = copy_cstate(ci, peer->remote.staging_cstate);
	ci->tx = create_commit_tx(ci,
				  &peer->local.finalkey,
				  &peer->remote.finalkey,
				  &peer->local.locktime,
				  &peer->remote.locktime,
				  &peer->anchor.txid,
				  peer->anchor.index,
				  peer->anchor.satoshis,
				  &ci->revocation_hash,
				  ci->cstate,
				  THEIRS,
				  &ci->map);

	log_debug(peer->log, "Signing tx for %u/%u msatoshis, %zu/%zu htlcs",
		  ci->cstate->side[OURS].pay_msat,
		  ci->cstate->side[THEIRS].pay_msat,
		  tal_count(ci->cstate->side[OURS].htlcs),
		  tal_count(ci->cstate->side[THEIRS].htlcs));

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
	peer->remote.commit = ci;

	/* Now send message */
	update_commit__init(u);
	u->sig = signature_to_proto(u, &ci->sig->sig);

	queue_pkt(peer, PKT__PKT_UPDATE_COMMIT, u);
}

/* At revocation time, we apply the changeset to the other side. */
static void apply_changeset(struct peer *peer,
			    struct peer_visible_state *which,
			    enum channel_side side,
			    const union htlc_staging *changes,
			    size_t num_changes)
{
	size_t i;
	struct htlc *htlc;

	for (i = 0; i < num_changes; i++) {
		switch (changes[i].type) {
		case HTLC_ADD:
			htlc = cstate_htlc_by_id(which->staging_cstate,
						 changes[i].add.htlc->id, side);
			if (htlc)
				fatal("Can't add duplicate HTLC id %"PRIu64,
				      changes[i].add.htlc->id);
			if (!cstate_add_htlc(which->staging_cstate,
					     changes[i].add.htlc,
					     side))
				fatal("Adding HTLC to %s failed",
				      side == OURS ? "ours" : "theirs");
			continue;
		case HTLC_FAIL:
			htlc = cstate_htlc_by_id(which->staging_cstate,
						 changes[i].fail.htlc->id,
						 !side);
			if (!htlc)
				fatal("Can't fail non-exisent HTLC id %"PRIu64,
				      changes[i].fail.htlc->id);
			cstate_fail_htlc(which->staging_cstate, htlc, !side);
			continue;
		case HTLC_FULFILL:
			htlc = cstate_htlc_by_id(which->staging_cstate,
						  changes[i].fulfill.htlc->id,
						 !side);
			if (!htlc)
				fatal("Can't fulfill non-exisent HTLC id %"PRIu64,
				      changes[i].fulfill.htlc->id);
			cstate_fulfill_htlc(which->staging_cstate, htlc, !side);
			continue;
		}
		abort();
	}
}

/* Send a preimage for the old commit tx.  The one we've just committed to is
 * in peer->local.commit. */
void queue_pkt_revocation(struct peer *peer)
{
	UpdateRevocation *u = tal(peer, UpdateRevocation);
	struct commit_info *ci;

	update_revocation__init(u);

	assert(peer->local.commit);
	ci = peer->local.commit->prev;
	assert(ci);
	assert(!ci->revocation_preimage);

	/* We have their signature on the current one, right? */
	assert(peer->local.commit->sig);

	ci->revocation_preimage = tal(ci, struct sha256);
	peer_get_revocation_preimage(peer, ci->commit_num,
				     ci->revocation_preimage);

	u->revocation_preimage = sha256_to_proto(u, ci->revocation_preimage);

	u->next_revocation_hash = sha256_to_proto(u,
						  &peer->local.next_revocation_hash);

	queue_pkt(peer, PKT__PKT_UPDATE_REVOCATION, u);

	/* BOLT #2:
	 *
	 * The node sending `update_revocation` MUST add the local unacked
	 * changes to the set of remote acked changes.
	 */
	/* Note: this means the unacked changes as of the commit we're
	 * revoking */
	add_acked_changes(&peer->remote.commit->acked_changes, ci->unacked_changes);
	apply_changeset(peer, &peer->remote, THEIRS,
			ci->unacked_changes, tal_count(ci->unacked_changes));

	if (tal_count(ci->unacked_changes))
		remote_changes_pending(peer);

	/* We should never look at this again. */
	ci->unacked_changes = tal_free(ci->unacked_changes);

	/* That revocation has committed us to changes in the current commitment.
	 * Any acked changes come from their commitment, so those are now committed
	 * by both of us.
	 */
	peer_both_committed_to(peer, ci->acked_changes, OURS);
}

Pkt *pkt_err(struct peer *peer, const char *msg, ...)
{
	Error *e = tal(peer, Error);
	va_list ap;

	error__init(e);
	va_start(ap, msg);
	e->problem = tal_vfmt(e, msg, ap);
	va_end(ap);

	log_unusual(peer->log, "Sending PKT_ERROR: %s", e->problem);
	return make_pkt(peer, PKT__PKT_ERROR, e);
}

void queue_pkt_err(struct peer *peer, Pkt *err)
{
	queue_raw_pkt(peer, err);
}

void queue_pkt_close_clearing(struct peer *peer)
{
	u8 *redeemscript;
	CloseClearing *c = tal(peer, CloseClearing);

	close_clearing__init(c);
	redeemscript = bitcoin_redeem_single(c, &peer->local.finalkey);
	peer->closing.our_script = scriptpubkey_p2sh(peer, redeemscript);

	c->scriptpubkey.data = tal_dup_arr(c, u8,
					   peer->closing.our_script,
					   tal_count(peer->closing.our_script),
					   0);
	c->scriptpubkey.len = tal_count(c->scriptpubkey.data);

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
	return pkt_err(peer, "Unexpected packet %s", pkt_name(pkt->pkt_case));
}

/* Process various packets: return an error packet on failure. */
Pkt *accept_pkt_open(struct peer *peer, const Pkt *pkt)
{
	struct rel_locktime locktime;
	const OpenChannel *o = pkt->open;

	if (!proto_to_rel_locktime(o->delay, &locktime))
		return pkt_err(peer, "Invalid delay");
	if (o->delay->locktime_case != LOCKTIME__LOCKTIME_BLOCKS)
		return pkt_err(peer, "Delay in seconds not accepted");
	if (o->delay->blocks > peer->dstate->config.locktime_max)
		return pkt_err(peer, "Delay too great");
	if (o->min_depth > peer->dstate->config.anchor_confirms_max)
		return pkt_err(peer, "min_depth too great");
	if (o->initial_fee_rate < peer->dstate->config.commitment_fee_rate_min)
		return pkt_err(peer, "Commitment fee rate too low");
	if (o->anch == OPEN_CHANNEL__ANCHOR_OFFER__WILL_CREATE_ANCHOR)
		peer->remote.offer_anchor = CMD_OPEN_WITH_ANCHOR;
	else if (o->anch == OPEN_CHANNEL__ANCHOR_OFFER__WONT_CREATE_ANCHOR)
		peer->remote.offer_anchor = CMD_OPEN_WITHOUT_ANCHOR;
	else
		return pkt_err(peer, "Unknown offer anchor value");

	if (peer->remote.offer_anchor == peer->local.offer_anchor)
		return pkt_err(peer, "Only one side can offer anchor");

	if (!proto_to_rel_locktime(o->delay, &peer->remote.locktime))
		return pkt_err(peer, "Malformed locktime");
	peer->remote.mindepth = o->min_depth;
	peer->remote.commit_fee_rate = o->initial_fee_rate;
	if (!proto_to_pubkey(peer->dstate->secpctx,
			     o->commit_key, &peer->remote.commitkey))
		return pkt_err(peer, "Bad commitkey");
	if (!proto_to_pubkey(peer->dstate->secpctx,
			     o->final_key, &peer->remote.finalkey))
		return pkt_err(peer, "Bad finalkey");

	/* Set up their commit info now: rest gets done in setup_first_commit
	 * once anchor is established. */
	peer->remote.commit = new_commit_info(peer);
	proto_to_sha256(o->revocation_hash, &peer->remote.commit->revocation_hash);
	proto_to_sha256(o->next_revocation_hash,
			&peer->remote.next_revocation_hash);

	/* Witness script for anchor. */
	peer->anchor.witnessscript
		= bitcoin_redeem_2of2(peer, &peer->local.commitkey,
				      &peer->remote.commitkey);
	return NULL;
}

/* Save and check signature. */
static Pkt *check_and_save_commit_sig(struct peer *peer,
				      struct commit_info *ci,
				      const Signature *pb)
{
	struct bitcoin_signature *sig = tal(ci, struct bitcoin_signature);

	assert(!ci->sig);
	sig->stype = SIGHASH_ALL;
	if (!proto_to_signature(pb, &sig->sig))
		return pkt_err(peer, "Malformed signature");

	log_debug(peer->log, "Checking sig for %u/%u msatoshis, %zu/%zu htlcs",
		  ci->cstate->side[OURS].pay_msat,
		  ci->cstate->side[THEIRS].pay_msat,
		  tal_count(ci->cstate->side[OURS].htlcs),
		  tal_count(ci->cstate->side[THEIRS].htlcs));

	/* Their sig should sign our commit tx. */
	if (!check_tx_sig(peer->dstate->secpctx,
			  ci->tx, 0,
			  NULL, 0,
			  peer->anchor.witnessscript,
			  &peer->remote.commitkey,
			  sig))
		return pkt_err(peer, "Bad signature");

	ci->sig = sig;
	return NULL;
}

Pkt *accept_pkt_anchor(struct peer *peer, const Pkt *pkt)
{
	const OpenAnchor *a = pkt->open_anchor;

	/* They must be offering anchor for us to try accepting */
	assert(peer->local.offer_anchor == CMD_OPEN_WITHOUT_ANCHOR);
	assert(peer->remote.offer_anchor == CMD_OPEN_WITH_ANCHOR);

	proto_to_sha256(a->txid, &peer->anchor.txid.sha);
	peer->anchor.index = a->output_index;
	peer->anchor.satoshis = a->amount;

	if (!setup_first_commit(peer))
		return pkt_err(peer, "Insufficient funds for fee");

	return NULL;
}

Pkt *accept_pkt_open_commit_sig(struct peer *peer, const Pkt *pkt)
{
	const OpenCommitSig *s = pkt->open_commit_sig;

	return check_and_save_commit_sig(peer, peer->local.commit, s->sig);
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
	struct htlc *htlc;
	union htlc_staging stage;

	/* BOLT #2:
	 *
	 * `amount_msat` MUST BE greater than 0.
	 */
	if (u->amount_msat == 0)
		return pkt_err(peer, "Invalid amount_msat");

	proto_to_sha256(u->r_hash, &rhash);
	if (!proto_to_abs_locktime(u->expiry, &expiry))
		return pkt_err(peer, "Invalid HTLC expiry");

	if (abs_locktime_is_seconds(&expiry))
		return pkt_err(peer, "HTLC expiry in seconds not supported!");

	/* BOLT #2:
	 *
	 * A node MUST NOT add a HTLC if it would result in it
	 * offering more than 300 HTLCs in either commitment transaction.
	 */
	if (tal_count(peer->remote.staging_cstate->side[THEIRS].htlcs) == 300
	    || tal_count(peer->local.staging_cstate->side[THEIRS].htlcs) == 300)
		return pkt_err(peer, "Too many HTLCs");

	/* BOLT #2:
	 *
	 * A node MUST NOT set `id` equal to another HTLC which is in
	 * any unrevoked commitment transaction.
	 */
	/* Note that it's not *our* problem if they do this, it's
	 * theirs (future confusion).  Nonetheless, we detect and
	 * error for them. */
	if (htlc_map_get(&peer->remote.htlcs, u->id))
		return pkt_err(peer, "HTLC id %"PRIu64" clashes for you", u->id);

	/* BOLT #2:
	 *
	 * ...and the receiving node MUST add the HTLC addition to the
	 * unacked changeset for its local commitment. */
	htlc = peer_new_htlc(peer, u->id, u->amount_msat, &rhash,
			     abs_locktime_to_blocks(&expiry),
			     u->route->info.data, u->route->info.len,
			     NULL, THEIRS);

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
	if (!cstate_add_htlc(peer->local.staging_cstate, htlc, THEIRS)) {
		tal_free(htlc);
		return pkt_err(peer, "Cannot afford %"PRIu64" milli-satoshis"
			       " in your commitment tx",
			       u->amount_msat);
	}

	stage.add.add = HTLC_ADD;
	stage.add.htlc = htlc;
	add_unacked(&peer->local, &stage);

	/* FIXME: Fees must be sufficient. */
	return NULL;
}

static Pkt *find_commited_htlc(struct peer *peer, uint64_t id,
			       struct htlc **local_htlc)
{
	/* BOLT #2:
	 *
	 * A node MUST check that `id` corresponds to an HTLC in its
	 * current commitment transaction, and MUST fail the
	 * connection if it does not.
	 */
	if (!cstate_htlc_by_id(peer->local.commit->cstate, id, OURS))
		return pkt_err(peer, "Did not find HTLC %"PRIu64, id);

	/* They must not fail/fulfill twice, so it should be in staging, too. */
	*local_htlc = cstate_htlc_by_id(peer->local.staging_cstate, id, OURS);
	if (!*local_htlc)
		return pkt_err(peer, "Already removed HTLC %"PRIu64, id);

	return NULL;
}

Pkt *accept_pkt_htlc_fail(struct peer *peer, const Pkt *pkt)
{
	const UpdateFailHtlc *f = pkt->update_fail_htlc;
	struct htlc *htlc;
	Pkt *err;
	union htlc_staging stage;

	err = find_commited_htlc(peer, f->id, &htlc);
	if (err)
		return err;

	/* FIXME: Save reason. */

	cstate_fail_htlc(peer->local.staging_cstate, htlc, OURS);

	/* BOLT #2:
	 *
	 * ... and the receiving node MUST add the HTLC fulfill/fail
	 * to the unacked changeset for its local commitment.
	 */
	stage.fail.fail = HTLC_FAIL;
	stage.fail.htlc = htlc;
	add_unacked(&peer->local, &stage);
	return NULL;
}

Pkt *accept_pkt_htlc_fulfill(struct peer *peer, const Pkt *pkt)
{
	const UpdateFulfillHtlc *f = pkt->update_fulfill_htlc;
	struct htlc *htlc;
	struct sha256 rhash;
	struct rval r;
	Pkt *err;
	union htlc_staging stage;

	err = find_commited_htlc(peer, f->id, &htlc);
	if (err)
		return err;

	/* Now, it must solve the HTLC rhash puzzle. */
	proto_to_rval(f->r, &r);
	sha256(&rhash, &r, sizeof(r));

	if (!structeq(&rhash, &htlc->rhash))
		return pkt_err(peer, "Invalid r for %"PRIu64, f->id);

	/* We can relay this upstream immediately. */
	our_htlc_fulfilled(peer, htlc, &r);

	/* BOLT #2:
	 *
	 * ... and the receiving node MUST add the HTLC fulfill/fail
	 * to the unacked changeset for its local commitment.
	 */
	cstate_fulfill_htlc(peer->local.staging_cstate, htlc, OURS);

	stage.fulfill.fulfill = HTLC_FULFILL;
	stage.fulfill.htlc = htlc;
	stage.fulfill.r = r;
	add_unacked(&peer->local, &stage);
	return NULL;
}

Pkt *accept_pkt_commit(struct peer *peer, const Pkt *pkt)
{
	const UpdateCommit *c = pkt->update_commit;
	Pkt *err;
	struct commit_info *ci = new_commit_info(peer);

	/* Create new commit info for this commit tx. */
	ci->prev = peer->local.commit;
	ci->commit_num = ci->prev->commit_num + 1;
	ci->revocation_hash = peer->local.next_revocation_hash;

	/* BOLT #2:
	 *
	 * A receiving node MUST apply all local acked and unacked
	 * changes except unacked fee changes to the local commitment
	 */
	/* (We already applied them to staging_cstate as we went) */
	ci->cstate = copy_cstate(ci, peer->local.staging_cstate);
	ci->tx = create_commit_tx(ci,
				  &peer->local.finalkey,
				  &peer->remote.finalkey,
				  &peer->local.locktime,
				  &peer->remote.locktime,
				  &peer->anchor.txid,
				  peer->anchor.index,
				  peer->anchor.satoshis,
				  &ci->revocation_hash,
				  ci->cstate,
				  OURS,
				  &ci->map);

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
	peer->local.commit = ci;
	peer_get_revocation_hash(peer, ci->commit_num + 1,
				 &peer->local.next_revocation_hash);

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
	struct commit_info *ci = peer->remote.commit->prev;

	/* BOLT #2:
	 *
	 * The receiver of `update_revocation` MUST check that the
	 * SHA256 hash of `revocation_preimage` matches the previous commitment
	 * transaction, and MUST fail if it does not.
	 */
	if (!check_preimage(r->revocation_preimage, &ci->revocation_hash))
		return pkt_err(peer, "complete preimage incorrect");

	/* They're revoking the previous one. */
	assert(!ci->revocation_preimage);
	ci->revocation_preimage = tal(ci, struct sha256);

	proto_to_sha256(r->revocation_preimage, ci->revocation_preimage);

	// save revocation preimages in shachain
	if (!shachain_add_hash(&peer->their_preimages, 0xFFFFFFFFFFFFFFFFL - ci->commit_num, ci->revocation_preimage))
		return pkt_err(peer, "preimage not next in shachain");

	/* Save next revocation hash. */
	proto_to_sha256(r->next_revocation_hash,
			&peer->remote.next_revocation_hash);

	/* BOLT #2:
	 *
	 * The receiver of `update_revocation`... MUST add the remote
	 * unacked changes to the set of local acked changes.
	 */
	add_acked_changes(&peer->local.commit->acked_changes, ci->unacked_changes);
	apply_changeset(peer, &peer->local, OURS,
			ci->unacked_changes,
			tal_count(ci->unacked_changes));

	/* Should never examine these again. */
	ci->unacked_changes = tal_free(ci->unacked_changes);

	/* That revocation has committed them to changes in the current commitment.
	 * Any acked changes come from our commitment, so those are now committed
	 * by both of us.
	 */
	peer_both_committed_to(peer, ci->acked_changes, THEIRS);
	
	return NULL;
}
	
Pkt *accept_pkt_close_clearing(struct peer *peer, const Pkt *pkt)
{
	const CloseClearing *c = pkt->close_clearing;

	/* FIXME: Filter for non-standardness? */
	peer->closing.their_script = tal_dup_arr(peer, u8,
						 c->scriptpubkey.data,
						 c->scriptpubkey.len, 0);

	return NULL;
}
