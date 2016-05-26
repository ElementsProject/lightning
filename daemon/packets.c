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

void queue_pkt_open(struct peer *peer, OpenChannel__AnchorOffer anchor)
{
	OpenChannel *o = tal(peer, OpenChannel);

	/* Set up out commit info now: rest gets done in setup_first_commit
	 * once anchor is established. */
	peer->local.commit = talz(peer, struct commit_info);
	peer->local.commit->revocation_hash = peer->local.next_revocation_hash;
	peer_get_revocation_hash(peer, 1, &peer->local.next_revocation_hash);

	open_channel__init(o);
	o->revocation_hash = sha256_to_proto(o, &peer->local.commit->revocation_hash);
	o->next_revocation_hash = sha256_to_proto(o, &peer->local.next_revocation_hash);
	o->commit_key = pubkey_to_proto(o, &peer->local.commitkey);
	o->final_key = pubkey_to_proto(o, &peer->local.finalkey);
	o->delay = tal(o, Locktime);
	locktime__init(o->delay);
	o->delay->locktime_case = LOCKTIME__LOCKTIME_SECONDS;
	o->delay->seconds = rel_locktime_to_seconds(&peer->local.locktime);
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

	/* Sign their commit sig */
	peer->remote.commit->sig = tal(peer->remote.commit,
				     struct bitcoin_signature);
	peer->remote.commit->sig->stype = SIGHASH_ALL;
	peer_sign_theircommit(peer, peer->remote.commit->tx,
			      &peer->remote.commit->sig->sig);
	a->commit_sig = signature_to_proto(a, &peer->remote.commit->sig->sig);

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

	/* BOLT #2:
	 *
	 * The sending node MUST add the HTLC addition to the unacked
	 * changeset for its remote commitment
	 */
	if (!funding_add_htlc(peer->remote.staging_cstate,
			      htlc_prog->stage.add.htlc.msatoshis,
			      &htlc_prog->stage.add.htlc.expiry,
			      &htlc_prog->stage.add.htlc.rhash,
			      htlc_prog->stage.add.htlc.id, THEIRS))
		fatal("Could not add HTLC?");
	add_unacked(&peer->remote, &htlc_prog->stage);

	remote_changes_pending(peer);

	peer_add_htlc_expiry(peer, &htlc_prog->stage.add.htlc.expiry);

	queue_pkt(peer, PKT__PKT_UPDATE_ADD_HTLC, u);
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

	/* BOLT #2:
	 *
	 * The sending node MUST add the HTLC fulfill/fail to the
	 * unacked changeset for its remote commitment
	 */
	n = funding_htlc_by_id(peer->remote.staging_cstate, f->id, OURS);
	assert(n != -1);
	funding_fulfill_htlc(peer->remote.staging_cstate, n, OURS);
	add_unacked(&peer->remote, &htlc_prog->stage);

	remote_changes_pending(peer);

	queue_pkt(peer, PKT__PKT_UPDATE_FULFILL_HTLC, f);
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

	/* BOLT #2:
	 *
	 * The sending node MUST add the HTLC fulfill/fail to the
	 * unacked changeset for its remote commitment
	 */
	n = funding_htlc_by_id(peer->remote.staging_cstate, f->id, OURS);
	assert(n != -1);
	funding_fail_htlc(peer->remote.staging_cstate, n, OURS);
	add_unacked(&peer->remote, &htlc_prog->stage);

	remote_changes_pending(peer);
	queue_pkt(peer, PKT__PKT_UPDATE_FAIL_HTLC, f);
}

/* OK, we're sending a signature for their pending changes. */
void queue_pkt_commit(struct peer *peer)
{
	UpdateCommit *u = tal(peer, UpdateCommit);
	struct commit_info *ci = talz(peer, struct commit_info);

	/* Create new commit info for this commit tx. */
	ci->prev = peer->remote.commit;
	ci->revocation_hash = peer->remote.next_revocation_hash;
	/* BOLT #2:
	 *
	 * A sending node MUST apply all remote acked and unacked
	 * changes except unacked fee changes to the remote commitment
	 * before generating `sig`. */
	ci->cstate = copy_funding(ci, peer->remote.staging_cstate);
	ci->tx = create_commit_tx(ci,
				  &peer->remote.finalkey,
				  &peer->local.finalkey,
				  &peer->local.locktime,
				  &peer->anchor.txid,
				  peer->anchor.index,
				  peer->anchor.satoshis,
				  &ci->revocation_hash,
				  ci->cstate,
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

	peer_check_if_cleared(peer);
	
	/* Now send message */
	update_commit__init(u);
	u->sig = signature_to_proto(u, &ci->sig->sig);
	u->ack = peer_outgoing_ack(peer);

	queue_pkt(peer, PKT__PKT_UPDATE_COMMIT, u);
}

/* At revocation time, we apply the changeset to the other side. */
static void apply_changeset(struct peer *peer,
			    struct peer_visible_state *which,
			    const union htlc_staging *changes,
			    size_t num_changes)
{
	size_t i;
	size_t n;

	for (i = 0; i < num_changes; i++) {
		switch (changes[i].type) {
		case HTLC_ADD:
			n = funding_htlc_by_id(which->staging_cstate,
					       changes[i].add.htlc.id, OURS);
			if (n != -1)
				fatal("Can't add duplicate HTLC id %"PRIu64,
				      changes[i].add.htlc.id);
			if (!funding_add_htlc(which->staging_cstate,
					      changes[i].add.htlc.msatoshis,
					      &changes[i].add.htlc.expiry,
					      &changes[i].add.htlc.rhash,
					      changes[i].add.htlc.id, OURS))
				fatal("Adding HTLC failed");
			continue;
		case HTLC_FAIL:
			n = funding_htlc_by_id(which->staging_cstate,
					       changes[i].fail.id, THEIRS);
			if (n == -1)
				fatal("Can't fail non-exisent HTLC id %"PRIu64,
				      changes[i].fail.id);
			funding_fail_htlc(which->staging_cstate, n, THEIRS);
			continue;
		case HTLC_FULFILL:
			n = funding_htlc_by_id(which->staging_cstate,
					       changes[i].fulfill.id, THEIRS);
			if (n == -1)
				fatal("Can't fulfill non-exisent HTLC id %"PRIu64,
				      changes[i].fulfill.id);
			funding_fulfill_htlc(which->staging_cstate, n, THEIRS);
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

	update_revocation__init(u);

	assert(peer->commit_tx_counter > 0);
	assert(peer->local.commit);
	assert(peer->local.commit->prev);
	assert(!peer->local.commit->prev->revocation_preimage);

	/* We have their signature on the current one, right? */
	assert(peer->local.commit->sig);

	peer->local.commit->prev->revocation_preimage
		= tal(peer->local.commit->prev, struct sha256);
	peer_get_revocation_preimage(peer, peer->commit_tx_counter-1,
				     peer->local.commit->prev->revocation_preimage);
	peer_check_if_cleared(peer);
	u->revocation_preimage
		= sha256_to_proto(u, peer->local.commit->prev->revocation_preimage);

	u->next_revocation_hash = sha256_to_proto(u,
						  &peer->local.next_revocation_hash);
	u->ack = peer_outgoing_ack(peer);

	queue_pkt(peer, PKT__PKT_UPDATE_REVOCATION, u);

	/* BOLT #2:
	 *
	 * The node sending `update_revocation` MUST add the local unacked
	 * changes to the set of remote acked changes.
	 */
	apply_changeset(peer, &peer->remote,
			peer->local.unacked_changes,
			tal_count(peer->local.unacked_changes));

	if (tal_count(peer->local.unacked_changes))
		remote_changes_pending(peer);

	/* Reset for next time. */
	tal_free(peer->local.unacked_changes);
	peer->local.unacked_changes = tal_arr(peer, union htlc_staging, 0);
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
	peer->remote.commit = talz(peer, struct commit_info);
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
			  &peer->remote.commitkey,
			  ci->sig))
		return pkt_err(peer, "Bad signature");

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

	return check_and_save_commit_sig(peer, peer->local.commit, a->commit_sig);
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
	struct channel_htlc *htlc;
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

	/* FIXME: Handle block-based expiry! */
	if (!abs_locktime_is_seconds(&expiry))
		return pkt_err(peer, "HTLC expiry in blocks not supported!");

	/* BOLT #2:
	 *
	 * A node MUST NOT add a HTLC if it would result in it
	 * offering more than 300 HTLCs in either commitment transaction.
	 */
	if (tal_count(peer->remote.staging_cstate->side[OURS].htlcs) == 300
	    || tal_count(peer->local.staging_cstate->side[THEIRS].htlcs) == 300)
		return pkt_err(peer, "Too many HTLCs");

	/* BOLT #2:
	 *
	 * A node MUST NOT set `id` equal to another HTLC which is in
	 * the current staged commitment transaction.
	 */
	if (funding_htlc_by_id(peer->remote.staging_cstate, u->id, OURS) != -1)
		return pkt_err(peer, "HTLC id %"PRIu64" clashes for you", u->id);

	/* FIXME: Assert this... */
	/* Note: these should be in sync, so this should be redundant! */
	if (funding_htlc_by_id(peer->local.staging_cstate, u->id, THEIRS) != -1)
		return pkt_err(peer, "HTLC id %"PRIu64" clashes for us", u->id);

	/* BOLT #2:
	 *
	 * ...and the receiving node MUST add the HTLC addition to the
	 * unacked changeset for its local commitment. */
	htlc = funding_add_htlc(peer->local.staging_cstate,
				u->amount_msat, &expiry, &rhash, u->id, THEIRS);

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
	if (!htlc)
		return pkt_err(peer, "Cannot afford %"PRIu64" milli-satoshis"
			       " in your commitment tx",
			       u->amount_msat);

	stage.add.add = HTLC_ADD;
	stage.add.htlc = *htlc;
	add_unacked(&peer->local, &stage);

	peer_add_htlc_expiry(peer, &expiry);


	/* FIXME: Fees must be sufficient. */
	return NULL;
}

static Pkt *find_commited_htlc(struct peer *peer, uint64_t id, size_t *n_local)
{
	size_t n;

	/* BOLT #2:
	 *
	 * A node MUST check that `id` corresponds to an HTLC in its
	 * current commitment transaction, and MUST fail the
	 * connection if it does not.
	 */
	n = funding_htlc_by_id(peer->local.commit->cstate, id, OURS);
	if (n == -1)
		return pkt_err(peer, "Did not find HTLC %"PRIu64, id);

	/* They must not fail/fulfill twice, so it should be in staging, too. */
	*n_local = funding_htlc_by_id(peer->local.staging_cstate, id, OURS);
	if (*n_local == -1)
		return pkt_err(peer, "Already removed HTLC %"PRIu64, id);

	return NULL;
}

Pkt *accept_pkt_htlc_fail(struct peer *peer, const Pkt *pkt)
{
	const UpdateFailHtlc *f = pkt->update_fail_htlc;
	size_t n_local;
	Pkt *err;
	union htlc_staging stage;

	err = find_commited_htlc(peer, f->id, &n_local);
	if (err)
		return err;

	/* FIXME: Save reason. */

	funding_fail_htlc(peer->local.staging_cstate, n_local, OURS);

	/* BOLT #2:
	 *
	 * ... and the receiving node MUST add the HTLC fulfill/fail
	 * to the unacked changeset for its local commitment.
	 */
	stage.fail.fail = HTLC_FAIL;
	stage.fail.id = f->id;
	add_unacked(&peer->local, &stage);
	return NULL;
}

Pkt *accept_pkt_htlc_fulfill(struct peer *peer, const Pkt *pkt)
{
	const UpdateFulfillHtlc *f = pkt->update_fulfill_htlc;
	size_t n_local;
	struct sha256 r, rhash;
	Pkt *err;
	union htlc_staging stage;

	err = find_commited_htlc(peer, f->id, &n_local);
	if (err)
		return err;

	/* Now, it must solve the HTLC rhash puzzle. */
	proto_to_sha256(f->r, &r);
	sha256(&rhash, &r, sizeof(r));

	if (!structeq(&rhash, &peer->local.staging_cstate->side[OURS].htlcs[n_local].rhash))
		return pkt_err(peer, "Invalid r for %"PRIu64, f->id);

	/* BOLT #2:
	 *
	 * ... and the receiving node MUST add the HTLC fulfill/fail
	 * to the unacked changeset for its local commitment.
	 */
	funding_fulfill_htlc(peer->local.staging_cstate, n_local, OURS);

	stage.fulfill.fulfill = HTLC_FULFILL;
	stage.fulfill.id = f->id;
	stage.fulfill.r = r;
	add_unacked(&peer->local, &stage);
	return NULL;
}

Pkt *accept_pkt_commit(struct peer *peer, const Pkt *pkt)
{
	const UpdateCommit *c = pkt->update_commit;
	Pkt *err;
	struct commit_info *ci = talz(peer, struct commit_info);

	/* Create new commit info for this commit tx. */
	ci->prev = peer->local.commit;
	ci->revocation_hash = peer->local.next_revocation_hash;

	/* BOLT #2:
	 *
	 * A receiving node MUST apply all local acked and unacked
	 * changes except unacked fee changes to the local commitment
	 */
	/* (We already applied them to staging_cstate as we went) */
	ci->cstate = copy_funding(ci, peer->local.staging_cstate);
	ci->tx = create_commit_tx(ci,
				  &peer->local.finalkey,
				  &peer->remote.finalkey,
				  &peer->remote.locktime,
				  &peer->anchor.txid,
				  peer->anchor.index,
				  peer->anchor.satoshis,
				  &ci->revocation_hash,
				  ci->cstate,
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
	peer->commit_tx_counter++;
	peer_get_revocation_hash(peer, peer->commit_tx_counter + 1,
				 &peer->local.next_revocation_hash);

	peer_check_if_cleared(peer);
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

	/* BOLT #2:
	 *
	 * The receiver of `update_revocation` MUST check that the
	 * SHA256 hash of `revocation_preimage` matches the previous commitment
	 * transaction, and MUST fail if it does not.
	 */
	/* FIXME: Save preimage in shachain too. */
	if (!check_preimage(r->revocation_preimage,
			    &peer->remote.commit->prev->revocation_hash))
		return pkt_err(peer, "complete preimage incorrect");

	/* They're revoking the previous one. */
	assert(!peer->remote.commit->prev->revocation_preimage);
	peer->remote.commit->prev->revocation_preimage
		= tal(peer->remote.commit->prev, struct sha256);

	proto_to_sha256(r->revocation_preimage,
			peer->remote.commit->prev->revocation_preimage);
	peer_check_if_cleared(peer);

	/* Save next revocation hash. */
	proto_to_sha256(r->next_revocation_hash,
			&peer->remote.next_revocation_hash);

	/* BOLT #2:
	 *
	 * The receiver of `update_revocation`... MUST add the remote
	 * unacked changes to the set of local acked changes.
	 */
	apply_changeset(peer, &peer->local,
			peer->remote.unacked_changes,
			tal_count(peer->remote.unacked_changes));

	/* Reset for next time. */
	tal_free(peer->remote.unacked_changes);
	peer->remote.unacked_changes = tal_arr(peer, union htlc_staging, 0);

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
	    || c->close_fee > commit_tx_fee(peer->remote.commit->tx,
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
	 * transaction with the given `close_fee`, and MUST fail the
	 * connection if it is not. */
	theirsig.stype = SIGHASH_ALL;
	if (!proto_to_signature(c->sig, &theirsig.sig))
		return pkt_err(peer, "Invalid signature format");

	close_tx = peer_create_close_tx(peer, c->close_fee);
	if (!check_tx_sig(peer->dstate->secpctx, close_tx, 0,
			  NULL, 0,
			  peer->anchor.witnessscript,
			  &peer->remote.commitkey, &theirsig))
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
