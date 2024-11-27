/* This is a fake channeld: it doesn't talk to the peer at all, it just
 * pretends to.  It knows secret keys though, for a fake network, and can
 * respond as if we are connected to that network.
 *
 * Example known payment_hashes (0000000..., 0100000..., 020000..., ...  FF0000...):
 *  66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925
 *  01d0fabd251fcbbe2b93b4b927b26ad2a1a99077152e45ded1e678afa45dbec5
 *  5778f985db754c6628691f56fadae50c65fddbe8eb2e93039633fefa05d45e31
 *  91d3827f052f5a4b44d5fe2bed657c752247365d94f80a33cb09c1436a16b125
 *  4b78063b9c224da311bd1d3fb969bba19e7e91ee07b506f9c4c438828915563f
 *  aae761377f3b4f1f07d982783b902314b61a9cbe6ccfdfa96559039f07e332ed
 */
#include "config.h"
#include <bitcoin/script.h>
#include <ccan/crypto/hkdf_sha256/hkdf_sha256.h>
#include <ccan/htable/htable_type.h>
#include <ccan/mem/mem.h>
#include <ccan/tal/str/str.h>
#include <channeld/channeld_wiregen.h>
#include <channeld/full_channel.h>
#include <common/blinding.h>
#include <common/daemon_conn.h>
#include <common/derive_basepoints.h>
#include <common/ecdh.h>
#include <common/gossmap.h>
#include <common/onion_decode.h>
#include <common/status.h>
#include <common/subdaemon.h>
#include <common/timeout.h>
#include <common/wire_error.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <secp256k1_ecdh.h>
#include <stdio.h>
#include <unistd.h>
#include <wire/wire_sync.h>

/* stdin == requests, 3 == peer, 4 = HSM */
#define MASTER_FD STDIN_FILENO
#define PEER_FD 3
#define HSM_FD 4

struct info {
	/* To talk to lightningd */
	struct daemon_conn *dc;
	/* The actual channel (to make sure we can fit!) */
	struct channel *channel;
	/* Cache of privkeys which have proven useful */
	size_t *cached_node_idx;
	/* Gossip map for lookup up our "channels" */
	struct gossmap *gossmap;
	/* To check cltv delays */
	u32 current_block_height;
	/* lightningd wants these when we tell it about a "new commitment" */
	size_t commit_num;
	/* MPP parts we've gathered */
	struct multi_payment **multi_payments;
	/* For MPP timers, delay timers */
	struct timers timers;
	/* Seed for channel feature determination (e.g. delay time) */
	struct siphash_seed seed;
	/* Currently used channels */
	struct reservation **reservations;

	/* Fake stuff we feed into lightningd */
	struct fee_states *fee_states;
	struct height_states *blockheight_states;
	struct bitcoin_tx *commit_tx;
	struct bitcoin_signature fakesig;
	struct sha256 peer_shaseed;
};

/* FIXME: For the ecdh() function called by onion routines */
static size_t current_nodeidx;

/* Core of an outgoing HTLC: freed by succeed() or fail() */
struct fake_htlc {
	/* The HTLC id we assigned this */
	u64 htlc_id;
	/* The payment hash */
	struct sha256 payment_hash;
	/* The shared secrets from each decryption */
	struct secret *secrets;
};

struct payment {
	struct fake_htlc *htlc;
	/* onion payload at the final hop */
	const struct onion_payload *payload;
};

/* To re-combine MPP */
struct multi_payment {
	/* For use in the timeout timer */
	struct info *info;
	/* The key to collect payments by */
	struct sha256 payment_hash;
	/* All the payloads we've gathered */
	struct payment **payments;
};

/* We've taken up some part of a channel */
struct reservation {
	struct short_channel_id_dir scidd;
	struct amount_msat amount;
};

static void make_privkey(size_t idx, struct privkey *pk)
{
	/* pyln-testing uses 'lightning-N' then all zeroes as hsm_secret. */
	if (idx & 1) {
		u32 salt = 0;
		struct secret hsm_secret;
		memset(&hsm_secret, 0, sizeof(hsm_secret));
		snprintf((char *)&hsm_secret, sizeof(hsm_secret),
			 "lightning-%zu", idx >> 1);

		/* This maps hsm_secret -> node privkey */
		hkdf_sha256(pk, sizeof(*pk),
			    &salt, sizeof(salt),
			    &hsm_secret, sizeof(hsm_secret),
			    "nodeid", 6);
		return;
	}

	/* gossmap-compress uses the node index (size_t, native endian), then all ones */
	memset(pk, 1, sizeof(*pk));
	idx >>= 1;
	memcpy(pk, &idx, sizeof(idx));

	struct pubkey pubkey;
	pubkey_from_privkey(pk, &pubkey);
}

static const char *fmt_nodeidx(const tal_t *ctx, size_t idx)
{
	if (idx & 1)
		return tal_fmt(ctx, "lightningd-%zu", idx >> 1);
	return tal_fmt(ctx, "gossmap-node-%zu", idx >> 1);
}

/* Return deterministic value >= min < max for this channel */
static u64 channel_range(const struct info *info,
			 const struct short_channel_id_dir *scidd,
			 u64 min, u64 max)
{
	return min + (siphash24(&info->seed, scidd, sizeof(scidd)) % max);
}

void ecdh(const struct pubkey *point, struct secret *ss)
{
	struct privkey pk;
	make_privkey(current_nodeidx, &pk);
	if (secp256k1_ecdh(secp256k1_ctx, ss->data, &point->pubkey,
			   pk.secret.data, NULL, NULL) != 1)
		abort();
}

static void pretend_got_revoke(struct info *info, u64 htlc_id, enum htlc_state newstate)
{
	struct changed_htlc *changed;
	struct secret secret;
	struct pubkey next_per_commit_point;
	const u8 *msg;

	changed = tal_arr(tmpctx, struct changed_htlc, 1);
	changed->id = htlc_id;
	changed->newstate = newstate;

	if (!per_commit_secret(&info->peer_shaseed,
			       &secret,
			       info->commit_num - 1))
		abort();
	if (!per_commit_point(&info->peer_shaseed,
			      &next_per_commit_point,
			      info->commit_num + 1))
		abort();

	msg = towire_channeld_got_revoke(NULL, info->commit_num - 1, &secret,
					 &next_per_commit_point, info->fee_states,
					 info->blockheight_states, changed,
					 NULL, NULL);
	daemon_conn_send(info->dc, take(msg));
}

/* Tell lightningd that htlc is fully committed. */
static void update_commitment_tx_added(struct info *info, u64 htlc_id)
{
	struct changed_htlc *changed;
	u8 *msg;
	const struct htlc **htlcs = tal_arr(tmpctx, const struct htlc *, 0);

	changed = tal_arr(tmpctx, struct changed_htlc, 1);
	changed->id = htlc_id;
	changed->newstate = SENT_ADD_COMMIT;
	/* Tell it we committed */
	msg = towire_channeld_sending_commitsig(NULL,
						info->commit_num,
						NULL,
						info->fee_states,
						info->blockheight_states,
						changed);
	daemon_conn_send(info->dc, take(msg));

	channel_sending_commit(info->channel, &htlcs);

	/* Tell it we got revoke & ack from them. */
	pretend_got_revoke(info, htlc_id, RCVD_ADD_REVOCATION);

	changed->newstate = RCVD_ADD_ACK_COMMIT;
	msg = towire_channeld_got_commitsig(NULL,
					    info->commit_num,
					    info->fee_states,
					    info->blockheight_states,
					    &info->fakesig,
					    NULL,
					    NULL,
					    NULL,
					    NULL,
					    changed,
					    info->commit_tx,
					    NULL);
	daemon_conn_send(info->dc, take(msg));

	/* Tell full_channel.c the htlc is totally committed. */
	channel_rcvd_revoke_and_ack(info->channel, &htlcs);
	channel_rcvd_commit(info->channel, &htlcs);
	channel_sending_revoke_and_ack(info->channel);

	/* Final change to SENT_ADD_ACK_REVOCATION is implied */
	info->commit_num++;
}

static bool ecdh_maybe_blinding(const struct pubkey *ephemeral_key,
				const struct pubkey *blinding,
				struct secret *ss)
{
	struct pubkey point = *ephemeral_key;

	if (blinding) {
		struct secret hmac;
		struct secret blinding_ss;

		ecdh(blinding, &blinding_ss);
		/* b(i) = HMAC256("blinded_node_id", ss(i)) * k(i) */
		subkey_from_hmac("blinded_node_id", &blinding_ss, &hmac);

		/* We instead tweak the *ephemeral* key from the onion and use
		 * our normal privkey: since hsmd knows only how to ECDH with
		 * our real key */
		if (secp256k1_ec_pubkey_tweak_mul(secp256k1_ctx,
						  &point.pubkey,
						  hmac.data) != 1) {
			return false;
		}
	}
	ecdh(&point, ss);
	return true;
}

static u8 *get_next_onion(const tal_t *ctx, const struct route_step *rs)
{
	switch (rs->nextcase) {
	case ONION_END:
		return NULL;
	case ONION_FORWARD:
		return serialize_onionpacket(ctx, rs->next);
	}
	abort();
}

/* Sets current_nodeidx, *next_onion_packet, *shared_secret and *me, and decodes */
static struct onion_payload *decode_onion(const tal_t *ctx,
					  struct info *info,
					  const u8 onion_routing_packet[],
					  const struct pubkey *path_key,
					  const struct sha256 *payment_hash,
					  struct amount_msat amount,
					  u32 cltv,
					  const struct node_id *expected_id,
					  u8 **next_onion_packet,
					  struct secret *shared_secret,
					  struct gossmap_node **me)
{
	struct onionpacket *op;
	enum onion_wire failcode;
	struct route_step *rs = NULL;
	struct onion_payload *payload;
	u64 failtlvtype;
	size_t failtlvpos;
	struct privkey pk;
	struct pubkey current_pubkey;
	struct node_id current_node_id;
	const char *explanation;

	op = parse_onionpacket(tmpctx, onion_routing_packet,
			       TOTAL_PACKET_SIZE(ROUTING_INFO_SIZE),
			       &failcode);
	if (!op)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Could not parse onion (failcode %u)", failcode);

	/* Try previously-useful keys first */
	for (size_t i = 0; i < tal_count(info->cached_node_idx); i++) {
		current_nodeidx = info->cached_node_idx[i];
		if (!ecdh_maybe_blinding(&op->ephemeralkey, path_key, shared_secret))
			abort();
		rs = process_onionpacket(tmpctx, op, shared_secret,
					 payment_hash->u.u8, sizeof(*payment_hash));
		if (rs)
			break;
	}

	if (!rs) {
		/* Try a new one */
		for (current_nodeidx = 0; current_nodeidx < 100000; current_nodeidx++) {
			if (!ecdh_maybe_blinding(&op->ephemeralkey, path_key, shared_secret))
				abort();
			rs = process_onionpacket(tmpctx, op, shared_secret,
						 payment_hash->u.u8, sizeof(*payment_hash));
			if (rs)
				break;
		}
		if (!rs)
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "Could not find privkey for onion");

		/* Add to cache */
		tal_arr_expand(&info->cached_node_idx, current_nodeidx);
	}

	*next_onion_packet = get_next_onion(ctx, rs);

	payload = onion_decode(tmpctx,
			       rs, path_key,
			       NULL,
			       amount,
			       cltv, &failtlvtype, &failtlvpos, &explanation);
	if (!payload) {
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Failed tlvtype %"PRIu64" at %zu: %s",
			      failtlvtype, failtlvpos, explanation);
	}

	/* Find ourselves in the gossmap, so we know our channels */
	make_privkey(current_nodeidx, &pk);
	pubkey_from_privkey(&pk, &current_pubkey);
	node_id_from_pubkey(&current_node_id, &current_pubkey);

	/* This means pay plugin messed up! */
	if (expected_id && !node_id_eq(expected_id, &current_node_id))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Onion sent to %s, but encrypted to %s",
			      fmt_node_id(tmpctx, expected_id),
			      fmt_node_id(tmpctx, &current_node_id));

	*me = gossmap_find_node(info->gossmap, &current_node_id);
	if (!*me)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Cannot find %s (%s) in gossmap",
			      fmt_nodeidx(tmpctx, current_nodeidx),
			      fmt_node_id(tmpctx, &current_node_id));

	status_debug("Unpacked onion for %s",
		     fmt_nodeidx(tmpctx, current_nodeidx));
	return payload;
}

static void fail(struct info *info,
		 struct fake_htlc *htlc STEALS,
		 const struct onion_payload *payload,
		 enum onion_wire failcode)
{
	struct failed_htlc *failed;
	const struct failed_htlc **failed_arr;
	u8 *msg;
	struct changed_htlc *changed;
	enum channel_remove_err err;

	msg = tal_arr(tmpctx, u8, 0);
	towire_u16(&msg, failcode);

	status_debug("Failing payment at %s due to %s",
		     fmt_nodeidx(tmpctx, current_nodeidx),
		     onion_wire_name(failcode));

	err = channel_fail_htlc(info->channel,
				LOCAL,
				htlc->htlc_id,
				NULL);
	assert(err == CHANNEL_ERR_REMOVE_OK);

	failed_arr = tal_arr(tmpctx, const struct failed_htlc *, 1);
	failed_arr[0] = failed = tal(failed_arr, struct failed_htlc);
	failed->id = htlc->htlc_id;
	failed->sha256_of_onion = NULL;
	failed->onion = create_onionreply(failed, &htlc->secrets[tal_count(htlc->secrets) - 1], msg);

	/* We create backwards, using shared secrets to wrap */
	for (size_t i = tal_count(htlc->secrets) - 1; i >= 0; i--)
		failed->onion = wrap_onionreply(failed, &htlc->secrets[i], failed->onion);

	msg = towire_channeld_got_commitsig(NULL,
					    info->commit_num,
					    info->fee_states,
					    info->blockheight_states,
					    &info->fakesig,
					    NULL,
					    NULL,
					    NULL,
					    failed_arr,
					    NULL,
					    info->commit_tx,
					    NULL);
	daemon_conn_send(info->dc, take(msg));

	changed = tal_arr(tmpctx, struct changed_htlc, 1);
	changed->id = htlc->htlc_id;
	changed->newstate = SENT_REMOVE_ACK_COMMIT;

	/* Tell it we committed, too */
	msg = towire_channeld_sending_commitsig(NULL,
						info->commit_num,
						NULL,
						info->fee_states,
						info->blockheight_states,
						changed);
	daemon_conn_send(info->dc, take(msg));

	/* Tell it we got revoke & ack from them. */
	pretend_got_revoke(info, htlc->htlc_id, RCVD_REMOVE_ACK_REVOCATION);
	info->commit_num++;
	tal_free(htlc);
}

static void destroy_multi_payment(struct multi_payment *mp)
{
	for (size_t i = 0; i < tal_count(mp->info->multi_payments); i++) {
		if (mp->info->multi_payments[i] == mp) {
			tal_arr_remove(&mp->info->multi_payments, i);
			return;
		}
	}
	abort();
}

static void multi_payment_timeout(struct multi_payment *mp)
{
	for (size_t i = 0; i < tal_count(mp->payments); i++) {
		struct payment *p = mp->payments[i];
		fail(mp->info, p->htlc, p->payload, WIRE_MPP_TIMEOUT);
	}
	tal_free(mp);
}

static struct multi_payment *add_payment_part(struct info *info,
					      struct fake_htlc *htlc STEALS,
					      const struct onion_payload *payload STEALS)
{
	struct multi_payment *mp;
	struct payment *p;
	struct amount_msat total;

	for (size_t i = 0; i < tal_count(info->multi_payments); i++) {
		mp = info->multi_payments[i];
		if (sha256_eq(&mp->payment_hash, &htlc->payment_hash)) {
			/* Cannot change total! */
			assert(amount_msat_eq(*mp->payments[0]->payload->total_msat,
					      *payload->total_msat));
			goto found;
		}
	}
	mp = tal(info->multi_payments, struct multi_payment);
	mp->payment_hash = htlc->payment_hash;
	mp->payments = tal_arr(mp, struct payment *, 0);
	mp->info = info;
	tal_arr_expand(&info->multi_payments, mp);
	tal_add_destructor(mp, destroy_multi_payment);

	/* BOLT #4:
	 *   - MUST fail all HTLCs in the HTLC set after some reasonable timeout.
	 *   - SHOULD wait for at least 60 seconds after the initial HTLC.
	 *   - SHOULD use `mpp_timeout` for the failure message.
	 */
	new_reltimer(&info->timers,
		     mp,
		     time_from_sec(60),
		     multi_payment_timeout, mp);

found:
	p = tal(mp, struct payment);
	p->htlc = tal_steal(p, htlc);
	p->payload = tal_steal(p, payload);
	tal_arr_expand(&mp->payments, p);

	/* If amount is enough, return it */
	total = AMOUNT_MSAT(0);
	for (size_t i = 0; i < tal_count(mp->payments); i++) {
		p = mp->payments[i];
		if (!amount_msat_accumulate(&total,
					    p->payload->amt_to_forward))
			abort();
	}

	if (amount_msat_less(total, *mp->payments[0]->payload->total_msat))
		return NULL;

	/* Done! */
	return mp;
}

static void succeed(struct info *info,
		    struct fake_htlc *htlc STEALS,
		    const struct onion_payload *payload,
		    const struct preimage *preimage)
{
	struct changed_htlc *changed;
	struct fulfilled_htlc *fulfilled;
	u8 *msg;
	enum channel_remove_err err;

	err = channel_fulfill_htlc(info->channel,
				   LOCAL,
				   htlc->htlc_id,
				   preimage,
				   NULL);
	status_debug("channel_fulfill_htlc = %i", err);
	assert(err == CHANNEL_ERR_REMOVE_OK);

	fulfilled = tal_arr(tmpctx, struct fulfilled_htlc, 1);
	fulfilled->id = htlc->htlc_id;
	fulfilled->payment_preimage = *preimage;

	msg = towire_channeld_got_commitsig(NULL,
					    info->commit_num,
					    info->fee_states,
					    info->blockheight_states,
					    &info->fakesig,
					    NULL,
					    NULL,
					    fulfilled,
					    NULL,
					    NULL,
					    info->commit_tx,
					    NULL);
	daemon_conn_send(info->dc, take(msg));

	changed = tal_arr(tmpctx, struct changed_htlc, 1);
	changed->id = htlc->htlc_id;
	changed->newstate = SENT_REMOVE_ACK_COMMIT;

	/* Tell it we committed, too */
	msg = towire_channeld_sending_commitsig(NULL,
						info->commit_num,
						NULL,
						info->fee_states,
						info->blockheight_states,
						changed);
	daemon_conn_send(info->dc, take(msg));

	/* Tell it we got revoke & ack from them. */
	pretend_got_revoke(info, htlc->htlc_id, RCVD_REMOVE_ACK_REVOCATION);

	info->commit_num++;
	tal_free(htlc);
}

static void add_mpp(struct info *info,
		    struct fake_htlc *htlc STEALS,
		    const struct onion_payload *payload STEALS)
{
	struct preimage preimage;
	struct multi_payment *mp;

	status_debug("Received payment at %s",
		     fmt_nodeidx(tmpctx, current_nodeidx));
	mp = add_payment_part(info, htlc, payload);
	if (!mp)
		return;

	/* Completed payment.  Guess payment_hash */
	memset(&preimage, 0, sizeof(preimage));
	for (size_t n = 0; n < 256; n++) {
		struct sha256 hash;
		preimage.r[0] = n;
		sha256(&hash, &preimage, sizeof(preimage));
		if (sha256_eq(&hash, &mp->payment_hash)) {
			for (size_t i = 0; i < tal_count(mp->payments); i++) {
				struct payment *p = mp->payments[i];
				succeed(info, p->htlc, p->payload, &preimage);
			}
			tal_free(mp);
			return;
		}
		status_debug("payment_hash %zu = %s",
			     n, fmt_sha256(tmpctx, &hash));
	}

	/* Unknown, fail them all. */
	for (size_t i = 0; i < tal_count(mp->payments); i++) {
		struct payment *p = mp->payments[i];
		fail(info, p->htlc, p->payload,
		     WIRE_INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS);
	}
	tal_free(mp);
}

static void destroy_reservation(struct reservation *r,
				struct info *info)
{
	for (size_t i = 0; i < tal_count(info->reservations); i++) {
		if (info->reservations[i] == r) {
			tal_arr_remove(&info->reservations, i);
			return;
		}
	}
	abort();
}

static void add_reservation(const tal_t *ctx,
			    struct info *info,
			    const struct short_channel_id_dir *scidd,
			    struct amount_msat amount)
{
	struct reservation *r = tal(ctx, struct reservation);
	r->scidd = *scidd;
	r->amount = amount;
	tal_arr_expand(&info->reservations, r);
	tal_add_destructor2(r, destroy_reservation, info);
}

/* We determine capacity for one side, then we derive the other side.
 * Reservations, however, do *not* credit the other side, since
 * they're htlcs in flight.  (We don't update after payments, either!) */
static struct amount_msat calc_capacity(struct info *info,
					const struct gossmap_chan *c,
					const struct short_channel_id_dir *scidd)
{
	struct short_channel_id_dir base_scidd;
	struct amount_msat base_capacity, dynamic_capacity;

	base_scidd.scid = scidd->scid;
	base_scidd.dir = 0;
	base_capacity = gossmap_chan_get_capacity(info->gossmap, c);
	dynamic_capacity = amount_msat(channel_range(info, &base_scidd,
						     0, base_capacity.millisatoshis)); /* Raw: rand function */
	/* Invert capacity if that is backwards */
	if (scidd->dir != base_scidd.dir) {
		if (!amount_msat_sub(&dynamic_capacity, base_capacity, dynamic_capacity))
			abort();
	}

	status_debug("Capacity for %s is %s, dynamic capacity is %s",
		     fmt_short_channel_id_dir(tmpctx, scidd),
		     fmt_amount_msat(tmpctx, base_capacity),
		     fmt_amount_msat(tmpctx, dynamic_capacity));

	/* Take away any reservations */
	for (size_t i = 0; i < tal_count(info->reservations); i++) {
		if (!short_channel_id_dir_eq(&info->reservations[i]->scidd, scidd))
			continue;
		/* We should never use more that we have! */
		if (!amount_msat_sub(&dynamic_capacity,
				     dynamic_capacity,
				     info->reservations[i]->amount))
			abort();
		status_debug("... minus reservation %s",
			     fmt_amount_msat(tmpctx, info->reservations[i]->amount));
	}

	return dynamic_capacity;
}

/* Mutual recursion via timer */
struct delayed_forward {
	struct info *info;
	struct fake_htlc *htlc;
	struct amount_msat amount;
	u32 cltv_expiry;
	const u8 *onion_routing_packet;
	const struct pubkey *path_key;
	struct node_id expected;
};

static void delayed_forward(struct delayed_forward *dfwd);

static void forward_htlc(struct info *info,
			 struct fake_htlc *htlc,
			 struct amount_msat amount,
			 u32 cltv_expiry,
			 const u8 onion_routing_packet[TOTAL_PACKET_SIZE(ROUTING_INFO_SIZE)],
			 const struct pubkey *path_key,
			 const struct node_id *expected)
{
	struct onion_payload *payload;
	u8 *next_onion_packet;
	struct gossmap_node *me;
	struct secret shared_secret;
	struct node_id next;
	struct gossmap_chan *c;
	struct short_channel_id_dir scidd;
	struct amount_msat amt_expected, htlc_min, htlc_max;
	struct pubkey *next_path_key;
	struct oneshot *timer;
	struct delayed_forward *dfwd;
	unsigned int msec_delay;

	/* Decode, and figure out who I am */
	payload = decode_onion(tmpctx,
			       info,
			       onion_routing_packet,
			       path_key,
			       &htlc->payment_hash,
			       amount, cltv_expiry,
			       expected,
			       &next_onion_packet,
			       &shared_secret,
			       &me);

	tal_arr_expand(&htlc->secrets, shared_secret);
	if (!next_onion_packet) {
		if (cltv_expiry < payload->outgoing_cltv) {
			fail(info, htlc, payload,
			     WIRE_FINAL_INCORRECT_CLTV_EXPIRY);
			return;
		}
		if (cltv_expiry < info->current_block_height + 18) {
			fail(info, htlc, payload,
			     WIRE_FINAL_INCORRECT_CLTV_EXPIRY);
			return;
		}

		/* MPP: consume htlc and payload */
		add_mpp(info, htlc, payload);
		return;
	}

	/* Find next node by channel or scid */
	for (size_t i = 0; i < me->num_chans; i++) {
		c = gossmap_nth_chan(info->gossmap, me, i, &scidd.dir);
		/* Get peer on other end */
		gossmap_node_get_id(info->gossmap,
				    gossmap_nth_node(info->gossmap, c,
						     !scidd.dir),
				    &next);
		scidd.scid = gossmap_chan_scid(info->gossmap, c);
		if (payload->forward_channel) {
			if (short_channel_id_eq(scidd.scid,
						*payload->forward_channel)) {
				goto found_next;
			}
		} else {
			struct node_id fwd;
			node_id_from_pubkey(&fwd, payload->forward_node_id);
			if (node_id_eq(&next, &fwd))
				goto found_next;
		}
	}
	fail(info, htlc, payload, WIRE_UNKNOWN_NEXT_PEER);
	return;

found_next:
	/* CLTV delta and fees must be correct */
	if (!gossmap_chan_set(c, scidd.dir)) {
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Channel used %s is not set?",
			      fmt_short_channel_id_dir(tmpctx, &scidd));
	}
	if (payload->outgoing_cltv + c->half[scidd.dir].delay < cltv_expiry) {
		status_broken("%s: incoming cltv %u (delay=%u), but outgoing %u",
			      fmt_short_channel_id_dir(tmpctx, &scidd),
			      cltv_expiry,
			      c->half[scidd.dir].delay,
			      payload->outgoing_cltv);
		fail(info, htlc, payload, WIRE_INCORRECT_CLTV_EXPIRY);
		return;
	}
	amt_expected = payload->amt_to_forward;
	if (!amount_msat_add_fee(&amt_expected,
				 c->half[scidd.dir].base_fee,
				 c->half[scidd.dir].proportional_fee))
		abort();
	if (amount_msat_less(amount, amt_expected)) {
		status_broken("%s: expected %s (base=%u, prop=%u), but got %s to fwd %s",
			      fmt_short_channel_id_dir(tmpctx, &scidd),
			      fmt_amount_msat(tmpctx, amt_expected),
			      c->half[scidd.dir].base_fee,
			      c->half[scidd.dir].proportional_fee,
			      fmt_amount_msat(tmpctx, amount),
			      fmt_amount_msat(tmpctx, payload->amt_to_forward));
		fail(info, htlc, payload, WIRE_FEE_INSUFFICIENT);
		return;
	}

	/* Obey our HTLC rules please! */
	gossmap_chan_get_update_details(info->gossmap, c, scidd.dir,
					NULL, NULL, NULL, NULL, NULL, NULL,
					&htlc_min, &htlc_max);
	if (amount_msat_less(payload->amt_to_forward, htlc_min)) {
		status_broken("Amount %s is below minimum (%s) for %s!",
			      fmt_amount_msat(tmpctx, payload->amt_to_forward),
			      fmt_amount_msat(tmpctx, htlc_min),
			      fmt_short_channel_id_dir(tmpctx, &scidd));
		fail(info, htlc, payload, WIRE_AMOUNT_BELOW_MINIMUM);
		return;
	}

	if (amount_msat_greater(payload->amt_to_forward, htlc_max)) {
		status_broken("Amount %s is above maximum (%s) for %s!",
			      fmt_amount_msat(tmpctx, payload->amt_to_forward),
			      fmt_amount_msat(tmpctx, htlc_max),
			      fmt_short_channel_id_dir(tmpctx, &scidd));
		fail(info, htlc, payload, WIRE_TEMPORARY_CHANNEL_FAILURE);
		return;
	}

	if (amount_msat_greater(amount, calc_capacity(info, c, &scidd))) {
		fail(info, htlc, payload, WIRE_TEMPORARY_CHANNEL_FAILURE);
		return;
	}

	/* When we resolve the HTLC, we'll cancel the reservations */
	add_reservation(htlc, info, &scidd, amount);

	if (payload->path_key) {
		struct sha256 sha;
		blinding_hash_e_and_ss(payload->path_key,
				       &payload->blinding_ss,
				       &sha);
		next_path_key = tal(tmpctx, struct pubkey);
		blinding_next_path_key(payload->path_key, &sha,
				       next_path_key);
	} else
		next_path_key = NULL;

	dfwd = tal(NULL, struct delayed_forward);
	dfwd->info = info;
	dfwd->htlc = htlc;
	dfwd->amount = payload->amt_to_forward;
	dfwd->cltv_expiry = payload->outgoing_cltv;
	dfwd->onion_routing_packet = tal_steal(dfwd, next_onion_packet);
	dfwd->path_key = tal_steal(dfwd, next_path_key);
	dfwd->expected = next;

	/* Delay 0.1 - 1 seconds, but skewed lower */
	msec_delay = channel_range(info, &scidd, 0, 900);
	msec_delay = 100 + channel_range(info, &scidd, 0, msec_delay);

	status_debug("Delaying %u msec for %s",
		     msec_delay, fmt_short_channel_id_dir(tmpctx, &scidd));
	timer = new_reltimer(&info->timers,
			     info,
			     time_from_msec(msec_delay),
			     delayed_forward, dfwd);
	/* Free dfwd after timer expires */
	tal_steal(timer, dfwd);
}

static void delayed_forward(struct delayed_forward *dfwd)
{
	forward_htlc(dfwd->info,
		     dfwd->htlc,
		     dfwd->amount,
		     dfwd->cltv_expiry,
		     dfwd->onion_routing_packet,
		     dfwd->path_key,
		     &dfwd->expected);
}

static void handle_offer_htlc(struct info *info, const u8 *inmsg)
{
	u8 *msg;
	u32 cltv_expiry;
	struct amount_msat amount;
	u8 onion_routing_packet[TOTAL_PACKET_SIZE(ROUTING_INFO_SIZE)];
	enum channel_add_err e;
	const u8 *failwiremsg;
	const char *failstr;
	struct amount_sat htlc_fee;
	struct pubkey *blinding;
	static u64 htlc_id;
	struct fake_htlc *htlc = tal(info, struct fake_htlc);

	htlc->secrets = tal_arr(htlc, struct secret, 0);
	htlc->htlc_id = htlc_id;
	if (!fromwire_channeld_offer_htlc(tmpctx, inmsg, &amount,
					 &cltv_expiry, &htlc->payment_hash,
					 onion_routing_packet, &blinding))
		master_badmsg(WIRE_CHANNELD_OFFER_HTLC, inmsg);

	e = channel_add_htlc(info->channel, LOCAL, htlc->htlc_id,
			     amount, cltv_expiry, &htlc->payment_hash,
			     onion_routing_packet, take(blinding), NULL,
			     &htlc_fee, true);
	status_debug("Adding HTLC %"PRIu64" amount=%s cltv=%u gave %s",
		     htlc->htlc_id, fmt_amount_msat(tmpctx, amount),
		     cltv_expiry,
		     channel_add_err_name(e));

	switch (e) {
	case CHANNEL_ERR_ADD_OK:
		/* Tell lightningd. */
		msg = towire_channeld_offer_htlc_reply(NULL, htlc_id,
						       0, "");
		daemon_conn_send(info->dc, take(msg));
		/* Tell it it's locked in */
		update_commitment_tx_added(info, htlc_id);

		/* Handle it. */
		forward_htlc(info, htlc, amount, cltv_expiry,
			     onion_routing_packet, blinding, NULL);
		htlc_id++;
		return;
	case CHANNEL_ERR_INVALID_EXPIRY:
		failwiremsg = towire_incorrect_cltv_expiry(inmsg, cltv_expiry, NULL);
		failstr = tal_fmt(inmsg, "Invalid cltv_expiry %u", cltv_expiry);
		goto failed;
	case CHANNEL_ERR_DUPLICATE:
	case CHANNEL_ERR_DUPLICATE_ID_DIFFERENT:
		status_failed(STATUS_FAIL_MASTER_IO,
			      "Duplicate HTLC %"PRIu64, htlc_id);

	case CHANNEL_ERR_MAX_HTLC_VALUE_EXCEEDED:
		failwiremsg = towire_required_node_feature_missing(inmsg);
		failstr = "Mini mode: maximum value exceeded";
		goto failed;
	/* FIXME: Fuzz the boundaries a bit to avoid probing? */
	case CHANNEL_ERR_CHANNEL_CAPACITY_EXCEEDED:
		failwiremsg = towire_temporary_channel_failure(inmsg, NULL);
		failstr = tal_fmt(inmsg, "Capacity exceeded - HTLC fee: %s", fmt_amount_sat(inmsg, htlc_fee));
		goto failed;
	case CHANNEL_ERR_HTLC_BELOW_MINIMUM:
		failwiremsg = towire_amount_below_minimum(inmsg, amount, NULL);
		failstr = tal_fmt(inmsg, "HTLC too small (%s minimum)",
				  fmt_amount_msat(tmpctx,
						  info->channel->config[REMOTE].htlc_minimum));
		goto failed;
	case CHANNEL_ERR_TOO_MANY_HTLCS:
		failwiremsg = towire_temporary_channel_failure(inmsg, NULL);
		failstr = "Too many HTLCs";
		goto failed;
	case CHANNEL_ERR_DUST_FAILURE:
		/* BOLT-919 #2:
		 * - upon an outgoing HTLC:
		 *   - if a HTLC's `amount_msat` is inferior the counterparty's...
		 *   - SHOULD NOT send this HTLC
		 *   - SHOULD fail this HTLC if it's forwarded
		 */
		failwiremsg = towire_temporary_channel_failure(inmsg, NULL);
		failstr = "HTLC too dusty, allowed dust limit reached";
		goto failed;
	}
	/* Shouldn't return anything else! */
	abort();

failed:
	/* lightningd appends update to this for us */
	msg = towire_channeld_offer_htlc_reply(NULL, 0, failwiremsg, failstr);
	daemon_conn_send(info->dc, take(msg));
}

static void handle_feerates(struct info *info, const u8 *inmsg)
{
	u32 feerate, min, max, penalty;

	if (!fromwire_channeld_feerates(inmsg, &feerate,
					&min, &max, &penalty))
		master_badmsg(WIRE_CHANNELD_FEERATES, inmsg);

	/* BOLT #2:
	 *
	 * The node _responsible_ for paying the Bitcoin fee:
	 *   - SHOULD send `update_fee` to ensure the current fee rate is
	 *    sufficient (by a significant margin) for timely processing of the
	 *     commitment transaction.
	 */
	if (info->channel->opener == LOCAL) {
		if (!channel_update_feerate(info->channel, feerate)) {
			abort();
		}
	}
}

static void handle_blockheight(struct info *info, const u8 *inmsg)
{
	if (!fromwire_channeld_blockheight(inmsg, &info->current_block_height))
		master_badmsg(WIRE_CHANNELD_BLOCKHEIGHT, inmsg);
}

static void handle_funding_depth(struct info *info, const u8 *inmsg)
{
	struct short_channel_id *short_channel_id;
	u32 depth;
	bool splicing;
	struct bitcoin_txid txid;
	struct pubkey somepoint;

	if (!fromwire_channeld_funding_depth(tmpctx, inmsg, &short_channel_id,
					     &depth, &splicing, &txid))
		master_badmsg(WIRE_CHANNELD_FUNDING_DEPTH, inmsg);

	/* Tell it the channel is ready ONCE, so it goes into CHANNELD_NORMAL.
	 * We make up the remote_per_commit */
	if (depth != 1)
		return;

	pubkey_from_hexstr("0266e4598d1d3c415f572a8488830b60f7e744ed9235eb0b1ba93283b315c03518",
			   strlen("0266e4598d1d3c415f572a8488830b60f7e744ed9235eb0b1ba93283b315c03518"),
			   &somepoint);
	/* Tell the peer we are ready: it will send a channel_update
	 * then to make lightningd happy */
	wire_sync_write(PEER_FD,
			take(towire_channel_ready(NULL,
						  &info->channel->cid,
						  &somepoint, NULL)));

	/* Ignore peer msgs except for channel_ready */
	while (fromwire_peektype(wire_sync_read(tmpctx, PEER_FD))
	       != WIRE_CHANNEL_READY);

	daemon_conn_send(info->dc,
			 take(towire_channeld_got_channel_ready(NULL, &somepoint, NULL)));
}

static void handle_dev_peer_shachain(struct info *info, const u8 *msg)
{
	if (!fromwire_channeld_dev_peer_shachain(msg, &info->peer_shaseed))
		master_badmsg(WIRE_CHANNELD_DEV_PEER_SHACHAIN, msg);
}

/* We don't care, but lightningd expects channeld to respond. */
static void handle_dev_memleak(struct info *info, const u8 *msg)
{
	daemon_conn_send(info->dc,
			 take(towire_channeld_dev_memleak_reply(NULL, false)));
}

static struct channel *handle_init(struct info *info, const u8 *init_msg)
{
	struct feature_set *our_features;
	u32 *hsm_capabilities;
	struct channel_id channel_id;
	struct basepoints points[NUM_SIDES];
	struct amount_sat funding_sats;
	struct amount_msat local_msat;
	struct pubkey funding_pubkey[NUM_SIDES];
	struct channel_config conf[NUM_SIDES];
	struct bitcoin_outpoint funding;
	enum side opener;
	struct existing_htlc **htlcs;
	bool reconnected;
	u32 final_index;
	struct ext_key final_ext_key;
	u8 *fwd_msg;
	u32 minimum_depth, lease_expiry;
	struct secret last_remote_per_commit_secret;
	struct penalty_base *pbases;
	bool reestablish_only;
	struct channel_type *channel_type;
	u32 feerate_min, feerate_max, feerate_penalty;
	struct pubkey remote_per_commit;
	struct pubkey old_remote_per_commit;
	u32 commit_msec;
	bool last_was_revoke;
	struct changed_htlc *last_sent_commit;
	u64 revocations_received;
	u8 channel_flags;
	bool channel_ready[NUM_SIDES];
	u64 next_index[NUM_SIDES];
	u64 htlc_id;
	struct bitcoin_signature their_commit_sig;
	struct short_channel_id short_channel_ids[NUM_SIDES];
	bool send_shutdown;
	bool shutdown_sent[NUM_SIDES];
	u8 *final_scriptpubkey;
	u8 *their_features;
	u8 *remote_upfront_shutdown_script;
	bool experimental_upgrade;
	u32 *dev_disable_commit;
	struct inflight **inflights;
	struct short_channel_id local_alias;
	struct channel *channel;
	const u8 *wscript;
	char *err_reason;
	struct wally_tx_output *direct_outputs[NUM_SIDES];
	struct htlc_map *htlc_map;

	if (!fromwire_channeld_init(info, init_msg,
				    &chainparams,
				    &our_features,
				    &hsm_capabilities,
				    &channel_id,
				    &funding,
				    &funding_sats,
				    &minimum_depth,
				    &info->current_block_height,
				    &info->blockheight_states,
				    &lease_expiry,
				    &conf[LOCAL], &conf[REMOTE],
				    &info->fee_states,
				    &feerate_min,
				    &feerate_max,
				    &feerate_penalty,
				    &their_commit_sig,
				    &funding_pubkey[REMOTE],
				    &points[REMOTE],
				    &remote_per_commit,
				    &old_remote_per_commit,
				    &opener,
				    &local_msat,
				    &points[LOCAL],
				    &funding_pubkey[LOCAL],
				    &commit_msec,
				    &last_was_revoke,
				    &last_sent_commit,
				    &next_index[LOCAL],
				    &next_index[REMOTE],
				    &revocations_received,
				    &htlc_id,
				    &htlcs,
				    &channel_ready[LOCAL],
				    &channel_ready[REMOTE],
				    &short_channel_ids[LOCAL],
				    &reconnected,
				    &send_shutdown,
				    &shutdown_sent[REMOTE],
				    &final_index,
				    &final_ext_key,
				    &final_scriptpubkey,
				    &channel_flags,
				    &fwd_msg,
				    &last_remote_per_commit_secret,
				    &their_features,
				    &remote_upfront_shutdown_script,
				    &channel_type,
				    &dev_disable_commit,
				    &pbases,
				    &reestablish_only,
				    &experimental_upgrade,
				    &inflights,
				    &local_alias))
		abort();

	status_debug("Parsed init...");
	channel = new_full_channel(info, &channel_id,
				   &funding,
				   minimum_depth,
				   info->blockheight_states,
				   lease_expiry,
				   funding_sats,
				   local_msat,
				   info->fee_states,
				   &conf[LOCAL], &conf[REMOTE],
				   &points[LOCAL], &points[REMOTE],
				   &funding_pubkey[LOCAL],
				   &funding_pubkey[REMOTE],
				   take(channel_type),
				   feature_offered(their_features,
						OPT_LARGE_CHANNELS),
				   opener);

	/* We need a tx, so use this.  It gets upset if channel->htlcs
	* is set, so temporarily clear that! */
	htlc_map = channel->htlcs;
	channel->htlcs = NULL;
	info->commit_tx = initial_channel_tx(info, &wscript, channel, &remote_per_commit,
					     LOCAL,
					     direct_outputs, &err_reason);
	channel->htlcs = htlc_map;

	status_debug("Created channel");
	daemon_conn_send(info->dc, take(towire_channeld_reestablished(NULL)));

	return channel;
}

static void master_gone(struct daemon_conn *dc UNUSED)
{
	daemon_shutdown();
	/* Can't tell master, it's gone. */
	exit(2);
}

static struct io_plan *recv_req(struct io_conn *conn,
				const u8 *msg,
				struct info *info)
{
	enum channeld_wire t = fromwire_peektype(msg);

	switch (t) {
	/* We ignore these */
	case WIRE_CHANNELD_SEND_ERROR:
	case WIRE_CHANNELD_SENDING_COMMITSIG_REPLY:
	case WIRE_CHANNELD_GOT_REVOKE_REPLY:
	case WIRE_CHANNELD_GOT_COMMITSIG_REPLY:
		goto out;
	case WIRE_CHANNELD_INIT:
		info->channel = handle_init(info, msg);
		goto out;
	case WIRE_CHANNELD_BLOCKHEIGHT:
		handle_blockheight(info, msg);
		goto out;
	case WIRE_CHANNELD_OFFER_HTLC:
		handle_offer_htlc(info, msg);
		goto out;
	case WIRE_CHANNELD_FEERATES:
		handle_feerates(info, msg);
		goto out;
	case WIRE_CHANNELD_FUNDING_DEPTH:
		handle_funding_depth(info, msg);
		goto out;
	case WIRE_CHANNELD_DEV_MEMLEAK:
		handle_dev_memleak(info, msg);
		goto out;
	case WIRE_CHANNELD_DEV_PEER_SHACHAIN:
		handle_dev_peer_shachain(info, msg);
		goto out;
		/* No incoming HTLCs, these should not happen */
	case WIRE_CHANNELD_FULFILL_HTLC:
	case WIRE_CHANNELD_FAIL_HTLC:
		/* Don't try closing this channel! */
	case WIRE_CHANNELD_SEND_SHUTDOWN:
		/* Don't try to splice */
	case WIRE_CHANNELD_SPLICE_INIT:
	case WIRE_CHANNELD_SPLICE_UPDATE:
	case WIRE_CHANNELD_SPLICE_SIGNED:
	case WIRE_CHANNELD_SPLICE_CONFIRMED_INIT:
	case WIRE_CHANNELD_SPLICE_CONFIRMED_SIGNED:
	case WIRE_CHANNELD_SPLICE_SENDING_SIGS:
	case WIRE_CHANNELD_SPLICE_CONFIRMED_UPDATE:
	case WIRE_CHANNELD_SPLICE_LOOKUP_TX:
	case WIRE_CHANNELD_SPLICE_LOOKUP_TX_RESULT:
	case WIRE_CHANNELD_SPLICE_FEERATE_ERROR:
	case WIRE_CHANNELD_SPLICE_FUNDING_ERROR:
	case WIRE_CHANNELD_SPLICE_ABORT:
	case WIRE_CHANNELD_STFU:
	case WIRE_CHANNELD_CONFIRMED_STFU:
	case WIRE_CHANNELD_ABORT:
		/* Not supported */
	case WIRE_CHANNELD_DEV_REENABLE_COMMIT:
	case WIRE_CHANNELD_DEV_QUIESCE:
		/* We send these, not receive */
	case WIRE_CHANNELD_OFFER_HTLC_REPLY:
	case WIRE_CHANNELD_SENDING_COMMITSIG:
	case WIRE_CHANNELD_GOT_COMMITSIG:
	case WIRE_CHANNELD_GOT_REVOKE:
	case WIRE_CHANNELD_GOT_CHANNEL_READY:
	case WIRE_CHANNELD_GOT_SPLICE_LOCKED:
	case WIRE_CHANNELD_GOT_ANNOUNCEMENT:
	case WIRE_CHANNELD_GOT_SHUTDOWN:
	case WIRE_CHANNELD_SHUTDOWN_COMPLETE:
	case WIRE_CHANNELD_DEV_REENABLE_COMMIT_REPLY:
	case WIRE_CHANNELD_FAIL_FALLEN_BEHIND:
	case WIRE_CHANNELD_DEV_MEMLEAK_REPLY:
	case WIRE_CHANNELD_SEND_ERROR_REPLY:
	case WIRE_CHANNELD_DEV_QUIESCE_REPLY:
	case WIRE_CHANNELD_UPGRADED:
	case WIRE_CHANNELD_ADD_INFLIGHT:
	case WIRE_CHANNELD_UPDATE_INFLIGHT:
	case WIRE_CHANNELD_GOT_INFLIGHT:
	case WIRE_CHANNELD_SPLICE_STATE_ERROR:
	case WIRE_CHANNELD_LOCAL_ANCHOR_INFO:
	case WIRE_CHANNELD_REESTABLISHED:
		break;
	}
	master_badmsg(-1, msg);

out:
	/* Read the next message. */
	return daemon_conn_read_next(conn, info->dc);
}

int main(int argc, char *argv[])
{
	struct info *info;

	setup_locale();

	subdaemon_setup(argc, argv);
	info = tal(NULL, struct info);

	info->dc = daemon_conn_new(info, MASTER_FD,
				   recv_req, NULL, info);
	tal_add_destructor(info->dc, master_gone);

	status_setup_async(info->dc);

	info->gossmap = gossmap_load(info, GOSSIP_STORE_FILENAME, NULL);
	if (!info->gossmap)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Loading gossmap %s", strerror(errno));

	info->cached_node_idx = tal_arr(info, size_t, 0);
	info->multi_payments = tal_arr(info, struct multi_payment *, 0);
	info->reservations = tal_arr(info, struct reservation *, 0);
	timers_init(&info->timers, time_mono());
	info->commit_num = 1;
	info->fakesig.sighash_type = SIGHASH_ALL;
	memset(&info->fakesig.s, 0, sizeof(info->fakesig.s));
	memset(&info->seed, 0, sizeof(info->seed));

	if (getenv("CHANNELD_FAKENET_SEED"))
		info->seed.u.u64[0] = atol(getenv("CHANNELD_FAKENET_SEED"));

	status_debug("channeld_fakenet seed is %"PRIu64, info->seed.u.u64[0]);

	/* This loop never exits.  io_loop() only returns if a timer has
	 * expired, or io_break() is called, or all fds are closed.  We don't
	 * use io_break and closing the lightningd fd calls master_gone()
	 * which exits. */
	for (;;) {
		struct timer *expired = NULL;
		io_loop(&info->timers, &expired);

		timer_expired(expired);
	}
}
