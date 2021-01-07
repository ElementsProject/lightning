/*~ Welcome to the gossip daemon: keeper of maps!
 *
 * This is the last "global" daemon; it has three purposes.
 *
 * 1. To determine routes for payments when lightningd asks.
 * 2. The second purpose is to receive gossip from peers (via their
 *    per-peer daemons) and send it out to them.
 * 3. Talk to `connectd` to to answer address queries for nodes.
 *
 * The gossip protocol itself is fairly simple, but has some twists which
 * add complexity to this daemon.
 */
#include <bitcoin/chainparams.h>
#include <ccan/array_size/array_size.h>
#include <ccan/build_assert/build_assert.h>
#include <ccan/cast/cast.h>
#include <ccan/container_of/container_of.h>
#include <ccan/crypto/hkdf_sha256/hkdf_sha256.h>
#include <ccan/crypto/siphash24/siphash24.h>
#include <ccan/endian/endian.h>
#include <ccan/fdpass/fdpass.h>
#include <ccan/io/fdpass/fdpass.h>
#include <ccan/io/io.h>
#include <ccan/mem/mem.h>
#include <ccan/noerr/noerr.h>
#include <ccan/take/take.h>
#include <ccan/tal/str/str.h>
#include <common/bech32.h>
#include <common/bech32_util.h>
#include <common/blinding.h>
#include <common/cryptomsg.h>
#include <common/daemon_conn.h>
#include <common/ecdh_hsmd.h>
#include <common/features.h>
#include <common/memleak.h>
#include <common/ping.h>
#include <common/pseudorand.h>
#include <common/sphinx.h>
#include <common/status.h>
#include <common/subdaemon.h>
#include <common/timeout.h>
#include <common/type_to_string.h>
#include <common/utils.h>
#include <common/version.h>
#include <common/wire_error.h>
#include <common/wireaddr.h>
#include <connectd/connectd_gossipd_wiregen.h>
#include <errno.h>
#include <fcntl.h>
#include <gossipd/broadcast.h>
#include <gossipd/gossip_generation.h>
#include <gossipd/gossip_store_wiregen.h>
#include <gossipd/gossipd.h>
#include <gossipd/gossipd_peerd_wiregen.h>
#include <gossipd/gossipd_wiregen.h>
#include <gossipd/queries.h>
#include <gossipd/routing.h>
#include <gossipd/seeker.h>
#include <inttypes.h>
#include <lightningd/gossip_msg.h>
#include <netdb.h>
#include <netinet/in.h>
#include <secp256k1_ecdh.h>
#include <sodium/crypto_aead_chacha20poly1305.h>
#include <sodium/randombytes.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#if EXPERIMENTAL_FEATURES
#include <wire/bolt12_exp_wiregen.h>
#endif
#include <wire/wire_io.h>
#include <wire/wire_sync.h>

/*~ A channel consists of a `struct half_chan` for each direction, each of
 * which has a `flags` word from the `channel_update`; bit 1 is
 * ROUTING_FLAGS_DISABLED in the `channel_update`.  But we also keep a local
 * whole-channel flag which indicates it's not available; we use this when a
 * peer disconnects, and generate a `channel_update` to tell the world lazily
 * when someone asks. */
static void peer_disable_channels(struct daemon *daemon, struct node *node)
{
	/* If this peer had a channel with us, mark it disabled. */
	struct chan_map_iter i;
	struct chan *c;

	for (c = first_chan(node, &i); c; c = next_chan(node, &i)) {
		if (node_id_eq(&other_node(node, c)->id, &daemon->id))
			local_disable_chan(daemon->rstate, c);
	}
}

/*~ Destroy a peer, usually because the per-peer daemon has exited.
 *
 * Were you wondering why we call this "destroy_peer" and not "peer_destroy"?
 * I thought not!  But while CCAN modules are required to keep to their own
 * prefix namespace, leading to unnatural word order, we couldn't stomach that
 * for our own internal use.  We use 'find_foo', 'destroy_foo' and 'new_foo'.
 */
static void destroy_peer(struct peer *peer)
{
	struct node *node;

	/* Remove it from the peers list */
	list_del_from(&peer->daemon->peers, &peer->list);

	/* If we have a channel with this peer, disable it. */
	node = get_node(peer->daemon->rstate, &peer->id);
	if (node)
		peer_disable_channels(peer->daemon, node);

	/* This is tricky: our lifetime is tied to the daemon_conn; it's our
	 * parent, so we are freed if it is, but we need to free it if we're
	 * freed manually.  tal_free() treats this as a noop if it's already
	 * being freed */
	tal_free(peer->dc);
}

/* Search for a peer. */
struct peer *find_peer(struct daemon *daemon, const struct node_id *id)
{
	struct peer *peer;

	list_for_each(&daemon->peers, peer, list)
		if (node_id_eq(&peer->id, id))
			return peer;
	return NULL;
}

/* Increase a peer's gossip_counter, if peer not NULL */
void peer_supplied_good_gossip(struct peer *peer, size_t amount)
{
	if (peer)
		peer->gossip_counter += amount;
}

/* Queue a gossip message for the peer: the subdaemon on the other end simply
 * forwards it to the peer. */
void queue_peer_msg(struct peer *peer, const u8 *msg TAKES)
{
	daemon_conn_send(peer->dc, msg);
}

/*~ We have a helper for messages from the store. */
void queue_peer_from_store(struct peer *peer,
			   const struct broadcastable *bcast)
{
	struct gossip_store *gs = peer->daemon->rstate->gs;
	queue_peer_msg(peer, take(gossip_store_get(NULL, gs, bcast->index)));
}

/*~ We don't actually keep node_announcements in memory; we keep them in
 * a file called `gossip_store`.  If we need some node details, we reload
 * and reparse.  It's slow, but generally rare. */
static bool get_node_announcement(const tal_t *ctx,
				  struct daemon *daemon,
				  const struct node *n,
				  u8 rgb_color[3],
				  u8 alias[32],
				  u8 **features,
				  struct wireaddr **wireaddrs)
{
	const u8 *msg;
	struct node_id id;
	secp256k1_ecdsa_signature signature;
	u32 timestamp;
	u8 *addresses;

	if (!n->bcast.index)
		return false;

	msg = gossip_store_get(tmpctx, daemon->rstate->gs, n->bcast.index);

	/* Note: validity of node_id is already checked. */
	if (!fromwire_node_announcement(ctx, msg,
					&signature, features,
					&timestamp,
					&id, rgb_color, alias,
					&addresses)) {
		status_broken("Bad local node_announcement @%u: %s",
			      n->bcast.index, tal_hex(tmpctx, msg));
		return false;
	}

	if (!node_id_eq(&id, &n->id) || timestamp != n->bcast.timestamp) {
		status_broken("Wrong node_announcement @%u:"
			      " expected %s timestamp %u "
			      " got %s timestamp %u",
			      n->bcast.index,
			      type_to_string(tmpctx, struct node_id, &n->id),
			      timestamp,
			      type_to_string(tmpctx, struct node_id, &id),
			      n->bcast.timestamp);
		return false;
	}

	*wireaddrs = read_addresses(ctx, addresses);
	tal_free(addresses);
	return true;
}

/* Version which also does nodeid lookup */
static bool get_node_announcement_by_id(const tal_t *ctx,
					struct daemon *daemon,
					const struct node_id *node_id,
					u8 rgb_color[3],
					u8 alias[32],
					u8 **features,
					struct wireaddr **wireaddrs)
{
	struct node *n = get_node(daemon->rstate, node_id);
	if (!n)
		return false;

	return get_node_announcement(ctx, daemon, n, rgb_color, alias,
				     features, wireaddrs);
}

/*~Routines to handle gossip messages from peer, forwarded by subdaemons.
 *-----------------------------------------------------------------------
 *
 * It's not the subdaemon's fault if they're malformed or invalid; so these
 * all return an error packet which gets sent back to the subdaemon in that
 * case.
 */

/* The routing code checks that it's basically valid, returning an
 * error message for the peer or NULL.  NULL means it's OK, but the
 * message might be redundant, in which case scid is also NULL.
 * Otherwise `scid` gives us the short_channel_id claimed by the
 * message, and puts the announcemnt on an internal 'pending'
 * queue.  We'll send a request to lightningd to look it up, and continue
 * processing in `handle_txout_reply`. */
static const u8 *handle_channel_announcement_msg(struct peer *peer,
						 const u8 *msg)
{
	const struct short_channel_id *scid;
	const u8 *err;

	/* If it's OK, tells us the short_channel_id to lookup; it notes
	 * if this is the unknown channel the peer was looking for (in
	 * which case, it frees and NULLs that ptr) */
	err = handle_channel_announcement(peer->daemon->rstate, msg,
					  peer->daemon->current_blockheight,
					  &scid, peer);
	if (err)
		return err;
	else if (scid) {
		/* We give them some grace period, in case we don't know about
		 * block yet. */
		if (peer->daemon->current_blockheight == 0
		    || !is_scid_depth_announceable(scid,
						   peer->daemon->current_blockheight)) {
			tal_arr_expand(&peer->daemon->deferred_txouts, *scid);
		} else {
			daemon_conn_send(peer->daemon->master,
					 take(towire_gossipd_get_txout(NULL,
								      scid)));
		}
	}
	return NULL;
}

static u8 *handle_channel_update_msg(struct peer *peer, const u8 *msg)
{
	struct short_channel_id unknown_scid;
	/* Hand the channel_update to the routing code */
	u8 *err;

	unknown_scid.u64 = 0;
	err = handle_channel_update(peer->daemon->rstate, msg, peer,
				    &unknown_scid);
	if (err) {
		if (unknown_scid.u64 != 0)
			query_unknown_channel(peer->daemon, peer, &unknown_scid);
		return err;
	}

	/*~ As a nasty compromise in the spec, we only forward `channel_announce`
	 * once we have a `channel_update`; the channel isn't *usable* for
	 * routing until you have both anyway.  For this reason, we might have
	 * just sent out our own channel_announce, so we check if it's time to
	 * send a node_announcement too. */
	maybe_send_own_node_announce(peer->daemon);
	return NULL;
}

/*~ When we compact the gossip store, all the broadcast indexs move.
 * We simply offset everyone, which means in theory they could retransmit
 * some, but that's a lesser evil than skipping some. */
void update_peers_broadcast_index(struct list_head *peers, u32 offset)
{
	struct peer *peer, *next;

	list_for_each_safe(peers, peer, next, list) {
		int gs_fd;
		/*~ Since store has been compacted, they need a new fd for the
		 * new store.  We also tell them how much this is shrunk, so
		 * they can (approximately) tell where to start in the new store.
		 */
		gs_fd = gossip_store_readonly_fd(peer->daemon->rstate->gs);
		if (gs_fd < 0) {
			status_broken("Can't get read-only gossip store fd:"
				      " killing peer");
			tal_free(peer);
		} else {
			u8 *msg = towire_gossipd_new_store_fd(NULL, offset);
			daemon_conn_send(peer->dc, take(msg));
			daemon_conn_send_fd(peer->dc, gs_fd);
		}
	}
}

/*~ For simplicity, all pings and pongs are forwarded to us here in gossipd. */
static u8 *handle_ping(struct peer *peer, const u8 *ping)
{
	u8 *pong;

	/* This checks the ping packet and makes a pong reply if needed; peer
	 * can specify it doesn't want a response, to simulate traffic. */
	if (!check_ping_make_pong(NULL, ping, &pong))
		return towire_errorfmt(peer, NULL, "Bad ping");

	if (pong)
		queue_peer_msg(peer, take(pong));
	return NULL;
}

/*~ When we get a pong, we tell lightningd about it (it's probably a response
 * to the `ping` JSON RPC command). */
static const u8 *handle_pong(struct peer *peer, const u8 *pong)
{
	const char *err = got_pong(pong, &peer->num_pings_outstanding);

	if (err)
		return towire_errorfmt(peer, NULL, "%s", err);

	daemon_conn_send(peer->daemon->master,
			 take(towire_gossipd_ping_reply(NULL, &peer->id, true,
						       tal_count(pong))));
	return NULL;
}

/*~ This is when channeld asks us for a channel_update for a local channel.
 * It does that to fill in the error field when lightningd fails an HTLC and
 * sets the UPDATE bit in the error type.  lightningd is too important to
 * fetch this itself, so channeld does it (channeld has to talk to us for
 * other things anyway, so why not?). */
static bool handle_get_local_channel_update(struct peer *peer, const u8 *msg)
{
	struct short_channel_id scid;
	struct local_chan *local_chan;
	struct chan *chan;
	const u8 *update;
	struct routing_state *rstate = peer->daemon->rstate;

	if (!fromwire_gossipd_get_update(msg, &scid)) {
		status_broken("peer %s sent bad gossip_get_update %s",
			      type_to_string(tmpctx, struct node_id, &peer->id),
			      tal_hex(tmpctx, msg));
		return false;
	}

	/* It's possible that the channel has just closed (though v. unlikely) */
	local_chan = local_chan_map_get(&rstate->local_chan_map, &scid);
	if (!local_chan) {
		status_unusual("peer %s scid %s: unknown channel",
			       type_to_string(tmpctx, struct node_id, &peer->id),
			       type_to_string(tmpctx, struct short_channel_id,
					      &scid));
		update = NULL;
		goto out;
	}

	chan = local_chan->chan;

	/* Since we're going to send it out, make sure it's up-to-date. */
	refresh_local_channel(peer->daemon, local_chan, false);

 	/* It's possible this is zero, if we've never sent a channel_update
	 * for that channel. */
	if (!is_halfchan_defined(&chan->half[local_chan->direction]))
		update = NULL;
	else
		update = gossip_store_get(tmpctx, rstate->gs,
					  chan->half[local_chan->direction].bcast.index);
out:
	status_peer_debug(&peer->id, "schanid %s: %s update",
			  type_to_string(tmpctx, struct short_channel_id, &scid),
			  update ? "got" : "no");

	msg = towire_gossipd_get_update_reply(NULL, update);
	daemon_conn_send(peer->dc, take(msg));
	return true;
}

static u8 *handle_node_announce(struct peer *peer, const u8 *msg)
{
	bool was_unknown = false;
	u8 *err;

	err = handle_node_announcement(peer->daemon->rstate, msg, peer,
				       &was_unknown);
	if (was_unknown)
		query_unknown_node(peer->daemon->seeker, peer);
	return err;
}

static bool handle_local_channel_announcement(struct daemon *daemon,
					      struct peer *peer,
					      const u8 *msg)
{
	u8 *cannouncement;
	const u8 *err;

	if (!fromwire_gossipd_local_channel_announcement(msg, msg,
							 &cannouncement)) {
		status_broken("peer %s bad local_channel_announcement %s",
			      type_to_string(tmpctx, struct node_id, &peer->id),
			      tal_hex(tmpctx, msg));
		return false;
	}

	err = handle_channel_announcement_msg(peer, cannouncement);
	if (err) {
		status_broken("peer %s invalid local_channel_announcement %s (%s)",
			      type_to_string(tmpctx, struct node_id, &peer->id),
			      tal_hex(tmpctx, msg),
			      tal_hex(tmpctx, err));
		return false;
	}

	return true;
}

#if EXPERIMENTAL_FEATURES
/* Peer sends onion msg. */
static u8 *handle_onion_message(struct peer *peer, const u8 *msg)
{
	enum onion_wire badreason;
	struct onionpacket *op;
	struct secret ss, *blinding_ss;
	struct pubkey *blinding_in;
	struct route_step *rs;
	u8 onion[TOTAL_PACKET_SIZE(ROUTING_INFO_SIZE)];
	const u8 *cursor;
	size_t max, maxlen;
	struct tlv_onionmsg_payload *om;
	struct tlv_onion_message_tlvs *tlvs = tlv_onion_message_tlvs_new(msg);

	/* FIXME: ratelimit! */
	if (!fromwire_onion_message(msg, onion, tlvs))
		return towire_errorfmt(peer, NULL, "Bad onion_message");

	/* We unwrap the onion now. */
	op = parse_onionpacket(tmpctx, onion, TOTAL_PACKET_SIZE(ROUTING_INFO_SIZE), &badreason);
	if (!op) {
		status_debug("peer %s: onion msg: can't parse onionpacket: %s",
			     type_to_string(tmpctx, struct node_id, &peer->id),
			     onion_wire_name(badreason));
		return NULL;
	}

	if (tlvs->blinding) {
		struct secret hmac;

		/* E(i) */
		blinding_in = tal_dup(msg, struct pubkey, tlvs->blinding);
		status_debug("peer %s: blinding in = %s",
			     type_to_string(tmpctx, struct node_id, &peer->id),
			     type_to_string(tmpctx, struct pubkey, blinding_in));
		blinding_ss = tal(msg, struct secret);
		ecdh(blinding_in, blinding_ss);

		/* b(i) = HMAC256("blinded_node_id", ss(i)) * k(i) */
		subkey_from_hmac("blinded_node_id", blinding_ss, &hmac);

		/* We instead tweak the *ephemeral* key from the onion and use
		 * our normal privkey: since hsmd knows only how to ECDH with
		 * our real key */
		if (secp256k1_ec_pubkey_tweak_mul(secp256k1_ctx,
						  &op->ephemeralkey.pubkey,
						  hmac.data) != 1) {
			status_debug("peer %s: onion msg: can't tweak pubkey",
				     type_to_string(tmpctx, struct node_id, &peer->id));
			return NULL;
		}
	} else {
		blinding_ss = NULL;
		blinding_in = NULL;
	}

	ecdh(&op->ephemeralkey, &ss);

	/* We make sure we can parse onion packet, so we know if shared secret
	 * is actually valid (this checks hmac). */
	rs = process_onionpacket(tmpctx, op, &ss, NULL, 0, false);
	if (!rs) {
		status_debug("peer %s: onion msg: can't process onionpacket ss=%s",
			     type_to_string(tmpctx, struct node_id, &peer->id),
			     type_to_string(tmpctx, struct secret, &ss));
		return NULL;
	}

	/* The raw payload is prepended with length in the TLV world. */
	cursor = rs->raw_payload;
	max = tal_bytelen(rs->raw_payload);
	maxlen = fromwire_bigsize(&cursor, &max);
	if (!cursor) {
		status_debug("peer %s: onion msg: Invalid hop payload %s",
			     type_to_string(tmpctx, struct node_id, &peer->id),
			     tal_hex(tmpctx, rs->raw_payload));
		return NULL;
	}
	if (maxlen > max) {
		status_debug("peer %s: onion msg: overlong hop payload %s",
			     type_to_string(tmpctx, struct node_id, &peer->id),
			     tal_hex(tmpctx, rs->raw_payload));
		return NULL;
	}

	om = tlv_onionmsg_payload_new(msg);
	if (!fromwire_onionmsg_payload(&cursor, &maxlen, om)) {
		status_debug("peer %s: onion msg: invalid onionmsg_payload %s",
			     type_to_string(tmpctx, struct node_id, &peer->id),
			     tal_hex(tmpctx, rs->raw_payload));
		return NULL;
	}

	/* If we weren't given a blinding factor, tlv can provide one. */
	if (om->blinding && !blinding_ss) {
		/* E(i) */
		blinding_in = tal_dup(msg, struct pubkey, om->blinding);
		blinding_ss = tal(msg, struct secret);

		ecdh(blinding_in, blinding_ss);
	}

	if (om->enctlv) {
		const unsigned char npub[crypto_aead_chacha20poly1305_ietf_NPUBBYTES] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		u8 *dec;
		struct secret rho;
		int ret;

		if (!blinding_ss) {
			status_debug("peer %s: enctlv but no blinding?",
				     type_to_string(tmpctx, struct node_id, &peer->id));
			return NULL;
		}

		/* We need this to decrypt enctlv */
		subkey_from_hmac("rho", blinding_ss, &rho);

		/* Overrides next_scid / next_node */
		if (tal_bytelen(om->enctlv)
		    < crypto_aead_chacha20poly1305_ietf_ABYTES) {
			status_debug("peer %s: enctlv too short for mac",
				     type_to_string(tmpctx, struct node_id, &peer->id));
			return NULL;
		}

		dec = tal_arr(msg, u8,
			      tal_bytelen(om->enctlv)
			      - crypto_aead_chacha20poly1305_ietf_ABYTES);
		ret = crypto_aead_chacha20poly1305_ietf_decrypt(dec, NULL,
								NULL,
								om->enctlv,
								tal_bytelen(om->enctlv),
								NULL, 0,
								npub,
								rho.data);
		if (ret != 0) {
			status_debug("peer %s: Failed to decrypt enctlv field",
				     type_to_string(tmpctx, struct node_id, &peer->id));
			return NULL;
		}

		status_debug("peer %s: enctlv -> %s",
			     type_to_string(tmpctx, struct node_id, &peer->id),
			     tal_hex(tmpctx, dec));

		/* Replace onionmsg with one from enctlv */
		cursor = dec;
		maxlen = tal_bytelen(dec);

		om = tlv_onionmsg_payload_new(msg);
		if (!fromwire_onionmsg_payload(&cursor, &maxlen, om)) {
			status_debug("peer %s: onion msg: invalid enctlv onionmsg_payload %s",
				     type_to_string(tmpctx, struct node_id, &peer->id),
				     tal_hex(tmpctx, dec));
			return NULL;
		}
	} else if (blinding_ss && rs->nextcase != ONION_END) {
		status_debug("peer %s: Onion had %s, but not enctlv?",
			     type_to_string(tmpctx, struct node_id, &peer->id),
			     tlvs->blinding ? "blinding" : "om blinding");
		return NULL;
	}

	if (rs->nextcase == ONION_END) {
		struct pubkey *blinding;
		const struct onionmsg_path **path;
		u8 *omsg;

		if (om->reply_path) {
			blinding = &om->reply_path->blinding;
			path = cast_const2(const struct onionmsg_path **,
					   om->reply_path->path);
		} else {
			blinding = NULL;
			path = NULL;
		}

		/* We re-marshall here by policy, before handing to lightningd */
		omsg = tal_arr(tmpctx, u8, 0);
		towire_tlvstream_raw(&omsg, om->fields);
		daemon_conn_send(peer->daemon->master,
				 take(towire_gossipd_got_onionmsg_to_us(NULL,
							blinding_in,
							blinding,
							path,
							omsg)));
	} else {
		struct pubkey *next_blinding;
		struct node_id *next_node;

		/* This *MUST* have instructions on where to go next. */
		if (!om->next_short_channel_id && !om->next_node_id) {
			status_debug("peer %s: onion msg: no next field in %s",
				     type_to_string(tmpctx, struct node_id, &peer->id),
				     tal_hex(tmpctx, rs->raw_payload));
			return NULL;
		}

		if (blinding_ss) {
			/* E(i-1) = H(E(i) || ss(i)) * E(i) */
			struct sha256 h;
			blinding_hash_e_and_ss(blinding_in, blinding_ss, &h);
			next_blinding = tal(msg, struct pubkey);
			blinding_next_pubkey(blinding_in, &h, next_blinding);
		} else
			next_blinding = NULL;

		if (om->next_node_id) {
			next_node = tal(tmpctx, struct node_id);
			node_id_from_pubkey(next_node, om->next_node_id);
		} else
			next_node = NULL;

		daemon_conn_send(peer->daemon->master,
				 take(towire_gossipd_got_onionmsg_forward(NULL,
						  om->next_short_channel_id,
						  next_node,
						  next_blinding,
						  serialize_onionpacket(tmpctx, rs->next))));
	}
	return NULL;
}

/* We send onion msg. */
static struct io_plan *onionmsg_req(struct io_conn *conn, struct daemon *daemon,
				    const u8 *msg)
{
	struct node_id id;
	u8 onion_routing_packet[TOTAL_PACKET_SIZE(ROUTING_INFO_SIZE)];
	struct pubkey *blinding;
	struct peer *peer;

	if (!fromwire_gossipd_send_onionmsg(msg, msg, &id, onion_routing_packet,
					    &blinding))
		master_badmsg(WIRE_GOSSIPD_SEND_ONIONMSG, msg);

	/* Even if lightningd were to check for valid ids, there's a race
	 * where it might vanish before we read this command; cleaner to
	 * handle it here with 'sent' = false. */
	peer = find_peer(daemon, &id);
	if (peer) {
		struct tlv_onion_message_tlvs *tlvs;

		tlvs = tlv_onion_message_tlvs_new(msg);
		if (blinding)
			tlvs->blinding = tal_dup(tlvs, struct pubkey, blinding);

		queue_peer_msg(peer,
			       take(towire_onion_message(NULL,
							 onion_routing_packet,
							 tlvs)));
	}
	return daemon_conn_read_next(conn, daemon->master);
}
#endif /* EXPERIMENTAL_FEATURES */

/*~ This is where the per-peer daemons send us messages.  It's either forwarded
 * gossip, or a request for information.  We deliberately use non-overlapping
 * message types so we can distinguish them. */
static struct io_plan *peer_msg_in(struct io_conn *conn,
				    const u8 *msg,
				    struct peer *peer)
{
	const u8 *err;
	bool ok;

	/* These are messages relayed from peer */
	switch ((enum peer_wire)fromwire_peektype(msg)) {
	case WIRE_CHANNEL_ANNOUNCEMENT:
		err = handle_channel_announcement_msg(peer, msg);
		goto handled_relay;
	case WIRE_CHANNEL_UPDATE:
		err = handle_channel_update_msg(peer, msg);
		goto handled_relay;
	case WIRE_NODE_ANNOUNCEMENT:
		err = handle_node_announce(peer, msg);
		goto handled_relay;
	case WIRE_QUERY_CHANNEL_RANGE:
		err = handle_query_channel_range(peer, msg);
		goto handled_relay;
	case WIRE_REPLY_CHANNEL_RANGE:
		err = handle_reply_channel_range(peer, msg);
		goto handled_relay;
	case WIRE_QUERY_SHORT_CHANNEL_IDS:
		err = handle_query_short_channel_ids(peer, msg);
		goto handled_relay;
	case WIRE_REPLY_SHORT_CHANNEL_IDS_END:
		err = handle_reply_short_channel_ids_end(peer, msg);
		goto handled_relay;
	case WIRE_PING:
		err = handle_ping(peer, msg);
		goto handled_relay;
	case WIRE_PONG:
		err = handle_pong(peer, msg);
		goto handled_relay;
#if EXPERIMENTAL_FEATURES
	case WIRE_ONION_MESSAGE:
		err = handle_onion_message(peer, msg);
		goto handled_relay;
#endif

	/* These are non-gossip messages (!is_msg_for_gossipd()) */
	case WIRE_INIT:
	case WIRE_ERROR:
	case WIRE_OPEN_CHANNEL:
	case WIRE_ACCEPT_CHANNEL:
	case WIRE_FUNDING_CREATED:
	case WIRE_FUNDING_SIGNED:
	case WIRE_FUNDING_LOCKED:
	case WIRE_SHUTDOWN:
	case WIRE_CLOSING_SIGNED:
	case WIRE_UPDATE_ADD_HTLC:
	case WIRE_UPDATE_FULFILL_HTLC:
	case WIRE_UPDATE_FAIL_HTLC:
	case WIRE_UPDATE_FAIL_MALFORMED_HTLC:
	case WIRE_COMMITMENT_SIGNED:
	case WIRE_REVOKE_AND_ACK:
	case WIRE_UPDATE_FEE:
	case WIRE_CHANNEL_REESTABLISH:
	case WIRE_ANNOUNCEMENT_SIGNATURES:
	case WIRE_GOSSIP_TIMESTAMP_FILTER:
#if EXPERIMENTAL_FEATURES
	case WIRE_TX_ADD_INPUT:
	case WIRE_TX_REMOVE_INPUT:
	case WIRE_TX_ADD_OUTPUT:
	case WIRE_TX_REMOVE_OUTPUT:
	case WIRE_TX_COMPLETE:
	case WIRE_TX_SIGNATURES:
	case WIRE_OPEN_CHANNEL2:
	case WIRE_ACCEPT_CHANNEL2:
	case WIRE_INIT_RBF:
	case WIRE_BLACKLIST_PODLE:
#endif
		status_broken("peer %s: relayed unexpected msg of type %s",
			      type_to_string(tmpctx, struct node_id, &peer->id),
			      peer_wire_name(fromwire_peektype(msg)));
		return io_close(conn);
	}

	/* Must be a gossipd_peerd_wire_type asking us to do something. */
	switch ((enum gossipd_peerd_wire)fromwire_peektype(msg)) {
	case WIRE_GOSSIPD_GET_UPDATE:
		ok = handle_get_local_channel_update(peer, msg);
		goto handled_cmd;
	case WIRE_GOSSIPD_LOCAL_CHANNEL_UPDATE:
		ok = handle_local_channel_update(peer->daemon, &peer->id, msg);
		goto handled_cmd;
	case WIRE_GOSSIPD_LOCAL_CHANNEL_ANNOUNCEMENT:
		ok = handle_local_channel_announcement(peer->daemon, peer, msg);
		goto handled_cmd;

	/* These are the ones we send, not them */
	case WIRE_GOSSIPD_GET_UPDATE_REPLY:
	case WIRE_GOSSIPD_NEW_STORE_FD:
		break;
	}

	if (fromwire_peektype(msg) == WIRE_GOSSIP_STORE_PRIVATE_CHANNEL) {
		ok = routing_add_private_channel(peer->daemon->rstate, peer,
						 msg, 0);
		goto handled_cmd;
	}

	/* Anything else should not have been sent to us: close on it */
	status_peer_broken(&peer->id, "unexpected cmd of type %i %s",
			   fromwire_peektype(msg),
			   gossipd_peerd_wire_name(fromwire_peektype(msg)));
	return io_close(conn);

	/* Commands should always be OK. */
handled_cmd:
	if (!ok)
		return io_close(conn);
	goto done;

	/* Forwarded messages may be bad, so we have error which the per-peer
	 * daemon will forward to the peer. */
handled_relay:
	if (err)
		queue_peer_msg(peer, take(err));
done:
	return daemon_conn_read_next(conn, peer->dc);
}

/*~ This is where connectd tells us about a new peer, and we hand back an fd for
 * it to send us messages via peer_msg_in above */
static struct io_plan *connectd_new_peer(struct io_conn *conn,
					 struct daemon *daemon,
					 const u8 *msg)
{
	struct peer *peer = tal(conn, struct peer);
	int fds[2];
	int gossip_store_fd;
	struct gossip_state *gs;

	if (!fromwire_gossipd_new_peer(msg, &peer->id,
				      &peer->gossip_queries_feature,
				      &peer->initial_routing_sync_feature)) {
		status_broken("Bad new_peer msg from connectd: %s",
			      tal_hex(tmpctx, msg));
		return io_close(conn);
	}

	gossip_store_fd = gossip_store_readonly_fd(daemon->rstate->gs);;
	if (gossip_store_fd < 0) {
		status_broken("Failed to get readonly store fd: %s",
			      strerror(errno));
		daemon_conn_send(daemon->connectd,
				 take(towire_gossipd_new_peer_reply(NULL,
								   false,
								   NULL)));
		goto done;
	}

	/* This can happen: we handle it gracefully, returning a `failed` msg. */
	if (socketpair(AF_LOCAL, SOCK_STREAM, 0, fds) != 0) {
		status_broken("Failed to create socketpair: %s",
			      strerror(errno));
		close(gossip_store_fd);
		daemon_conn_send(daemon->connectd,
				 take(towire_gossipd_new_peer_reply(NULL,
								   false,
								   NULL)));
		goto done;
	}

	/* We might not have noticed old peer is dead; kill it now. */
	tal_free(find_peer(daemon, &peer->id));

	/* Populate the rest of the peer info. */
	peer->daemon = daemon;
	peer->gossip_counter = 0;
	peer->scid_queries = NULL;
	peer->scid_query_idx = 0;
	peer->scid_query_nodes = NULL;
	peer->scid_query_nodes_idx = 0;
	peer->scid_query_outstanding = false;
	peer->range_replies = NULL;
	peer->query_channel_range_cb = NULL;
	peer->num_pings_outstanding = 0;

	/* We keep a list so we can find peer by id */
	list_add_tail(&peer->daemon->peers, &peer->list);
	tal_add_destructor(peer, destroy_peer);

	/* This is the new connection: calls maybe_send_query_responses when
	 * nothing else to send. */
	peer->dc = daemon_conn_new(daemon, fds[0],
				   peer_msg_in,
				   maybe_send_query_responses, peer);
	/* Free peer if conn closed (destroy_peer closes conn if peer freed) */
	tal_steal(peer->dc, peer);

	/* This sends the initial timestamp filter. */
	seeker_setup_peer_gossip(daemon->seeker, peer);

	/* BOLT #7:
	 *
	 * A node:
	 *   - if the `gossip_queries` feature is negotiated:
	 * 	- MUST NOT relay any gossip messages it did not generate itself,
	 *        unless explicitly requested.
	 */
	if (peer->gossip_queries_feature) {
		gs = NULL;
	} else {
		/* BOLT #7:
		 *
		 * - upon receiving an `init` message with the
		 *   `initial_routing_sync` flag set to 1:
		 *   - SHOULD send gossip messages for all known channels and
		 *    nodes, as if they were just received.
		 * - if the `initial_routing_sync` flag is set to 0, OR if the
		 *   initial sync was completed:
		 *   - SHOULD resume normal operation, as specified in the
		 *     following [Rebroadcasting](#rebroadcasting) section.
		 */
		gs = tal(tmpctx, struct gossip_state);
		gs->timestamp_min = 0;
		gs->timestamp_max = UINT32_MAX;

		/* If they don't want initial sync, start at end of store */
		if (!peer->initial_routing_sync_feature)
			lseek(gossip_store_fd, 0, SEEK_END);

		gs->next_gossip = time_mono();
	}

	/* Reply with success, and the new fd and gossip_state. */
	daemon_conn_send(daemon->connectd,
			 take(towire_gossipd_new_peer_reply(NULL, true, gs)));
	daemon_conn_send_fd(daemon->connectd, fds[1]);
	daemon_conn_send_fd(daemon->connectd, gossip_store_fd);

done:
	return daemon_conn_read_next(conn, daemon->connectd);
}

/*~ connectd can also ask us if we know any addresses for a given id. */
static struct io_plan *connectd_get_address(struct io_conn *conn,
					    struct daemon *daemon,
					    const u8 *msg)
{
	struct node_id id;
	u8 rgb_color[3];
	u8 alias[32];
	u8 *features;
	struct wireaddr *addrs;

	if (!fromwire_gossipd_get_addrs(msg, &id)) {
		status_broken("Bad gossipd_get_addrs msg from connectd: %s",
			      tal_hex(tmpctx, msg));
		return io_close(conn);
	}

	if (!get_node_announcement_by_id(tmpctx, daemon, &id,
					 rgb_color, alias, &features, &addrs))
		addrs = NULL;

	daemon_conn_send(daemon->connectd,
			 take(towire_gossipd_get_addrs_reply(NULL, addrs)));
	return daemon_conn_read_next(conn, daemon->connectd);
}

/*~ connectd's input handler is very simple. */
static struct io_plan *connectd_req(struct io_conn *conn,
				    const u8 *msg,
				    struct daemon *daemon)
{
	enum connectd_gossipd_wire t = fromwire_peektype(msg);

	switch (t) {
	case WIRE_GOSSIPD_NEW_PEER:
		return connectd_new_peer(conn, daemon, msg);

	case WIRE_GOSSIPD_GET_ADDRS:
		return connectd_get_address(conn, daemon, msg);

	/* We send these, don't receive them. */
	case WIRE_GOSSIPD_NEW_PEER_REPLY:
	case WIRE_GOSSIPD_GET_ADDRS_REPLY:
		break;
	}

	status_broken("Bad msg from connectd: %s",
		      tal_hex(tmpctx, msg));
	return io_close(conn);
}

/*~ This is our 13-day timer callback for refreshing our channels.  This
 * was added to the spec because people abandoned their channels without
 * closing them. */
static void gossip_send_keepalive_update(struct daemon *daemon,
					 struct local_chan *local_chan)
{
	status_debug("Sending keepalive channel_update for %s/%u",
		     type_to_string(tmpctx, struct short_channel_id,
				    &local_chan->chan->scid),
		     local_chan->direction);

	/* As a side-effect, this will create an update which matches the
	 * local_disabled state */
	refresh_local_channel(daemon, local_chan, true);
}


/* BOLT #7:
 *
 * A node:
 *  - if a channel's oldest `channel_update`s `timestamp` is older than two weeks
 *    (1209600 seconds):
 *     - MAY prune the channel.
 *     - MAY ignore the channel.
 */
static void gossip_refresh_network(struct daemon *daemon)
{
	u64 now = gossip_time_now(daemon->rstate).ts.tv_sec;
	s64 highwater;
	struct node *n;

	/* Send out 1 day before deadline */
	highwater = now - (GOSSIP_PRUNE_INTERVAL(daemon->rstate->dev_fast_gossip)
			   - GOSSIP_BEFORE_DEADLINE(daemon->rstate->dev_fast_gossip_prune));

	/* Schedule next run now */
	notleak(new_reltimer(&daemon->timers, daemon,
			     time_from_sec(GOSSIP_PRUNE_INTERVAL(daemon->rstate->dev_fast_gossip_prune)/4),
			     gossip_refresh_network, daemon));

	/* Find myself in the network */
	n = get_node(daemon->rstate, &daemon->id);
	if (n) {
		/* Iterate through all outgoing connection and check whether
		 * it's time to re-announce */
		struct chan_map_iter i;
		struct chan *c;

		for (c = first_chan(n, &i); c; c = next_chan(n, &i)) {
			struct local_chan *local_chan;
			struct half_chan *hc;

			local_chan = is_local_chan(daemon->rstate, c);
			hc = &c->half[local_chan->direction];

			if (!is_halfchan_defined(hc)) {
				/* Connection is not announced yet, so don't even
				 * try to re-announce it */
				continue;
			}

			if (hc->bcast.timestamp > highwater) {
				/* No need to send a keepalive update message */
				continue;
			}

			if (!is_halfchan_enabled(hc)) {
				/* Only send keepalives for active connections */
				continue;
			}

			gossip_send_keepalive_update(daemon, local_chan);
		}
	}

	/* Now we've refreshed our channels, we can prune without clobbering
	 * them */
	route_prune(daemon->rstate);
}

/* Disables all channels connected to our node. */
static void gossip_disable_local_channels(struct daemon *daemon)
{
	struct node *local_node = get_node(daemon->rstate, &daemon->id);
	struct chan_map_iter i;
	struct chan *c;

	/* We don't have a local_node, so we don't have any channels yet
	 * either */
	if (!local_node)
		return;

	for (c = first_chan(local_node, &i); c; c = next_chan(local_node, &i))
		local_disable_chan(daemon->rstate, c);
}

struct peer *random_peer(struct daemon *daemon,
			 bool (*check_peer)(const struct peer *peer))
{
	u64 target = UINT64_MAX;
	struct peer *best = NULL, *i;

	/* Reservoir sampling */
	list_for_each(&daemon->peers, i, list) {
		u64 r;

		if (!check_peer(i))
			continue;

		r = pseudorand_u64();
		if (r <= target) {
			best = i;
			target = r;
		}
	}
	return best;
}

/*~ Parse init message from lightningd: starts the daemon properly. */
static struct io_plan *gossip_init(struct io_conn *conn,
				   struct daemon *daemon,
				   const u8 *msg)
{
	u32 *dev_gossip_time;
	bool dev_fast_gossip, dev_fast_gossip_prune;
	u32 timestamp;

	if (!fromwire_gossipd_init(daemon, msg,
				     &chainparams,
				     &daemon->our_features,
				     &daemon->id,
				     daemon->rgb,
				     daemon->alias,
				     &daemon->announcable,
				     &dev_gossip_time,
				     &dev_fast_gossip,
				     &dev_fast_gossip_prune)) {
		master_badmsg(WIRE_GOSSIPD_INIT, msg);
	}

	daemon->rstate = new_routing_state(daemon,
					   &daemon->id,
					   &daemon->peers,
					   &daemon->timers,
					   take(dev_gossip_time),
					   dev_fast_gossip,
					   dev_fast_gossip_prune);

	/* Load stored gossip messages, get last modified time of file */
	timestamp = gossip_store_load(daemon->rstate, daemon->rstate->gs);

	/* If last_timestamp was > modified time of file, reduce it.
	 * Usually it's capped to "now", but in the reload case it needs to
	 * be the gossip_store mtime. */
	if (daemon->rstate->last_timestamp > timestamp)
		daemon->rstate->last_timestamp = timestamp;

	/* Now disable all local channels, they can't be connected yet. */
	gossip_disable_local_channels(daemon);

	/* If that announced channels, we can announce ourselves (options
	 * or addresses might have changed!) */
	maybe_send_own_node_announce(daemon);

	/* Start the twice- weekly refresh timer. */
	notleak(new_reltimer(&daemon->timers, daemon,
			     time_from_sec(GOSSIP_PRUNE_INTERVAL(daemon->rstate->dev_fast_gossip_prune) / 4),
			     gossip_refresh_network, daemon));

	/* Fire up the seeker! */
	daemon->seeker = new_seeker(daemon);

	return daemon_conn_read_next(conn, daemon->master);
}

/*~ lightningd can ask for a route between nodes. */
static struct io_plan *getroute_req(struct io_conn *conn, struct daemon *daemon,
				    const u8 *msg)
{
	struct node_id *source, destination;
	struct amount_msat msat;
	u32 final_cltv;
	/* risk factor 12.345% -> riskfactor_millionths = 12345000 */
	u64 riskfactor_millionths;
	u32 max_hops;
	u8 *out;
	struct route_hop **hops;
	/* fuzz 12.345% -> fuzz_millionths = 12345000 */
	u64 fuzz_millionths;
	struct exclude_entry **excluded;

	/* To choose between variations, we need to know how much we're
	 * sending (eliminates too-small channels, and also effects the fees
	 * we'll pay), how to trade off more locktime vs. more fees, and how
	 * much cltv we need a the final node to give exact values for each
	 * intermediate hop, as well as how much random fuzz to inject to
	 * avoid being too predictable.
	 *
	 * We also treat routing slightly differently if we're asking
	 * for a route from ourselves (the usual case): in that case,
	 * we don't have to consider fees on our own outgoing channels.
	 */
	if (!fromwire_gossipd_getroute_request(
		msg, msg, &source, &destination, &msat, &riskfactor_millionths,
		&final_cltv, &fuzz_millionths, &excluded, &max_hops))
		master_badmsg(WIRE_GOSSIPD_GETROUTE_REQUEST, msg);

	status_debug("Trying to find a route from %s to %s for %s",
		     source
		     ? type_to_string(tmpctx, struct node_id, source) : "(me)",
		     type_to_string(tmpctx, struct node_id, &destination),
		     type_to_string(tmpctx, struct amount_msat, &msat));

	/* routing.c does all the hard work; can return NULL. */
	hops = get_route(tmpctx, daemon->rstate, source, &destination, msat,
			 riskfactor_millionths / 1000000.0, final_cltv,
			 fuzz_millionths / 1000000.0, pseudorand_u64(),
			 excluded, max_hops);

	out = towire_gossipd_getroute_reply(NULL,
					   cast_const2(const struct route_hop **,
						       hops));
	daemon_conn_send(daemon->master, take(out));
	return daemon_conn_read_next(conn, daemon->master);
}

/*~ When someone asks lightningd to `listchannels`, gossipd does the work:
 * marshalling the channel information for all channels into an array of
 * gossip_getchannels_entry, which lightningd converts to JSON.  Each channel
 * is represented by two half_chan; one in each direction.
 */
static struct gossip_halfchannel_entry *hc_entry(const tal_t *ctx,
						 const struct chan *chan,
						 int idx)
{
	/* Our 'struct chan' contains two nodes: they are in pubkey_cmp order
	 * (ie. chan->nodes[0] is the lesser pubkey) and this is the same as
	 * the direction bit in `channel_update`s `channel_flags`.
	 *
	 * The halfchans are arranged so that half[0] src == nodes[0], and we
	 * use that here. */
	const struct half_chan *c = &chan->half[idx];
	struct gossip_halfchannel_entry *e;

	/* If we've never seen a channel_update for this direction... */
	if (!is_halfchan_defined(c))
		return NULL;

	e = tal(ctx, struct gossip_halfchannel_entry);
	e->channel_flags = c->channel_flags;
	e->message_flags = c->message_flags;
	e->last_update_timestamp = c->bcast.timestamp;
	e->base_fee_msat = c->base_fee;
	e->fee_per_millionth = c->proportional_fee;
	e->delay = c->delay;
	e->min = c->htlc_minimum;
	e->max = c->htlc_maximum;

	return e;
}

/*~ We don't keep channel features in memory; they're rarely used.  So we
 * remember if it exists, and load it off disk when needed. */
static u8 *get_channel_features(const tal_t *ctx,
				struct gossip_store *gs,
				const struct chan *chan)
{
	secp256k1_ecdsa_signature sig;
	u8 *features;
	struct bitcoin_blkid chain_hash;
	struct short_channel_id short_channel_id;
	struct node_id node_id;
	struct pubkey bitcoin_key;
	struct amount_sat sats;
	u8 *ann;

	/* This is where we stash a flag to indicate it exists. */
	if (!chan->half[0].any_features)
		return NULL;

	ann = cast_const(u8 *, gossip_store_get(tmpctx, gs, chan->bcast.index));

	/* Could be a private_channel */
	fromwire_gossip_store_private_channel(tmpctx, ann, &sats, &ann);

	if (!fromwire_channel_announcement(ctx, ann, &sig, &sig, &sig, &sig,
					   &features, &chain_hash,
					   &short_channel_id,
					   &node_id, &node_id,
					   &bitcoin_key, &bitcoin_key))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "bad channel_announcement / local_add_channel at %u: %s",
			      chan->bcast.index, tal_hex(tmpctx, ann));

	return features;
}

/*~ Marshal (possibly) both channel directions into entries. */
static void append_channel(struct routing_state *rstate,
			   const struct gossip_getchannels_entry ***entries,
			   const struct chan *chan,
			   const struct node_id *srcfilter)
{
	struct gossip_getchannels_entry *e = tal(*entries, struct gossip_getchannels_entry);

	e->node[0] = chan->nodes[0]->id;
	e->node[1] = chan->nodes[1]->id;
	e->sat = chan->sat;
	e->local_disabled = is_chan_local_disabled(rstate, chan);
	e->public = is_chan_public(chan);
	e->short_channel_id = chan->scid;
	e->features = get_channel_features(e, rstate->gs, chan);
	if (!srcfilter || node_id_eq(&e->node[0], srcfilter))
		e->e[0] = hc_entry(*entries, chan, 0);
	else
		e->e[0] = NULL;
	if (!srcfilter || node_id_eq(&e->node[1], srcfilter))
		e->e[1] = hc_entry(*entries, chan, 1);
	else
		e->e[1] = NULL;

	/* We choose not to tell lightningd about channels with no updates,
	 * as they're unusable and can't be represented in the listchannels
	 * JSON output we use anyway. */
	if (e->e[0] || e->e[1])
		tal_arr_expand(entries, e);
}

/*~ This is where lightningd asks for all channels we know about. */
static struct io_plan *getchannels_req(struct io_conn *conn,
				       struct daemon *daemon,
				       const u8 *msg)
{
	u8 *out;
	const struct gossip_getchannels_entry **entries;
	struct chan *chan;
	struct short_channel_id *scid, *prev;
	struct node_id *source;
	bool complete = true;

	/* Note: scid is marked optional in gossip_wire.csv */
	if (!fromwire_gossipd_getchannels_request(msg, msg, &scid, &source,
						 &prev))
		master_badmsg(WIRE_GOSSIPD_GETCHANNELS_REQUEST, msg);

	entries = tal_arr(tmpctx, const struct gossip_getchannels_entry *, 0);
	/* They can ask about a particular channel by short_channel_id */
	if (scid) {
		chan = get_channel(daemon->rstate, scid);
		if (chan)
			append_channel(daemon->rstate, &entries, chan, NULL);
	} else if (source) {
		struct node *s = get_node(daemon->rstate, source);
		if (s) {
			struct chan_map_iter i;
			struct chan *c;

			for (c = first_chan(s, &i); c; c = next_chan(s, &i)) {
				append_channel(daemon->rstate,
					       &entries, c, source);
			}
		}
	} else {
		u64 idx;

		/* For the more general case, we just iterate through every
		 * short channel id, starting with previous if any (there is
		 * no scid 0). */
		idx = prev ? prev->u64 : 0;
		while ((chan = uintmap_after(&daemon->rstate->chanmap, &idx))) {
			append_channel(daemon->rstate, &entries, chan, NULL);
			/* Limit how many we do at once. */
			if (tal_count(entries) == 4096) {
				complete = false;
				break;
			}
		}
	}

	out = towire_gossipd_getchannels_reply(NULL, complete, entries);
	daemon_conn_send(daemon->master, take(out));
	return daemon_conn_read_next(conn, daemon->master);
}

/*~ Similarly, lightningd asks us for all nodes when it gets `listnodes` */
/* We keep pointers into n, assuming it won't change. */
static void add_node_entry(const tal_t *ctx,
			   struct daemon *daemon,
			   const struct node *n,
			   struct gossip_getnodes_entry *e)
{
	e->nodeid = n->id;
	if (get_node_announcement(ctx, daemon, n,
				  e->color, e->alias,
				  &e->features,
				  &e->addresses)) {
		e->last_timestamp = n->bcast.timestamp;
	} else {
		/* Timestamp on wire is an unsigned 32 bit: we use a 64-bit
		 * signed, so -1 means "we never received a
		 * channel_update". */
		e->last_timestamp = -1;
	}
}

/* Simply routine when they ask for `listnodes` */
static struct io_plan *getnodes(struct io_conn *conn, struct daemon *daemon,
				const u8 *msg)
{
	u8 *out;
	struct node *n;
	const struct gossip_getnodes_entry **nodes;
	struct gossip_getnodes_entry *node_arr;
	struct node_id *id;

	if (!fromwire_gossipd_getnodes_request(tmpctx, msg, &id))
		master_badmsg(WIRE_GOSSIPD_GETNODES_REQUEST, msg);

	/* Format of reply is the same whether they ask for a specific node
	 * (0 or one responses) or all nodes (0 or more) */
	if (id) {
		n = get_node(daemon->rstate, id);
		if (n) {
			node_arr = tal_arr(tmpctx,
					   struct gossip_getnodes_entry,
					   1);
			add_node_entry(node_arr, daemon, n, &node_arr[0]);
		} else {
			nodes = NULL;
			node_arr = NULL;
		}
	} else {
		struct node_map_iter it;
		size_t i = 0;
		node_arr = tal_arr(tmpctx, struct gossip_getnodes_entry,
				   node_map_count(daemon->rstate->nodes));
		n = node_map_first(daemon->rstate->nodes, &it);
		while (n != NULL) {
			add_node_entry(node_arr, daemon, n, &node_arr[i++]);
			n = node_map_next(daemon->rstate->nodes, &it);
		}
		assert(i == node_map_count(daemon->rstate->nodes));
	}

	/* FIXME: towire wants array of pointers. */
	nodes = tal_arr(tmpctx, const struct gossip_getnodes_entry *,
			tal_count(node_arr));
	for (size_t i = 0; i < tal_count(node_arr); i++)
		nodes[i] = &node_arr[i];
	out = towire_gossipd_getnodes_reply(NULL, nodes);
	daemon_conn_send(daemon->master, take(out));
	return daemon_conn_read_next(conn, daemon->master);
}

/*~ We currently have a JSON command to ping a peer: it ends up here, where
 * gossipd generates the actual ping and sends it like any other gossip. */
static struct io_plan *ping_req(struct io_conn *conn, struct daemon *daemon,
				const u8 *msg)
{
	struct node_id id;
	u16 num_pong_bytes, len;
	struct peer *peer;
	u8 *ping;

	if (!fromwire_gossipd_ping(msg, &id, &num_pong_bytes, &len))
		master_badmsg(WIRE_GOSSIPD_PING, msg);

	/* Even if lightningd were to check for valid ids, there's a race
	 * where it might vanish before we read this command; cleaner to
	 * handle it here with 'sent' = false. */
	peer = find_peer(daemon, &id);
	if (!peer) {
		daemon_conn_send(daemon->master,
				 take(towire_gossipd_ping_reply(NULL, &id,
							       false, 0)));
		goto out;
	}

	/* It should never ask for an oversize ping. */
	ping = make_ping(peer, num_pong_bytes, len);
	if (tal_count(ping) > 65535)
		status_failed(STATUS_FAIL_MASTER_IO, "Oversize ping");

	queue_peer_msg(peer, take(ping));
	status_peer_debug(&peer->id, "sending ping expecting %sresponse",
			  num_pong_bytes >= 65532 ? "no " : "");

	/* BOLT #1:
	 *
	 * A node receiving a `ping` message:
	 *...
	 *  - if `num_pong_bytes` is less than 65532:
	 *    - MUST respond by sending a `pong` message, with `byteslen` equal
	 *      to `num_pong_bytes`.
	 *  - otherwise (`num_pong_bytes` is **not** less than 65532):
	 *    - MUST ignore the `ping`.
	 */
	if (num_pong_bytes >= 65532)
		daemon_conn_send(daemon->master,
				 take(towire_gossipd_ping_reply(NULL, &id,
							       true, 0)));
	else
		/* We'll respond to lightningd once the pong comes in */
		peer->num_pings_outstanding++;

out:
	return daemon_conn_read_next(conn, daemon->master);
}

/*~ If a node has no public channels (other than the one to us), it's not
 * a very useful route to tell anyone about. */
static bool node_has_public_channels(const struct node *peer,
				     const struct chan *exclude)
{
	struct chan_map_iter i;
	struct chan *c;

	for (c = first_chan(peer, &i); c; c = next_chan(peer, &i)) {
		if (c == exclude)
			continue;
		if (is_chan_public(c))
			return true;
	}
	return false;
}

/*~ For routeboost, we offer payers a hint of what incoming channels might
 * have capacity for their payment.  To do this, lightningd asks for the
 * information about all channels to this node; but gossipd doesn't know about
 * current capacities, so lightningd selects which to use. */
static struct io_plan *get_incoming_channels(struct io_conn *conn,
					     struct daemon *daemon,
					     const u8 *msg)
{
	struct node *node;
	struct route_info *public = tal_arr(tmpctx, struct route_info, 0);
	struct route_info *private = tal_arr(tmpctx, struct route_info, 0);
	bool *priv_deadends = tal_arr(tmpctx, bool, 0);
	bool *pub_deadends = tal_arr(tmpctx, bool, 0);

	if (!fromwire_gossipd_get_incoming_channels(msg))
		master_badmsg(WIRE_GOSSIPD_GET_INCOMING_CHANNELS, msg);

	node = get_node(daemon->rstate, &daemon->rstate->local_id);
	if (node) {
		struct chan_map_iter i;
		struct chan *c;

		for (c = first_chan(node, &i); c; c = next_chan(node, &i)) {
			const struct half_chan *hc;
			struct route_info ri;
			bool deadend;

			hc = &c->half[half_chan_to(node, c)];

			if (!is_halfchan_enabled(hc))
				continue;

			ri.pubkey = other_node(node, c)->id;
			ri.short_channel_id = c->scid;
			ri.fee_base_msat = hc->base_fee;
			ri.fee_proportional_millionths = hc->proportional_fee;
			ri.cltv_expiry_delta = hc->delay;

			deadend = !node_has_public_channels(other_node(node, c),
							    c);
			if (is_chan_public(c)) {
				tal_arr_expand(&public, ri);
				tal_arr_expand(&pub_deadends, deadend);
			} else {
				tal_arr_expand(&private, ri);
				tal_arr_expand(&priv_deadends, deadend);
			}
		}
	}

	msg = towire_gossipd_get_incoming_channels_reply(NULL,
							public, pub_deadends,
							private, priv_deadends);
	daemon_conn_send(daemon->master, take(msg));

	return daemon_conn_read_next(conn, daemon->master);
}

static struct io_plan *new_blockheight(struct io_conn *conn,
				       struct daemon *daemon,
				       const u8 *msg)
{
	if (!fromwire_gossipd_new_blockheight(msg, &daemon->current_blockheight))
		master_badmsg(WIRE_GOSSIPD_NEW_BLOCKHEIGHT, msg);

	/* Check if we can now send any deferred queries. */
	for (size_t i = 0; i < tal_count(daemon->deferred_txouts); i++) {
		const struct short_channel_id *scid
			= &daemon->deferred_txouts[i];

		if (!is_scid_depth_announceable(scid,
						daemon->current_blockheight))
			continue;

		/* short_channel_id is deep enough, now ask about it. */
		daemon_conn_send(daemon->master,
				 take(towire_gossipd_get_txout(NULL, scid)));

		tal_arr_remove(&daemon->deferred_txouts, i);
		i--;
	}

	return daemon_conn_read_next(conn, daemon->master);
}

#if DEVELOPER
/* Another testing hack */
static struct io_plan *dev_gossip_suppress(struct io_conn *conn,
					   struct daemon *daemon,
					   const u8 *msg)
{
	if (!fromwire_gossipd_dev_suppress(msg))
		master_badmsg(WIRE_GOSSIPD_DEV_SUPPRESS, msg);

	status_unusual("Suppressing all gossip");
	dev_suppress_gossip = true;
	return daemon_conn_read_next(conn, daemon->master);
}

static struct io_plan *dev_gossip_memleak(struct io_conn *conn,
					  struct daemon *daemon,
					  const u8 *msg)
{
	struct htable *memtable;
	bool found_leak;

	memtable = memleak_find_allocations(tmpctx, msg, msg);

	/* Now delete daemon and those which it has pointers to. */
	memleak_remove_region(memtable, daemon, sizeof(*daemon));

	found_leak = dump_memleak(memtable);
	daemon_conn_send(daemon->master,
			 take(towire_gossipd_dev_memleak_reply(NULL,
							      found_leak)));
	return daemon_conn_read_next(conn, daemon->master);
}

static struct io_plan *dev_compact_store(struct io_conn *conn,
					 struct daemon *daemon,
					 const u8 *msg)
{
	bool done = gossip_store_compact(daemon->rstate->gs);

	daemon_conn_send(daemon->master,
			 take(towire_gossipd_dev_compact_store_reply(NULL,
								    done)));
	return daemon_conn_read_next(conn, daemon->master);
}

static struct io_plan *dev_gossip_set_time(struct io_conn *conn,
					   struct daemon *daemon,
					   const u8 *msg)
{
	u32 time;

	if (!fromwire_gossipd_dev_set_time(msg, &time))
		master_badmsg(WIRE_GOSSIPD_DEV_SET_TIME, msg);
	if (!daemon->rstate->gossip_time)
		daemon->rstate->gossip_time = tal(daemon->rstate, struct timeabs);
	daemon->rstate->gossip_time->ts.tv_sec = time;
	daemon->rstate->gossip_time->ts.tv_nsec = 0;

	return daemon_conn_read_next(conn, daemon->master);
}
#endif /* DEVELOPER */

/*~ lightningd: so, get me the latest update for this local channel,
 *  so I can include it in an error message. */
static struct io_plan *get_stripped_cupdate(struct io_conn *conn,
					    struct daemon *daemon, const u8 *msg)
{
	struct short_channel_id scid;
	struct local_chan *local_chan;
	const u8 *stripped_update;

	if (!fromwire_gossipd_get_stripped_cupdate(msg, &scid))
		master_badmsg(WIRE_GOSSIPD_GET_STRIPPED_CUPDATE, msg);

	local_chan = local_chan_map_get(&daemon->rstate->local_chan_map, &scid);
	if (!local_chan) {
		status_debug("Failed to resolve local channel %s",
			     type_to_string(tmpctx, struct short_channel_id, &scid));
		stripped_update = NULL;
	} else {
		const struct half_chan *hc;

		/* Since we're going to use it, make sure it's up-to-date. */
		refresh_local_channel(daemon, local_chan, false);

		hc = &local_chan->chan->half[local_chan->direction];
		if (is_halfchan_defined(hc)) {
			const u8 *update;

			update = gossip_store_get(tmpctx, daemon->rstate->gs,
						  hc->bcast.index);
			stripped_update = tal_dup_arr(tmpctx, u8, update + 2,
						      tal_count(update) - 2, 0);
		} else
			stripped_update = NULL;
	}
	daemon_conn_send(daemon->master,
			 take(towire_gossipd_get_stripped_cupdate_reply(NULL,
							   stripped_update)));
	return daemon_conn_read_next(conn, daemon->master);
}

/*~ We queue incoming channel_announcement pending confirmation from lightningd
 * that it really is an unspent output.  Here's its reply. */
static struct io_plan *handle_txout_reply(struct io_conn *conn,
					  struct daemon *daemon, const u8 *msg)
{
	struct short_channel_id scid;
	u8 *outscript;
	struct amount_sat sat;
	bool good;

	if (!fromwire_gossipd_get_txout_reply(msg, msg, &scid, &sat, &outscript))
		master_badmsg(WIRE_GOSSIPD_GET_TXOUT_REPLY, msg);

	/* Outscript is NULL if it's not an unspent output */
	good = handle_pending_cannouncement(daemon, daemon->rstate,
					    &scid, sat, outscript);

	/* If we looking specifically for this, we no longer are. */
	remove_unknown_scid(daemon->seeker, &scid, good);

	/* Anywhere we might have announced a channel, we check if it's time to
	 * announce ourselves (ie. if we just announced our own first channel) */
	maybe_send_own_node_announce(daemon);

	return daemon_conn_read_next(conn, daemon->master);
}

/* Fix up the channel_update to include the type if it doesn't currently have
 * one. See ElementsProject/lightning#1730 and lightningnetwork/lnd#1599 for the
 * in-depth discussion on why we break message parsing here... */
static u8 *patch_channel_update(const tal_t *ctx, u8 *channel_update TAKES)
{
	u8 *fixed;
	if (channel_update != NULL &&
	    fromwire_peektype(channel_update) != WIRE_CHANNEL_UPDATE) {
		/* This should be a channel_update, prefix with the
		 * WIRE_CHANNEL_UPDATE type, but isn't. Let's prefix it. */
		fixed = tal_arr(ctx, u8, 0);
		towire_u16(&fixed, WIRE_CHANNEL_UPDATE);
		towire(&fixed, channel_update, tal_bytelen(channel_update));
		if (taken(channel_update))
			tal_free(channel_update);
		return fixed;
	} else {
		return tal_dup_talarr(ctx, u8, channel_update);
	}
}

/* Return NULL if the wrapped onion error message has no channel_update field,
 * or return the embedded channel_update message otherwise. */
static u8 *channel_update_from_onion_error(const tal_t *ctx,
					   const u8 *onion_message)
{
	u8 *channel_update = NULL;
	struct amount_msat unused_msat;
	u32 unused32;

	/* Identify failcodes that have some channel_update.
	 *
	 * TODO > BOLT 1.0: Add new failcodes when updating to a
	 * new BOLT version. */
	if (!fromwire_temporary_channel_failure(ctx,
						onion_message,
						&channel_update) &&
	    !fromwire_amount_below_minimum(ctx,
					   onion_message, &unused_msat,
					   &channel_update) &&
	    !fromwire_fee_insufficient(ctx,
		    		       onion_message, &unused_msat,
				       &channel_update) &&
	    !fromwire_incorrect_cltv_expiry(ctx,
		    			    onion_message, &unused32,
					    &channel_update) &&
	    !fromwire_expiry_too_soon(ctx,
		    		      onion_message,
				      &channel_update))
		/* No channel update. */
		return NULL;

	return patch_channel_update(ctx, take(channel_update));
}

/*~ lightningd tells us when a payment has failed; we mark the channel (or
 * node) unusable here if it's a permanent failure, and unpack any
 * channel_update contained in the error. */
static struct io_plan *handle_payment_failure(struct io_conn *conn,
					      struct daemon *daemon,
					      const u8 *msg)
{
	u8 *error;
	u8 *channel_update;

	if (!fromwire_gossipd_payment_failure(msg, msg, &error))
		master_badmsg(WIRE_GOSSIPD_PAYMENT_FAILURE, msg);

	channel_update = channel_update_from_onion_error(tmpctx, error);
	if (channel_update) {
		status_debug("Extracted channel_update %s from onionreply %s",
			     tal_hex(tmpctx, channel_update),
			     tal_hex(tmpctx, error));
		u8 *err = handle_channel_update(daemon->rstate, channel_update,
						NULL, NULL);
		if (err) {
			status_info("extracted bad channel_update %s from onionreply %s",
				    sanitize_error(err, err, NULL),
				    error);
			tal_free(err);
		}
	}

	return daemon_conn_read_next(conn, daemon->master);
}

/*~ This is where lightningd tells us that a channel's funding transaction has
 * been spent. */
static struct io_plan *handle_outpoint_spent(struct io_conn *conn,
					     struct daemon *daemon,
					     const u8 *msg)
{
	struct short_channel_id scid;
	struct chan *chan;
	struct routing_state *rstate = daemon->rstate;
	if (!fromwire_gossipd_outpoint_spent(msg, &scid))
		master_badmsg(WIRE_GOSSIPD_OUTPOINT_SPENT, msg);

	chan = get_channel(rstate, &scid);
	if (chan) {
		status_debug(
		    "Deleting channel %s due to the funding outpoint being "
		    "spent",
		    type_to_string(msg, struct short_channel_id, &scid));
		/* Suppress any now-obsolete updates/announcements */
		add_to_txout_failures(rstate, &scid);
		remove_channel_from_store(rstate, chan);
		/* Freeing is sufficient since everything else is allocated off
		 * of the channel and this takes care of unregistering
		 * the channel */
		free_chan(rstate, chan);
	}

	return daemon_conn_read_next(conn, daemon->master);
}

/*~ This is sent by lightningd when it kicks off 'closingd': we disable it
 * in both directions.
 *
 * We'll leave it to handle_outpoint_spent to delete the channel from our view
 * once the close gets confirmed. This avoids having strange states in which the
 * channel is list in our peer list but won't be returned when listing public
 * channels. This does not send out updates since that's triggered by the peer
 * connection closing.
 */
static struct io_plan *handle_local_channel_close(struct io_conn *conn,
						  struct daemon *daemon,
						  const u8 *msg)
{
	struct short_channel_id scid;
	struct chan *chan;
	struct routing_state *rstate = daemon->rstate;
	if (!fromwire_gossipd_local_channel_close(msg, &scid))
		master_badmsg(WIRE_GOSSIPD_LOCAL_CHANNEL_CLOSE, msg);

	chan = get_channel(rstate, &scid);
	if (chan)
		local_disable_chan(rstate, chan);
	return daemon_conn_read_next(conn, daemon->master);
}

/*~ This routine handles all the commands from lightningd. */
static struct io_plan *recv_req(struct io_conn *conn,
				const u8 *msg,
				struct daemon *daemon)
{
	enum gossipd_wire t = fromwire_peektype(msg);

	switch (t) {
	case WIRE_GOSSIPD_INIT:
		return gossip_init(conn, daemon, msg);

	case WIRE_GOSSIPD_GETNODES_REQUEST:
		return getnodes(conn, daemon, msg);

	case WIRE_GOSSIPD_GETROUTE_REQUEST:
		return getroute_req(conn, daemon, msg);

	case WIRE_GOSSIPD_GETCHANNELS_REQUEST:
		return getchannels_req(conn, daemon, msg);

	case WIRE_GOSSIPD_GET_STRIPPED_CUPDATE:
		return get_stripped_cupdate(conn, daemon, msg);

	case WIRE_GOSSIPD_GET_TXOUT_REPLY:
		return handle_txout_reply(conn, daemon, msg);

	case WIRE_GOSSIPD_PAYMENT_FAILURE:
		return handle_payment_failure(conn, daemon, msg);

	case WIRE_GOSSIPD_OUTPOINT_SPENT:
		return handle_outpoint_spent(conn, daemon, msg);

	case WIRE_GOSSIPD_LOCAL_CHANNEL_CLOSE:
		return handle_local_channel_close(conn, daemon, msg);

	case WIRE_GOSSIPD_PING:
		return ping_req(conn, daemon, msg);

	case WIRE_GOSSIPD_GET_INCOMING_CHANNELS:
		return get_incoming_channels(conn, daemon, msg);

	case WIRE_GOSSIPD_NEW_BLOCKHEIGHT:
		return new_blockheight(conn, daemon, msg);

#if DEVELOPER
	case WIRE_GOSSIPD_DEV_SET_MAX_SCIDS_ENCODE_SIZE:
		return dev_set_max_scids_encode_size(conn, daemon, msg);
	case WIRE_GOSSIPD_DEV_SUPPRESS:
		return dev_gossip_suppress(conn, daemon, msg);
	case WIRE_GOSSIPD_DEV_MEMLEAK:
		return dev_gossip_memleak(conn, daemon, msg);
	case WIRE_GOSSIPD_DEV_COMPACT_STORE:
		return dev_compact_store(conn, daemon, msg);
	case WIRE_GOSSIPD_DEV_SET_TIME:
		return dev_gossip_set_time(conn, daemon, msg);
#else
	case WIRE_GOSSIPD_DEV_SET_MAX_SCIDS_ENCODE_SIZE:
	case WIRE_GOSSIPD_DEV_SUPPRESS:
	case WIRE_GOSSIPD_DEV_MEMLEAK:
	case WIRE_GOSSIPD_DEV_COMPACT_STORE:
	case WIRE_GOSSIPD_DEV_SET_TIME:
		break;
#endif /* !DEVELOPER */

	case WIRE_GOSSIPD_SEND_ONIONMSG:
#if EXPERIMENTAL_FEATURES
		return onionmsg_req(conn, daemon, msg);
#endif
	/* We send these, we don't receive them */
	case WIRE_GOSSIPD_GETNODES_REPLY:
	case WIRE_GOSSIPD_GETROUTE_REPLY:
	case WIRE_GOSSIPD_GETCHANNELS_REPLY:
	case WIRE_GOSSIPD_PING_REPLY:
	case WIRE_GOSSIPD_GET_STRIPPED_CUPDATE_REPLY:
	case WIRE_GOSSIPD_GET_INCOMING_CHANNELS_REPLY:
	case WIRE_GOSSIPD_GET_TXOUT:
	case WIRE_GOSSIPD_DEV_MEMLEAK_REPLY:
	case WIRE_GOSSIPD_DEV_COMPACT_STORE_REPLY:
	case WIRE_GOSSIPD_GOT_ONIONMSG_TO_US:
	case WIRE_GOSSIPD_GOT_ONIONMSG_FORWARD:
		break;
	}

	/* Master shouldn't give bad requests. */
	status_failed(STATUS_FAIL_MASTER_IO, "%i: %s",
		      t, tal_hex(tmpctx, msg));
}

/* This is called when lightningd closes its connection to us.  We simply
 * exit. */
static void master_gone(struct daemon_conn *master UNUSED)
{
	daemon_shutdown();
	/* Can't tell master, it's gone. */
	exit(2);
}

int main(int argc, char *argv[])
{
	setup_locale();

	struct daemon *daemon;

	subdaemon_setup(argc, argv);

	daemon = tal(NULL, struct daemon);
	list_head_init(&daemon->peers);
	daemon->deferred_txouts = tal_arr(daemon, struct short_channel_id, 0);
	daemon->node_announce_timer = NULL;
	daemon->current_blockheight = 0; /* i.e. unknown */

	/* Tell the ecdh() function how to talk to hsmd */
	ecdh_hsmd_setup(HSM_FD, status_failed);

	/* Note the use of time_mono() here.  That's a monotonic clock, which
	 * is really useful: it can only be used to measure relative events
	 * (there's no correspondence to time-since-Ken-grew-a-beard or
	 * anything), but unlike time_now(), this will never jump backwards by
	 * half a second and leave me wondering how my tests failed CI! */
	timers_init(&daemon->timers, time_mono());

	/* Our daemons always use STDIN for commands from lightningd. */
	daemon->master = daemon_conn_new(daemon, STDIN_FILENO,
					 recv_req, NULL, daemon);
	tal_add_destructor(daemon->master, master_gone);

	status_setup_async(daemon->master);

	/* connectd is already started, and uses this fd to ask us things. */
	daemon->connectd = daemon_conn_new(daemon, CONNECTD_FD,
					   connectd_req, NULL, daemon);

	/* This loop never exits.  io_loop() only returns if a timer has
	 * expired, or io_break() is called, or all fds are closed.  We don't
	 * use io_break and closing the lightningd fd calls master_gone()
	 * which exits. */
	for (;;) {
		struct timer *expired = NULL;
		io_loop(&daemon->timers, &expired);

		timer_expired(daemon, expired);
	}
}

/*~ Note that the actual routing stuff is in routing.c; you might want to
 * check that out later.
 *
 * But that's the last of the global daemons.  We now move on to the first of
 * the per-peer daemons: openingd/openingd.c.
 */
