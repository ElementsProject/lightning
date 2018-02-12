#include <ccan/crypto/hkdf_sha256/hkdf_sha256.h>
#include <ccan/tal/str/str.h>
#include <gossipd/gen_gossip_wire.h>
#include <inttypes.h>
#include <lightningd/channel.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/lightningd.h>
#include <lightningd/log.h>
#include <lightningd/peer_control.h>
#include <lightningd/subd.h>

void channel_set_owner(struct channel *channel, struct subd *owner)
{
	struct subd *old_owner = channel->owner;
	channel->owner = owner;

	if (old_owner)
		subd_release_peer(old_owner, channel2peer(channel));
}

static void destroy_channel(struct channel *channel)
{
	/* Free any old owner still hanging around. */
	channel_set_owner(channel, NULL);

	list_del_from(&channel->peer->channels, &channel->list);

	/* Last one out frees the peer */
	if (list_empty(&channel->peer->channels))
		tal_free(channel->peer);
}

/* This lets us give a more detailed error than just a destructor. */
void free_channel(struct channel *channel, const char *why)
{
	if (channel->opening_cmd) {
		command_fail(channel->opening_cmd, "%s", why);
		channel->opening_cmd = NULL;
	}
	wallet_channel_delete(channel->peer->ld->wallet, channel->dbid,
			      channel->peer->dbid);
	tal_free(channel);
}

/* FIXME: We have no business knowing this! */
/**
 * derive_channel_seed - Generate a unique secret for this peer's channel
 *
 * @ld: the lightning daemon to get global secret from
 * @seed: where to store the generated secret
 * @peer_id: the id node_id of the remote peer
 * @dbid: channel DBID
 *
 * This method generates a unique secret from the given parameters. It
 * is important that this secret be unique for each channel, but it
 * must be reproducible for the same channel in case of
 * reconnection. We use the DB channel ID to guarantee unique secrets
 * per channel.
 */
void derive_channel_seed(struct lightningd *ld, struct privkey *seed,
			 const struct pubkey *peer_id,
			 const u64 dbid)
{
	u8 input[PUBKEY_DER_LEN + sizeof(dbid)];
	char *info = "per-peer seed";
	pubkey_to_der(input, peer_id);
	memcpy(input + PUBKEY_DER_LEN, &dbid, sizeof(dbid));

	assert(dbid != 0);
	hkdf_sha256(seed, sizeof(*seed),
		    input, sizeof(input),
		    &ld->peer_seed, sizeof(ld->peer_seed),
		    info, strlen(info));
}

struct channel *new_channel(struct peer *peer, u64 dbid, u32 first_blocknum)
{
	/* FIXME: We currently rely on it being all zero/NULL */
	struct channel *channel = talz(peer->ld, struct channel);

	channel->dbid = dbid;
	channel->peer = peer;
	channel->first_blocknum = first_blocknum;
	channel->state = UNINITIALIZED;
	channel->local_shutdown_idx = -1;

	/* FIXME: update log prefix when we get scid */
	channel->log = new_log(channel, peer->log_book, "%s chan #%"PRIu64":",
			       log_prefix(peer->log), dbid);
	list_add_tail(&peer->channels, &channel->list);
	tal_add_destructor(channel, destroy_channel);
	if (channel->dbid != 0)
		derive_channel_seed(peer->ld, &channel->seed, &peer->id,
				    channel->dbid);

	return channel;
}

const char *channel_state_name(const struct channel *channel)
{
	return peer_state_name(channel->state);
}

struct channel *peer_active_channel(struct peer *peer)
{
	struct channel *channel;

	list_for_each(&peer->channels, channel, list) {
		if (channel_active(channel))
			return channel;
	}
	return NULL;
}

struct channel *peer2channel(const struct peer *peer)
{
	return list_top(&peer->channels, struct channel, list);
}

struct peer *channel2peer(const struct channel *channel)
{
	return channel->peer;
}
