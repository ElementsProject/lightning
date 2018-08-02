#ifndef LIGHTNING_COMMON_READ_PEER_MSG_H
#define LIGHTNING_COMMON_READ_PEER_MSG_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <ccan/typesafe_cb/typesafe_cb.h>

struct crypto_state;
struct channel_id;

/**
 * peer_or_gossip_sync_read - read a peer message, or maybe a gossip msg.
 * @ctx: context to allocate return packet from.
 * @peer_fd, @gossip_fd: peer and gossip fd.
 * @cs: the cryptostate (updated)
 * @from_gossipd: true if the msg was from gossipd, otherwise false.
 *
 * Will call peer_failed_connection_lost() or
 * status_failed(STATUS_FAIL_GOSSIP_IO) or return a message.
 *
 * Usually, you should call handle_gossip_msg if *@from_gossipd is
 * true, otherwise if is_peer_error() handle the error, otherwise if
 * is_msg_for_gossipd() then send to gossipd, otherwise if is
 * is_wrong_channel() send that as a reply.  Otherwise it should be
 * a valid message.
 */
u8 *peer_or_gossip_sync_read(const tal_t *ctx,
			     int peer_fd, int gossip_fd,
			     struct crypto_state *cs,
			     bool *from_gossipd);

/**
 * is_peer_error - if it's an error, describe if it applies to this channel.
 * @ctx: context to allocate return from.
 * @msg: the peer message.
 * @channel_id: the channel id of the current channel.
 * @desc: set to non-NULL if this describes a channel we care about.
 * @all_channels: set to true if this applies to all channels.
 *
 * If @desc is NULL, ignore this message.  Otherwise, that's usually passed
 * to peer_failed_received_errmsg().
 */
bool is_peer_error(const tal_t *ctx, const u8 *msg,
		   const struct channel_id *channel_id,
		   char **desc, bool *all_channels);

/**
 * is_wrong_channel - if it's a message about a different channel, return true
 * @msg: the peer message.
 * @channel_id: the channel id of the current channel.
 * @actual: set to the actual channel id if this returns false.
 *
 * Note that this only handles some message types, returning false for others.
 */
bool is_wrong_channel(const u8 *msg, const struct channel_id *expected,
		      struct channel_id *actual);


/**
 * handle_peer_gossip_or_error - simple handler for all the above cases.
 * @peer_fd, @gossip_fd: peer and gossip fd.
 * @cs: the cryptostate (updated)
 * @msg: the peer message (only taken if returns true).
 *
 * This returns true if it handled the packet: a gossip packet (forwarded
 * to gossipd), an error packet (causes peer_failed_received_errmsg or
 * ignored), or a message about the wrong channel (sends sync error reply).
 */
bool handle_peer_gossip_or_error(int peer_fd, int gossip_fd,
				 struct crypto_state *cs,
				 const struct channel_id *channel_id,
				 const u8 *msg TAKES);

/**
 * read_peer_msg - read & decode in a peer message, handling common ones.
 * @ctx: context to allocate return packet from.
 * @cs: the cryptostate (updated)
 * @chanid: the channel id (for identifying errors)
 * @send_reply: the way to send a reply packet (eg. sync_crypto_write_arg)
 *
 * This returns NULL if it handled the message, so it's normally called in
 * a loop.
 */
#define read_peer_msg(ctx, cs, chanid, send_reply, arg)			\
	read_peer_msg_((ctx), PEER_FD, GOSSIP_FD, (cs),			\
		       (chanid),					\
		       typesafe_cb_preargs(bool, void *, (send_reply), (arg), \
					   struct crypto_state *, int,	\
					   const u8 *),			\
		       arg)

/* Like the above, but don't read from GOSSIP_FD */
#define read_peer_msg_nogossip(ctx, cs, chanid, send_reply, arg)	\
	read_peer_msg_((ctx), PEER_FD, -1, (cs),			\
		       (chanid),					\
		       typesafe_cb_preargs(bool, void *, (send_reply), (arg), \
					   struct crypto_state *, int,	\
					   const u8 *),			\
		       arg)

/* Helper: sync_crypto_write, with extra args it ignores */
bool sync_crypto_write_arg(struct crypto_state *cs, int fd, const u8 *TAKES,
			   void *unused);

/* Handler for a gossip msg; used by channeld since it queues them. */
#define handle_gossip_msg(msg, cs, send_reply, arg)			\
	handle_gossip_msg_((msg), PEER_FD, (cs),			\
			   typesafe_cb_preargs(bool, void *,		\
					       (send_reply), (arg),	\
					       struct crypto_state *, int, \
					       const u8 *),		\
			   arg)

void handle_gossip_msg_(const u8 *msg TAKES,
			int peer_fd,
			struct crypto_state *cs,
			bool (*send_msg)(struct crypto_state *cs, int fd,
					 const u8 *TAKES, void *arg),
			void *arg);

u8 *read_peer_msg_(const tal_t *ctx,
		   int peer_fd, int gossip_fd,
		   struct crypto_state *cs,
		   const struct channel_id *channel,
		   bool (*send_reply)(struct crypto_state *cs, int fd,
				      const u8 *TAKES,  void *arg),
		   void *arg);

#endif /* LIGHTNING_COMMON_READ_PEER_MSG_H */
