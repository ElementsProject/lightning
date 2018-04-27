#ifndef LIGHTNING_COMMON_READ_PEER_MSG_H
#define LIGHTNING_COMMON_READ_PEER_MSG_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <ccan/typesafe_cb/typesafe_cb.h>

struct crypto_state;
struct channel_id;

/**
 * read_peer_msg - read & decode in a peer message, handling common ones.
 * @ctx: context to allocate return packet from.
 * @cs: the cryptostate (updated)
 * @chanid: the channel id (for identifying errors)
 * @send_reply: the way to send a reply packet (eg. sync_crypto_write_arg)
 * @io_error: what to do if there's an IO error (eg. status_fail_io)
 *            (MUST NOT RETURN!)
 *
 * This returns NULL if it handled the message, so it's normally called in
 * a loop.
 */
#define read_peer_msg(ctx, cs, chanid, send_reply, io_error, arg)	\
	read_peer_msg_((ctx), PEER_FD, GOSSIP_FD, (cs),			\
		       (chanid),					\
		       typesafe_cb_preargs(bool, void *, (send_reply), (arg), \
					   struct crypto_state *, int,	\
					   const u8 *),			\
		       typesafe_cb(void, void *, (io_error), (arg)),	\
		       arg)

/* Helper: sync_crypto_write, with extra args it ignores */
bool sync_crypto_write_arg(struct crypto_state *cs, int fd, const u8 *TAKES,
			   void *unused);

/* Helper: calls peer_failed_connection_lost. */
void status_fail_io(void *unused);

/* Handler for a gossip msg; used by channeld since it queues them. */
#define handle_gossip_msg(msg, cs, send_reply, io_error, arg)		\
	handle_gossip_msg_((msg), PEER_FD, (cs),			\
			   typesafe_cb_preargs(bool, void *,		\
					       (send_reply), (arg),	\
					       struct crypto_state *, int, \
					       const u8 *),		\
			   typesafe_cb(void, void *, (io_error), (arg)), \
			   arg)

void handle_gossip_msg_(const u8 *msg TAKES,
			int peer_fd,
			struct crypto_state *cs,
			bool (*send_msg)(struct crypto_state *cs, int fd,
					 const u8 *TAKES, void *arg),
			void (*io_error)(void *arg),
			void *arg);

u8 *read_peer_msg_(const tal_t *ctx,
		   int peer_fd, int gossip_fd,
		   struct crypto_state *cs,
		   const struct channel_id *channel,
		   bool (*send_reply)(struct crypto_state *cs, int fd,
				      const u8 *TAKES,  void *arg),
		   void (*io_error)(void *arg),
		   void *arg);

#endif /* LIGHTNING_COMMON_READ_PEER_MSG_H */
