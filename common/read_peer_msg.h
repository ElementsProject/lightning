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
 * @gossip_index: the gossip_index
 * @chanid: the channel id (for identifying errors)
 * @send_reply: the way to send a reply packet (eg. sync_crypto_write_arg)
 * @io_error: what to do if there's an IO error (eg. status_fail_io)
 *            (MUST NOT RETURN!)
 * @err_pkt: what to do if there's an error packet (eg. status_fail_errorpkt)
 *            (MUST NOT RETURN!)
 *
 * This returns NULL if it handled the message, so it's normally called in
 * a loop.
 */
#define read_peer_msg(ctx, cs, gossip_index, chanid, send_reply,	\
		      io_error, err_pkt, arg)				\
	read_peer_msg_((ctx), PEER_FD, GOSSIP_FD, (cs), (gossip_index), \
		       (chanid),					\
		       typesafe_cb_preargs(bool, void *, (send_reply), (arg), \
					   struct crypto_state *, int,	\
					   const u8 *),			\
		       typesafe_cb(void, void *, (io_error), (arg)),	\
		       typesafe_cb_preargs(void, void *, (err_pkt), (arg), \
					   int, int,			\
					   struct crypto_state *,	\
					   u64, const char *,		\
					   const struct channel_id *),	\
		       arg)

/* Helper: sync_crypto_write, with extra args it ignores */
bool sync_crypto_write_arg(struct crypto_state *cs, int fd, const u8 *TAKES,
			   void *unused);

/* Helper: calls peer_failed_connection_lost. */
void status_fail_io(void *unused);

/* Helper: calls peer_failed_received_errmsg() */
void status_fail_errpkt(int peer_fd, int gossip_fd,
			struct crypto_state *cs, u64 gossip_index,
			const char *desc,
			const struct channel_id *channel_id,
			void *unused);

u8 *read_peer_msg_(const tal_t *ctx,
		   int peer_fd, int gossip_fd,
		   struct crypto_state *cs, u64 gossip_index,
		   const struct channel_id *channel,
		   bool (*send_reply)(struct crypto_state *cs, int fd,
				      const u8 *TAKES,  void *arg),
		   void (*io_error)(void *arg),
		   void (*err_pkt)(int peer_fd, int gossip_fd,
				   struct crypto_state *cs, u64 gossip_index,
				   const char *desc,
				   const struct channel_id *channel_id,
				   void *arg),
		   void *arg);

#endif /* LIGHTNING_COMMON_READ_PEER_MSG_H */
