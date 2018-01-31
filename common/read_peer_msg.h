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
 * @channel_id: the channel id (for identifying errors)
 * @send_reply: the way to send a reply packet (eg. sync_crypto_write_arg)
 * @io_error: what to do if there's an IO error (eg. status_fail_io)
 *            (MUST NOT RETURN!)
 * @err_pkt: what to do if there's an error packet (eg. status_fail_errorpkt)
 *            (MUST NOT RETURN!)
 *
 * This returns NULL if it handled the message, so it's normally called in
 * a loop.
 */
#define read_peer_msg(ctx, cs, channel_id, send_reply, io_error, err_pkt, arg) \
	read_peer_msg_((ctx), PEER_FD, GOSSIP_FD, (cs), (channel_id),	\
		       typesafe_cb_preargs(bool, void *, (send_reply), (arg), \
					   struct crypto_state *, int,	\
					   const u8 *),			\
		       typesafe_cb_preargs(void, void *, (io_error), (arg), \
					   const char *),		\
		       typesafe_cb_preargs(void, void *, (err_pkt), (arg), \
					   const char *, bool),		\
		       arg)

/* Helper: sync_crypto_write, with extra args it ignores */
bool sync_crypto_write_arg(struct crypto_state *cs, int fd, const u8 *TAKES,
			   void *unused);

/* Helper: calls status_failed(STATUS_FAIL_PEER_IO) */
void status_fail_io(const char *what_i_was_doing, void *unused);

/* Helper: calls status_failed(STATUS_FAIL_PEER_BAD, <error>) */
void status_fail_errpkt(const char *desc, bool this_channel_only, void *unused);

u8 *read_peer_msg_(const tal_t *ctx,
		   int peer_fd, int gossip_fd,
		   struct crypto_state *cs,
		   const struct channel_id *channel,
		   bool (*send_reply)(struct crypto_state *cs, int fd,
				      const u8 *TAKES,  void *arg),
		   void (*io_error)(const char *what_i_was_doing, void *arg),
		   void (*err_pkt)(const char *desc, bool this_channel_only,
				   void *arg),
		   void *arg);

#endif /* LIGHTNING_COMMON_READ_PEER_MSG_H */
