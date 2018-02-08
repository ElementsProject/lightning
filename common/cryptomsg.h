#ifndef LIGHTNING_COMMON_CRYPTOMSG_H
#define LIGHTNING_COMMON_CRYPTOMSG_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <common/crypto_state.h>

struct io_conn;
struct peer;

struct peer_crypto_state {
	struct crypto_state cs;

	/* Peer who owns us: peer->crypto_state == this */
	struct peer *peer;

	/* Where we are up to in reading (we do in two parts). */
	bool reading_body;

	/* Output and input buffers. */
	u8 *out, *in;
	struct io_plan *(*next_in)(struct io_conn *, struct peer *, u8 *);
	struct io_plan *(*next_out)(struct io_conn *, struct peer *);
};

/* Initializes peer->cs (still need to read in cs->cs) */
void init_peer_crypto_state(struct peer *peer, struct peer_crypto_state *pcs);

/* Get decrypted message: ignores unknown odd messages. */
struct io_plan *peer_read_message(struct io_conn *conn,
				  struct peer_crypto_state *cs,
				  struct io_plan *(*next)(struct io_conn *,
							  struct peer *,
							  u8 *msg));

/* Have we already started reading a message? */
bool peer_in_started(const struct io_conn *conn,
		     const struct peer_crypto_state *cs);

/* Sends message: frees if taken(msg). */
struct io_plan *peer_write_message(struct io_conn *conn,
				   struct peer_crypto_state *cs,
				   const u8 *msg,
				   struct io_plan *(*next)(struct io_conn *,
							   struct peer *));

/* Low-level functions for sync comms: doesn't discard unknowns! */
u8 *cryptomsg_encrypt_msg(const tal_t *ctx,
			  struct crypto_state *cs,
			  const u8 *msg);
bool cryptomsg_decrypt_header(struct crypto_state *cs, u8 hdr[18], u16 *lenp);
u8 *cryptomsg_decrypt_body(const tal_t *ctx,
			   struct crypto_state *cs, const u8 *in);
#endif /* LIGHTNING_COMMON_CRYPTOMSG_H */
