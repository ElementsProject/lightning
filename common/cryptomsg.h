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

/* Sends message: frees if taken(msg). */
struct io_plan *peer_write_message(struct io_conn *conn,
				   struct peer_crypto_state *cs,
				   const u8 *msg,
				   struct io_plan *(*next)(struct io_conn *,
							   struct peer *));
/* BOLT #8:
 *
 * ### Receiving and Decrypting Messages
 *
 * In order to decrypt the _next_ message in the network stream, the
 * following steps are completed:
 *
 *  1. Read _exactly_ 18 bytes from the network buffer.
 */
#define CRYPTOMSG_HDR_SIZE 18

/* BOLT #8:
 *
 * 4. Read _exactly_ `l+16` bytes from the network buffer
 */
#define CRYPTOMSG_BODY_OVERHEAD 16

/* Low-level functions for sync comms: doesn't discard unknowns! */
u8 *cryptomsg_encrypt_msg(const tal_t *ctx,
			  struct crypto_state *cs,
			  const u8 *msg);
bool cryptomsg_decrypt_header(struct crypto_state *cs, u8 hdr[18], u16 *lenp);
u8 *cryptomsg_decrypt_body(const tal_t *ctx,
			   struct crypto_state *cs, const u8 *in);
#endif /* LIGHTNING_COMMON_CRYPTOMSG_H */
