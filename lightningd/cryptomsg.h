#ifndef LIGHTNING_LIGHTNINGD_CRYPTOMSG_H
#define LIGHTNING_LIGHTNINGD_CRYPTOMSG_H
#include "config.h"
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

struct io_conn;
struct peer;

struct crypto_state {
	/* Received and sent nonces. */
	u64 rn, sn;
	/* Sending and receiving keys. */
	struct sha256 sk, rk;
	/* Chaining key for re-keying */
	struct sha256 s_ck, r_ck;

	/* Peer who owns us: peer->crypto_state == this */
	struct peer *peer;

	/* Output and input buffers. */
	u8 *out, *in;
	struct io_plan *(*next_in)(struct io_conn *, struct peer *, u8 *);
	struct io_plan *(*next_out)(struct io_conn *, struct peer *);
};

/* Initializes peer->crypto_state */
struct crypto_state *crypto_state(struct peer *peer,
				  const struct sha256 *sk,
				  const struct sha256 *rk,
				  const struct sha256 *rck,
				  const struct sha256 *sck,
				  u64 rn, u64 sn);

/* Get decrypted message */
struct io_plan *peer_read_message(struct io_conn *conn,
				  struct crypto_state *cs,
				  struct io_plan *(*next)(struct io_conn *,
							  struct peer *,
							  u8 *msg));

/* Sends and frees message */
struct io_plan *peer_write_message(struct io_conn *conn,
				   struct crypto_state *cs,
				   const u8 *msg,
				   struct io_plan *(*next)(struct io_conn *,
							   struct peer *));

void towire_crypto_state(u8 **pptr, const struct crypto_state *cs);
void fromwire_crypto_state(const u8 **ptr, size_t *max, struct crypto_state *cs);

/* Low-level functions for sync comms. */
u8 *cryptomsg_encrypt_msg(const tal_t *ctx,
			  struct crypto_state *cs,
			  const u8 *msg);
bool cryptomsg_decrypt_header(struct crypto_state *cs, u8 *hdr, u16 *lenp);
u8 *cryptomsg_decrypt_body(const tal_t *ctx,
			   struct crypto_state *cs, const u8 *in);
#endif /* LIGHTNING_LIGHTNINGD_CRYPTOMSG_H */
