#ifndef LIGHTNING_LIGHTNINGD_CRYPTOMSG_H
#define LIGHTNING_LIGHTNINGD_CRYPTOMSG_H
#include "config.h"
#include <ccan/short_types/short_types.h>

struct io_conn;
struct peer;
struct sha256;

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

#endif /* LIGHTNING_LIGHTNINGD_CRYPTOMSG_H */
