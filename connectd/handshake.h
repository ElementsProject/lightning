#ifndef LIGHTNING_CONNECTD_HANDSHAKE_H
#define LIGHTNING_CONNECTD_HANDSHAKE_H
#include "config.h"
#include <ccan/typesafe_cb/typesafe_cb.h>

struct crypto_state;
struct io_conn;
struct wireaddr_internal;
struct pubkey;

#define initiator_handshake(conn, my_id, their_id, addr, cb, cbarg)	\
	initiator_handshake_((conn), (my_id), (their_id), (addr),	\
			     typesafe_cb_preargs(struct io_plan *, void *, \
						 (cb), (cbarg),		\
						 struct io_conn *,	\
						 const struct pubkey *,	\
						 const struct wireaddr_internal *,	\
						 const struct crypto_state *), \
			     (cbarg))


struct io_plan *initiator_handshake_(struct io_conn *conn,
				     const struct pubkey *my_id,
				     const struct pubkey *their_id,
				     const struct wireaddr_internal *addr,
				     struct io_plan *(*cb)(struct io_conn *,
							   const struct pubkey *,
							   const struct wireaddr_internal *,
							   const struct crypto_state *,
							   void *cbarg),
				     void *cbarg);


#define responder_handshake(conn, my_id, addr, cb, cbarg)		\
	responder_handshake_((conn), (my_id), (addr),			\
			     typesafe_cb_preargs(struct io_plan *, void *, \
						 (cb), (cbarg),		\
						 struct io_conn *,	\
						 const struct pubkey *,	\
						 const struct wireaddr_internal *,	\
						 const struct crypto_state *), \
			     (cbarg))

struct io_plan *responder_handshake_(struct io_conn *conn,
				     const struct pubkey *my_id,
				     const struct wireaddr_internal *addr,
				     struct io_plan *(*cb)(struct io_conn *,
							   const struct pubkey *,
							   const struct wireaddr_internal *,
							   const struct crypto_state *,
							   void *cbarg),
				     void *cbarg);

#endif /* LIGHTNING_CONNECTD_HANDSHAKE_H */
