#ifndef LIGHTNING_CONNECTD_HANDSHAKE_H
#define LIGHTNING_CONNECTD_HANDSHAKE_H
#include "config.h"

struct crypto_state;
struct io_conn;
struct wireaddr_internal;
struct pubkey;
struct oneshot;

/*~ Sometimes it's nice to have an explicit enum instead of a bool to make
 * arguments clearer: it kind of hacks around C's lack of naming formal
 * arguments in callers (e.g. in Python we'd simply call func(websocket=False)).
 */
enum is_websocket {
	NORMAL_SOCKET,
	WEBSOCKET,
};

#define initiator_handshake(conn, my_id, their_id, addr, timeout, is_ws, cb, cbarg) \
	initiator_handshake_((conn), (my_id), (their_id), (addr), (timeout), (is_ws), \
			     typesafe_cb_preargs(struct io_plan *, void *, \
						 (cb), (cbarg),		\
						 struct io_conn *,	\
						 const struct pubkey *,	\
						 const struct wireaddr_internal *, \
						 struct crypto_state *, \
						 struct oneshot *,	\
						 enum is_websocket),	\
			     (cbarg))


struct io_plan *initiator_handshake_(struct io_conn *conn,
				     const struct pubkey *my_id,
				     const struct pubkey *their_id,
				     const struct wireaddr_internal *addr,
				     struct oneshot *timeout,
				     enum is_websocket is_websocket,
				     struct io_plan *(*cb)(struct io_conn *,
							   const struct pubkey *,
							   const struct wireaddr_internal *,
							   struct crypto_state *,
							   struct oneshot *timeout,
							   enum is_websocket,
							   void *cbarg),
				     void *cbarg);


#define responder_handshake(conn, my_id, addr, timeout, is_ws, cb, cbarg)	\
	responder_handshake_((conn), (my_id), (addr), (timeout), (is_ws), \
			     typesafe_cb_preargs(struct io_plan *, void *, \
						 (cb), (cbarg),		\
						 struct io_conn *,	\
						 const struct pubkey *,	\
						 const struct wireaddr_internal *, \
						 struct crypto_state *, \
						 struct oneshot *,	\
						 enum is_websocket),	\
			     (cbarg))

struct io_plan *responder_handshake_(struct io_conn *conn,
				     const struct pubkey *my_id,
				     const struct wireaddr_internal *addr,
				     struct oneshot *timeout,
				     enum is_websocket is_websocket,
				     struct io_plan *(*cb)(struct io_conn *,
							   const struct pubkey *,
							   const struct wireaddr_internal *,
							   struct crypto_state *,
							   struct oneshot *,
							   enum is_websocket,
							   void *cbarg),
				     void *cbarg);
#endif /* LIGHTNING_CONNECTD_HANDSHAKE_H */
