#ifndef LIGHTNING_DAEMON_WATCH_H
#define LIGHTNING_DAEMON_WATCH_H
#include "config.h"
#include "bitcoin/shadouble.h"
#include <ccan/crypto/ripemd160/ripemd160.h>
#include <ccan/htable/htable_type.h>
#include <ccan/list/list.h>
#include <ccan/short_types/short_types.h>
#include <ccan/typesafe_cb/typesafe_cb.h>

struct bitcoin_tx;
struct lightningd_state;

struct txwatch_output {
	struct sha256_double txid;
	unsigned int index;
};

/* Watching an output */
struct txowatch {
	/* Peer who owns us. */
	struct peer *peer;
	
	/* Output to watch. */
	struct txwatch_output out;

	/* A new tx. */
	void (*cb)(struct peer *peer,
		   const struct bitcoin_tx *tx,
		   void *cbdata);

	void *cbdata;
};

const struct txwatch_output *txowatch_keyof(const struct txowatch *w);
size_t txo_hash(const struct txwatch_output *out);
bool txowatch_eq(const struct txowatch *w, const struct txwatch_output *out);

HTABLE_DEFINE_TYPE(struct txowatch, txowatch_keyof, txo_hash, txowatch_eq,
		   txowatch_hash);

struct txwatch {
	struct lightningd_state *dstate;

	/* Peer who owns us. */
	struct peer *peer;
	
	/* Transaction to watch. */
	struct sha256_double txid;
	int depth;

	/* A new depth (-1 if conflicted) */
	void (*cb)(struct peer *peer, int depth, void *cbdata);
	void *cbdata;
};

const struct sha256_double *txwatch_keyof(const struct txwatch *w);
size_t txid_hash(const struct sha256_double *txid);
bool txwatch_eq(const struct txwatch *w, const struct sha256_double *txid);
HTABLE_DEFINE_TYPE(struct txwatch, txwatch_keyof, txid_hash, txwatch_eq,
		   txwatch_hash);


void add_anchor_watch_(struct peer *peer,
		       const struct sha256_double *txid,
		       unsigned int out,
		       void (*anchor_cb)(struct peer *peer, int depth, void *),
		       void (*spend_cb)(struct peer *peer,
					const struct bitcoin_tx *, void *),
		       void *cbdata);

#define add_anchor_watch(peer, txid, out, anchor_cb, spend_cb, cbdata)	\
	add_anchor_watch_((peer), (txid), (out),			\
			  typesafe_cb_preargs(void, void *,		\
					      (anchor_cb), (cbdata),	\
					      struct peer *,		\
					      int depth),		\
			  typesafe_cb_preargs(void, void *,		\
					      (spend_cb), (cbdata),	\
					      struct peer *,		\
					      const struct bitcoin_tx *), \
			  (cbdata))

void add_commit_tx_watch_(struct peer *peer,
			  const struct sha256_double *txid,
			  void (*cb)(struct peer *peer, int depth, void *),
			  void *cbdata);

#define add_commit_tx_watch(peer, txid, cb, cbdata) \
	add_commit_tx_watch_((peer), (txid),			  \
			     typesafe_cb_preargs(void, void *,		\
						 (cb), (cbdata),	\
						 struct peer *,		\
						 int depth),		\
			     (cbdata))

void add_close_tx_watch(struct peer *peer,
			const struct bitcoin_tx *tx,
			void (*cb)(struct peer *peer, int depth));

void setup_watch_timer(struct lightningd_state *dstate);
#endif /* LIGHTNING_DAEMON_WATCH_H */
