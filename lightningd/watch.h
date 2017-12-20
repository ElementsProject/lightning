#ifndef LIGHTNING_LIGHTNINGD_WATCH_H
#define LIGHTNING_LIGHTNINGD_WATCH_H
#include "config.h"
#include <bitcoin/tx.h>
#include <ccan/crypto/ripemd160/ripemd160.h>
#include <ccan/htable/htable_type.h>
#include <ccan/list/list.h>
#include <ccan/short_types/short_types.h>
#include <ccan/typesafe_cb/typesafe_cb.h>

struct bitcoin_tx;
struct block;

enum watch_result {
	DELETE_WATCH = -1,
	KEEP_WATCHING = -2
};

struct txwatch_output {
	struct bitcoin_txid txid;
	unsigned int index;
};

/* Watching an output */
struct txowatch {
	struct chain_topology *topo;

	/* Peer who owns us. */
	struct peer *peer;

	/* Output to watch. */
	struct txwatch_output out;

	/* A new tx. */
	enum watch_result (*cb)(struct peer *peer,
				const struct bitcoin_tx *tx,
				size_t input_num,
				const struct block *block,
				void *cbdata);

	void *cbdata;
};

const struct txwatch_output *txowatch_keyof(const struct txowatch *w);
size_t txo_hash(const struct txwatch_output *out);
bool txowatch_eq(const struct txowatch *w, const struct txwatch_output *out);

HTABLE_DEFINE_TYPE(struct txowatch, txowatch_keyof, txo_hash, txowatch_eq,
		   txowatch_hash);

struct txwatch {
	struct chain_topology *topo;

	/* Peer who owns us. */
	struct peer *peer;

	/* Transaction to watch. */
	struct bitcoin_txid txid;
	unsigned int depth;

	/* A new depth (0 if kicked out, otherwise 1 = tip, etc.) */
	enum watch_result (*cb)(struct peer *peer,
				const struct bitcoin_tx *tx,
				unsigned int depth,
				void *cbdata);

	void *cbdata;
};

const struct bitcoin_txid *txwatch_keyof(const struct txwatch *w);
size_t txid_hash(const struct bitcoin_txid *txid);
bool txwatch_eq(const struct txwatch *w, const struct bitcoin_txid *txid);
HTABLE_DEFINE_TYPE(struct txwatch, txwatch_keyof, txid_hash, txwatch_eq,
		   txwatch_hash);


struct txwatch *watch_txid_(const tal_t *ctx,
			    struct chain_topology *topo,
			    struct peer *peer,
			    const struct bitcoin_txid *txid,
			    enum watch_result (*cb)(struct peer *peer,
						    const struct bitcoin_tx *,
						    unsigned int depth,
						    void *),
			    void *cbdata);

#define watch_txid(ctx, topo, peer_, txid, cb, cbdata)			\
	watch_txid_((ctx), (topo), (peer_), (txid),			\
		    typesafe_cb_preargs(enum watch_result, void *,	\
					(cb), (cbdata),			\
					struct peer *,			\
					const struct bitcoin_tx *,	\
					unsigned int depth),		\
		    (cbdata))

struct txwatch *watch_tx_(const tal_t *ctx,
			  struct chain_topology *topo,
			  struct peer *peer,
			  const struct bitcoin_tx *tx,
			  enum watch_result (*cb)(struct peer *peer,
						  const struct bitcoin_tx *,
						  unsigned int depth,
						  void *),
			  void *cbdata);

#define watch_tx(ctx, topo, peer_, tx, cb, cbdata)			\
	watch_tx_((ctx), (topo), (peer_), (tx),				\
		  typesafe_cb_preargs(enum watch_result, void *,	\
				      (cb), (cbdata),			\
				      struct peer *,			\
				      const struct bitcoin_tx *,	\
				      unsigned int depth),		\
		  (cbdata))

struct txowatch *watch_txo_(const tal_t *ctx,
			    struct chain_topology *topo,
			    struct peer *peer,
			    const struct bitcoin_txid *txid,
			    unsigned int output,
			    enum watch_result (*cb)(struct peer *peer,
						    const struct bitcoin_tx *tx,
						    size_t input_num,
						    const struct block *block,
						    void *),
			    void *cbdata);

#define watch_txo(ctx, topo, peer_, txid, outnum, cb, cbdata)		\
	watch_txo_((ctx), (topo), (peer_), (txid), (outnum),		\
		   typesafe_cb_preargs(enum watch_result, void *,	\
				      (cb), (cbdata),			\
				      struct peer *,			\
				      const struct bitcoin_tx *,	\
				       size_t,				\
				       const struct block *block),	\
		  (cbdata))

void txwatch_fire(struct chain_topology *topo,
		  const struct bitcoin_tx *tx,
		  unsigned int depth);

void txowatch_fire(struct chain_topology *topo,
		   const struct txowatch *txow,
		   const struct bitcoin_tx *tx, size_t input_num,
		   const struct block *block);

bool watching_txid(const struct chain_topology *topo,
		   const struct bitcoin_txid *txid);

void watch_topology_changed(struct chain_topology *topo);
#endif /* LIGHTNING_LIGHTNINGD_WATCH_H */
