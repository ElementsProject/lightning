#ifndef LIGHTNING_LIGHTNINGD_WATCH_H
#define LIGHTNING_LIGHTNINGD_WATCH_H
#include "config.h"
#include <bitcoin/tx.h>
#include <ccan/htable/htable_type.h>

struct block;
struct channel;
struct chain_topology;
struct lightningd;
struct txowatch;
struct txwatch;

enum watch_result {
	DELETE_WATCH = -1,
	KEEP_WATCHING = -2
};

const struct bitcoin_outpoint *txowatch_keyof(const struct txowatch *w);
size_t txo_hash(const struct bitcoin_outpoint *out);
bool txowatch_eq(const struct txowatch *w, const struct bitcoin_outpoint *out);

HTABLE_DEFINE_TYPE(struct txowatch, txowatch_keyof, txo_hash, txowatch_eq,
		   txowatch_hash);

const struct bitcoin_txid *txwatch_keyof(const struct txwatch *w);
size_t txid_hash(const struct bitcoin_txid *txid);
bool txwatch_eq(const struct txwatch *w, const struct bitcoin_txid *txid);
HTABLE_DEFINE_TYPE(struct txwatch, txwatch_keyof, txid_hash, txwatch_eq,
		   txwatch_hash);


struct txwatch *watch_txid_(const tal_t *ctx,
			    struct chain_topology *topo,
			    const struct bitcoin_txid *txid,
			    enum watch_result (*cb)(struct lightningd *ld,
						    const struct bitcoin_txid *,
						    const struct bitcoin_tx *,
						    unsigned int depth,
						    void *arg),
			    void *arg);

#define watch_txid(ctx, topo, txid, cb, arg)				\
	watch_txid_((ctx), (topo), (txid),				\
		    typesafe_cb_preargs(enum watch_result, void *,	\
					(cb), (arg),			\
					struct lightningd *,		\
					const struct bitcoin_txid *,	\
					const struct bitcoin_tx *,	\
					unsigned int depth),		\
		    (arg))

struct txowatch *watch_txo(const tal_t *ctx,
			   struct chain_topology *topo,
			   struct channel *channel,
			   const struct bitcoin_outpoint *outpoint,
			   enum watch_result (*cb)(struct channel *,
						   const struct bitcoin_tx *tx,
						   size_t input_num,
						   const struct block *block));

struct txwatch *find_txwatch_(struct chain_topology *topo,
			      const struct bitcoin_txid *txid,
			      enum watch_result (*cb)(struct lightningd *ld,
						      const struct bitcoin_txid *,
						      const struct bitcoin_tx *,
						      unsigned int depth,
						      void *arg),
			    void *arg);

#define find_txwatch(topo, txid, cb, arg)			\
	find_txwatch_((topo), (txid),				\
		      typesafe_cb_preargs(enum watch_result, void *,	\
					  (cb), (arg),			\
					  struct lightningd *,		\
					  const struct bitcoin_txid *,	\
					  const struct bitcoin_tx *,	\
					  unsigned int depth),		\
		      (arg))

void txwatch_fire(struct chain_topology *topo,
		  const struct bitcoin_txid *txid,
		  unsigned int depth);

void txowatch_fire(const struct txowatch *txow,
		   const struct bitcoin_tx *tx, size_t input_num,
		   const struct block *block);

bool watching_txid(const struct chain_topology *topo,
		   const struct bitcoin_txid *txid);

void txwatch_inform(const struct chain_topology *topo,
		    const struct bitcoin_txid *txid,
		    struct bitcoin_tx *tx TAKES);

void watch_topology_changed(struct chain_topology *topo);
#endif /* LIGHTNING_LIGHTNINGD_WATCH_H */
