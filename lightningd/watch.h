#ifndef LIGHTNING_LIGHTNINGD_WATCH_H
#define LIGHTNING_LIGHTNINGD_WATCH_H
#include "config.h"
#include <bitcoin/script.h>
#include <bitcoin/tx.h>
#include <ccan/htable/htable_type.h>

struct block;
struct channel;
struct chain_topology;
struct lightningd;
struct txlocator;
struct txowatch;
struct txwatch;
struct scriptpubkeywatch;
struct blockdepthwatch;

enum watch_result {
	DELETE_WATCH = -1,
	KEEP_WATCHING = -2
};

const struct bitcoin_outpoint *txowatch_keyof(const struct txowatch *w);
size_t txo_hash(const struct bitcoin_outpoint *out);
bool txowatch_eq(const struct txowatch *w, const struct bitcoin_outpoint *out);

HTABLE_DEFINE_DUPS_TYPE(struct txowatch, txowatch_keyof, txo_hash, txowatch_eq,
			txowatch_hash);

const struct bitcoin_txid *txwatch_keyof(const struct txwatch *w);
size_t txid_hash(const struct bitcoin_txid *txid);
bool txwatch_eq(const struct txwatch *w, const struct bitcoin_txid *txid);
HTABLE_DEFINE_DUPS_TYPE(struct txwatch, txwatch_keyof, txid_hash, txwatch_eq,
			txwatch_hash);

const struct script_with_len *scriptpubkeywatch_keyof(const struct scriptpubkeywatch *w);
bool scriptpubkeywatch_eq(const struct scriptpubkeywatch *w, const struct script_with_len *swl);
HTABLE_DEFINE_DUPS_TYPE(struct scriptpubkeywatch, scriptpubkeywatch_keyof, script_with_len_hash, scriptpubkeywatch_eq,
			scriptpubkeywatch_hash);

u32 blockdepthwatch_keyof(const struct blockdepthwatch *w);
size_t u32_hash(u32);
bool blockdepthwatch_eq(const struct blockdepthwatch *w, u32 height);
HTABLE_DEFINE_DUPS_TYPE(struct blockdepthwatch, blockdepthwatch_keyof, u32_hash, blockdepthwatch_eq,
			blockdepthwatch_hash);

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

/* Watch for specific spends to this scriptpubkey: returns false if was already watched. */
bool watch_scriptpubkey_(const tal_t *ctx,
			 struct chain_topology *topo,
			 const u8 *scriptpubkey TAKES,
			 const struct bitcoin_outpoint *expected_outpoint,
			 struct amount_sat expected_amount,
			 void (*cb)(struct lightningd *ld,
				    const struct bitcoin_tx *tx,
				    u32 outnum,
				    const struct txlocator *loc,
				    void *),
			 void *arg);

#define watch_scriptpubkey(ctx, topo, scriptpubkey, expected_outpoint, expected_amount, cb, arg) \
	watch_scriptpubkey_((ctx), (topo), (scriptpubkey),		\
			    (expected_outpoint), (expected_amount), \
			    typesafe_cb_preargs(void, void *,		\
						(cb), (arg),		\
						struct lightningd *,	\
						const struct bitcoin_tx *, \
						u32 outnum,		\
						const struct txlocator *), \
			    (arg))

bool unwatch_scriptpubkey_(const tal_t *ctx,
			   struct chain_topology *topo,
			   const u8 *scriptpubkey,
			   const struct bitcoin_outpoint *expected_outpoint,
			   struct amount_sat expected_amount,
			   void (*cb)(struct lightningd *ld,
				      const struct bitcoin_tx *tx,
				      u32 outnum,
				      const struct txlocator *loc,
				      void *),
			   void *arg);

#define unwatch_scriptpubkey(ctx, topo, scriptpubkey, expected_outpoint, expected_amount, cb, arg) \
	unwatch_scriptpubkey_((ctx), (topo), (scriptpubkey),		\
			      (expected_outpoint), (expected_amount),	\
			      typesafe_cb_preargs(void, void *,		\
						  (cb), (arg),		\
						  struct lightningd *,	\
						  const struct bitcoin_tx *, \
						  u32 outnum,		\
						  const struct txlocator *), \
			      (arg))

/* Watch for this block getting deeper (or reorged out).  Returns false it if was a duplicate. */
bool watch_blockdepth_(const tal_t *ctx,
		       struct chain_topology *topo,
		       u32 blockheight,
		       enum watch_result (*depthcb)(struct lightningd *ld, u32 depth, void *),
		       enum watch_result (*reorgcb)(struct lightningd *ld, void *),
		       void *arg);

#define watch_blockdepth(ctx, topo, blockheight, depthcb, reorgcb, arg)	\
	watch_blockdepth_((ctx), (topo), (blockheight),		\
			  typesafe_cb_preargs(enum watch_result, void *, \
					      (depthcb), (arg),		\
					      struct lightningd *,	\
					      u32),			\
			  typesafe_cb_preargs(enum watch_result, void *, \
					      (reorgcb), (arg),		\
					      struct lightningd *),	\
			  (arg))

/* Call any scriptpubkey callbacks for this tx */
bool watch_check_tx_outputs(const struct chain_topology *topo,
			    const struct txlocator *loc,
			    const struct bitcoin_tx *tx,
			    const struct bitcoin_txid *txid);

/* Call anyone watching for block height increases. */
void watch_check_block_added(const struct chain_topology *topo, u32 blockheight);

/* Call anyone watching for block removals. */
void watch_check_block_removed(const struct chain_topology *topo, u32 blockheight);

void watch_topology_changed(struct chain_topology *topo);
#endif /* LIGHTNING_LIGHTNINGD_WATCH_H */
