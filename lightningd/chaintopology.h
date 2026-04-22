#ifndef LIGHTNING_LIGHTNINGD_CHAINTOPOLOGY_H
#define LIGHTNING_LIGHTNINGD_CHAINTOPOLOGY_H
#include "config.h"
#include <lightningd/broadcast.h>
#include <lightningd/watch.h>

struct bitcoin_tx;
struct bitcoind;
struct command;
struct lightningd;
struct peer;
struct txwatch;
struct scriptpubkeywatch;
struct wallet;

/* We keep the last three in case there are outliers (for min/max) */
#define FEE_HISTORY_NUM 3

struct block {
	u32 height;

	/* Actual header. */
	struct bitcoin_block_hdr hdr;

	/* Previous block (if any). */
	struct block *prev;

	/* Next block (if any). */
	struct block *next;

	/* Key for hash table */
	struct bitcoin_blkid blkid;

	/* Full copy of txs (freed in filter_block_txs) */
	struct bitcoin_tx **full_txs;
	struct bitcoin_txid *txids;
};

/* Hash blocks by sha */
static inline const struct bitcoin_blkid *keyof_block_map(const struct block *b)
{
	return &b->blkid;
}

static inline size_t hash_sha(const struct bitcoin_blkid *key)
{
	size_t ret;

	memcpy(&ret, key, sizeof(ret));
	return ret;
}

static inline bool block_eq(const struct block *b, const struct bitcoin_blkid *key)
{
	return bitcoin_blkid_eq(&b->blkid, key);
}
HTABLE_DEFINE_NODUPS_TYPE(struct block, keyof_block_map, hash_sha, block_eq,
			  block_map);

/* Our plugins give us a series of blockcount, feerate pairs. */
struct feerate_est {
	u32 blockcount;
	u32 rate;
};

struct chain_topology {
	struct lightningd *ld;
	struct block *root;
	struct block *tip;
	struct bitcoin_blkid prev_tip;
	struct block_map *block_map;

	/* This is the lowest feerate that bitcoind is saying will broadcast. */
	u32 feerate_floor;

	/* We keep last three feerates we got: this is useful for min/max. */
	struct feerate_est *feerates[FEE_HISTORY_NUM];

	/* We keep a smoothed feerate: this is useful when we're going to
	 * suggest feerates / check feerates from our peers. */
	struct feerate_est *smoothed_feerates;

	/* Where to log things. */
	struct logger *log;

	/* How often to poll. */
	u32 poll_seconds;

	/* struct sync_waiters waiting for us to catch up with bitcoind (and
	 * once that has caught up with the network).  NULL if we're already
	 * caught up. */
	struct list_head *sync_waiters;

	/* The bitcoind. */
	struct bitcoind *bitcoind;

	/* Timers we're running. */
	struct oneshot *checkchain_timer, *extend_timer, *updatefee_timer;

	/* Parent context for requests (to bcli plugin) we have outstanding. */
	tal_t *request_ctx;

	/* Transactions/txos we are watching. */
	struct txwatch_hash *txwatches;
	struct txowatch_hash *txowatches;
	struct scriptpubkeywatch_hash *scriptpubkeywatches;
	struct blockdepthwatch_hash *blockdepthwatches;

	/* The number of headers known to the bitcoin backend at startup. Not
	 * updated after the initial check. */
	u32 headercount;

	/* Progress on routine to look for old missed transactions.  0 = not interested. */
	u32 old_block_scan;
};

/* Information relevant to locating a TX in a blockchain. */
struct txlocator {

	/* The height of the block that includes this transaction */
	u32 blkheight;

	/* Position of the transaction in the transactions list */
	u32 index;
};

/* Get the minimum feerate that bitcoind will accept */
u32 get_feerate_floor(const struct chain_topology *topo);

/* This is the number of blocks which would have to be mined to invalidate
 * the tx */
size_t get_tx_depth(const struct chain_topology *topo,
		    const struct bitcoin_txid *txid);

/* Get highest block number. */
u32 get_block_height(const struct chain_topology *topo);

/* Get the highest block number in the network that we are aware of. Unlike
 * `get_block_height` this takes into consideration the block header counter
 * in the bitcoin backend as well. If an absolute time is required, rather
 * than our current scan position this is preferable since it is far less
 * likely to lag behind the rest of the network.*/
u32 get_network_blockheight(const struct chain_topology *topo);

/* Get feerate estimate for getting a tx in this many blocks */
u32 feerate_for_deadline(const struct chain_topology *topo, u32 blockcount);
u32 smoothed_feerate_for_deadline(const struct chain_topology *topo, u32 blockcount);

/* Get feerate to hit this *block number*. */
u32 feerate_for_target(const struct chain_topology *topo, u64 deadline);

/* Has our feerate estimation failed altogether? */
bool unknown_feerates(const struct chain_topology *topo);

/* Get range of feerates to insist other side abide by for normal channels.
 * If we have to guess, sets *unknown to true, otherwise false. */
u32 feerate_min(struct lightningd *ld, bool *unknown);
u32 feerate_max(struct lightningd *ld, bool *unknown);

/* These return 0 if unknown */
u32 opening_feerate(struct chain_topology *topo);
u32 mutual_close_feerate(struct chain_topology *topo);
u32 unilateral_feerate(struct chain_topology *topo, bool option_anchors);
/* For onchain resolution. */
u32 delayed_to_us_feerate(struct chain_topology *topo);
u32 htlc_resolution_feerate(struct chain_topology *topo);
u32 penalty_feerate(struct chain_topology *topo);

/* Usually we set nLocktime to tip (or recent) like bitcoind does */
u32 default_locktime(const struct chain_topology *topo);

struct chain_topology *new_topology(struct lightningd *ld, struct logger *log);
void setup_topology(struct chain_topology *topology);

void begin_topology(struct chain_topology *topo);

void stop_topology(struct chain_topology *topo);

struct txlocator *locate_tx(const void *ctx, const struct chain_topology *topo, const struct bitcoin_txid *txid);

static inline bool topology_synced(const struct chain_topology *topo)
{
	return topo->sync_waiters == NULL;
}

/**
 * topology_add_sync_waiter: wait for lightningd to sync with bitcoin network
 * @ctx: context to allocate the waiter from.
 * @topo: chain topology
 * @cb: callback to call when we're synced.
 * @arg: arg for @cb
 *
 * topology_synced() must be false when this is called.  It will be true
 * when @cb is called.  @cb will not be called if @ctx is freed first.
 */
void topology_add_sync_waiter_(const tal_t *ctx,
			       struct chain_topology *topo,
			       void (*cb)(struct chain_topology *,
					  void *),
			       void *arg);
#define topology_add_sync_waiter(ctx, topo, cb, arg)			\
	topology_add_sync_waiter_((ctx), (topo),			\
				  typesafe_cb_preargs(void, void *,	\
						      (cb), (arg),	\
						      struct chain_topology *), \
				  (arg))


/* In channel_control.c */
void notify_feerate_change(struct lightningd *ld);

/* We want to update db when this txid is confirmed.  We always do this
 * if it's related to a channel or incoming funds, but sendpsbt without
 * change would be otherwise untracked. */
void watch_unconfirmed_txid(struct lightningd *ld,
			    struct chain_topology *topo,
			    const struct bitcoin_txid *txid);
#endif /* LIGHTNING_LIGHTNINGD_CHAINTOPOLOGY_H */
