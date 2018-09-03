#ifndef LIGHTNING_LIGHTNINGD_CHAINTOPOLOGY_H
#define LIGHTNING_LIGHTNINGD_CHAINTOPOLOGY_H
#include "config.h"
#include <bitcoin/block.h>
#include <bitcoin/tx.h>
#include <ccan/list/list.h>
#include <ccan/short_types/short_types.h>
#include <ccan/structeq/structeq.h>
#include <ccan/time/time.h>
#include <jsmn.h>
#include <lightningd/json.h>
#include <lightningd/watch.h>
#include <math.h>
#include <stddef.h>

struct bitcoin_tx;
struct bitcoind;
struct command;
struct lightningd;
struct peer;
struct txwatch;

/* FIXME: move all feerate stuff out to new lightningd/feerate.[ch] files */
enum feerate {
	FEERATE_URGENT, /* Aka: aim for next block. */
	FEERATE_NORMAL, /* Aka: next 4 blocks or so. */
	FEERATE_SLOW, /* Aka: next 100 blocks or so. */
};
#define NUM_FEERATES (FEERATE_SLOW+1)

/* We keep the last three in case there are outliers (for min/max) */
#define FEE_HISTORY_NUM 3

/* Off topology->outgoing_txs */
struct outgoing_tx {
	struct list_node list;
	struct channel *channel;
	const char *hextx;
	struct bitcoin_txid txid;
	void (*failed)(struct channel *channel, int exitstatus, const char *err);
};

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

	/* And their associated index in the block */
	u32 *txnums;

	/* Full copy of txs (trimmed to txs list in connect_block) */
	struct bitcoin_tx **full_txs;
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
HTABLE_DEFINE_TYPE(struct block, keyof_block_map, hash_sha, block_eq, block_map);

struct chain_topology {
	struct lightningd *ld;
	struct block *root;
	struct block *prev_tip, *tip;
	struct block_map block_map;
	u32 feerate[NUM_FEERATES];
	bool feerate_uninitialized;
	u32 feehistory[NUM_FEERATES][FEE_HISTORY_NUM];

	/* Where to log things. */
	struct log *log;

	/* What range of blocks do we have in our database? */
	u32 min_blockheight, max_blockheight;

	/* How often to poll. */
	u32 poll_seconds;

	/* The bitcoind. */
	struct bitcoind *bitcoind;

	/* Our timer list. */
	struct timers *timers;

	/* Bitcoin transactions we're broadcasting */
	struct list_head outgoing_txs;

	/* Transactions/txos we are watching. */
	struct txwatch_hash txwatches;
	struct txowatch_hash txowatches;
};

/* Information relevant to locating a TX in a blockchain. */
struct txlocator {

	/* The height of the block that includes this transaction */
	u32 blkheight;

	/* Position of the transaction in the transactions list */
	u32 index;
};

/* This is the number of blocks which would have to be mined to invalidate
 * the tx */
size_t get_tx_depth(const struct chain_topology *topo,
		    const struct bitcoin_txid *txid);

/* Get highest block number. */
u32 get_block_height(const struct chain_topology *topo);

/* Get fee rate in satoshi per kiloweight, or 0 if unavailable! */
u32 try_get_feerate(const struct chain_topology *topo, enum feerate feerate);

/* Get range of feerates to insist other side abide by for normal channels.
 * If we have to guess, sets *unknown to true, otherwise false. */
u32 feerate_min(struct lightningd *ld, bool *unknown);
u32 feerate_max(struct lightningd *ld, bool *unknown);

u32 mutual_close_feerate(struct chain_topology *topo);
u32 opening_feerate(struct chain_topology *topo);
u32 unilateral_feerate(struct chain_topology *topo);

/* We always use feerate-per-ksipa, ie. perkw */
u32 feerate_from_style(u32 feerate, enum feerate_style style);
u32 feerate_to_style(u32 feerate_perkw, enum feerate_style style);

const char *feerate_name(enum feerate feerate);

/* Set feerate_per_kw to this estimate, or fail cmd */
bool json_feerate_estimate(struct command *cmd,
			   u32 **feerate_per_kw, enum feerate feerate);

/* Broadcast a single tx, and rebroadcast as reqd (copies tx).
 * If failed is non-NULL, call that and don't rebroadcast. */
void broadcast_tx(struct chain_topology *topo,
		  struct channel *channel, const struct bitcoin_tx *tx,
		  void (*failed)(struct channel *channel,
				 int exitstatus,
				 const char *err));

struct chain_topology *new_topology(struct lightningd *ld, struct log *log);
void setup_topology(struct chain_topology *topology, struct timers *timers,
		    u32 min_blockheight, u32 max_blockheight);

void begin_topology(struct chain_topology *topo);

struct txlocator *locate_tx(const void *ctx, const struct chain_topology *topo, const struct bitcoin_txid *txid);

/* In channel_control.c */
void notify_feerate_change(struct lightningd *ld);
#endif /* LIGHTNING_LIGHTNINGD_CHAINTOPOLOGY_H */
