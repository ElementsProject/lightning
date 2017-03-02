#ifndef LIGHTNING_DAEMON_CHAINTOPOLOGY_H
#define LIGHTNING_DAEMON_CHAINTOPOLOGY_H
#include "config.h"
#include <bitcoin/block.h>
#include <bitcoin/shadouble.h>
#include <ccan/list/list.h>
#include <ccan/short_types/short_types.h>
#include <ccan/structeq/structeq.h>
#include <ccan/time/time.h>
#include <daemon/jsmn/jsmn.h>
#include <daemon/watch.h>
#include <stddef.h>

struct bitcoin_tx;
struct bitcoind;
struct command;
struct lightningd_state;
struct peer;
struct sha256_double;
struct txwatch;

/* Off topology->outgoing_txs */
struct outgoing_tx {
	struct list_node list;
	struct peer *peer;
	const char *hextx;
	struct sha256_double txid;
	void (*failed)(struct peer *peer, int exitstatus, const char *err);
	/* FIXME: Remove this. */
	struct chain_topology *topo;
};

struct block {
	int height;

	/* Actual header. */
	struct bitcoin_block_hdr hdr;

	/* Previous block (if any). */
	struct block *prev;

	/* Next block (if any). */
	struct block *next;

	/* Key for hash table */
	struct sha256_double blkid;

	/* 0 if not enough predecessors. */
	u32 mediantime;

	/* Transactions in this block we care about */
	struct sha256_double *txids;

	/* And their associated index in the block */
	u32 *txnums;

	/* Full copy of txs (trimmed to txs list in connect_block) */
	struct bitcoin_tx **full_txs;

	/* FIXME: Remove this. */
	struct chain_topology *topo;
};

/* Hash blocks by sha */
static inline const struct sha256_double *keyof_block_map(const struct block *b)
{
	return &b->blkid;
}

static inline size_t hash_sha(const struct sha256_double *key)
{
	size_t ret;

	memcpy(&ret, key, sizeof(ret));
	return ret;
}

static inline bool block_eq(const struct block *b, const struct sha256_double *key)
{
	return structeq(&b->blkid, key);
}
HTABLE_DEFINE_TYPE(struct block, keyof_block_map, hash_sha, block_eq, block_map);

struct chain_topology {
	struct block *root;
	struct block *tip;
	struct block_map block_map;
	u64 feerate;
	bool startup;

	/* Where to log things. */
	struct log *log;

	/* How far back (in blocks) to go. */
	unsigned int first_blocknum;

	/* How often to poll. */
	struct timerel poll_time;

	/* The bitcoind. */
	struct bitcoind *bitcoind;

	/* Our timer list. */
	struct timers *timers;

	/* Bitcoin transctions we're broadcasting */
	struct list_head outgoing_txs;

	/* Force a partiular fee rate regardless of estimatefee (satoshis/kb) */
	u64 override_fee_rate;

	/* What fee we use if estimatefee fails (satoshis/kb) */
	u64 default_fee_rate;

	/* Transactions/txos we are watching. */
	struct txwatch_hash txwatches;
	struct txowatch_hash txowatches;

	/* Suppress broadcast (for testing) */
	bool dev_no_broadcast;
};

/* Information relevant to locating a TX in a blockchain. */
struct txlocator {

	/* The height of the block that includes this transaction */
	u32 blkheight;

	/* Position of the transaction in the transactions list */
	u32 index;
};

/* This is the number of blocks which would have to be mined to invalidate
 * the tx. */
size_t get_tx_depth(const struct chain_topology *topo,
		    const struct sha256_double *txid);

/* Get the mediantime of the block including this tx (must be one!) */
u32 get_tx_mediantime(const struct chain_topology *topo,
		      const struct sha256_double *txid);

/* Get mediantime of the tip; if more than one, pick greatest time. */
u32 get_tip_mediantime(const struct chain_topology *topo);

/* Get highest block number. */
u32 get_block_height(const struct chain_topology *topo);

/* Get fee rate. */
u64 get_feerate(const struct chain_topology *topo);

/* Broadcast a single tx, and rebroadcast as reqd (copies tx).
 * If failed is non-NULL, call that and don't rebroadcast. */
void broadcast_tx(struct chain_topology *topo,
		  struct peer *peer, const struct bitcoin_tx *tx,
		  void (*failed)(struct peer *peer,
				 int exitstatus,
				 const char *err));

struct chain_topology *new_topology(const tal_t *ctx, struct log *log);
void setup_topology(struct chain_topology *topology, struct bitcoind *bitcoind,
		    struct timers *timers,
		    struct timerel poll_time, u32 first_peer_block);

struct txlocator *locate_tx(const void *ctx, const struct chain_topology *topo, const struct sha256_double *txid);

void notify_new_block(struct chain_topology *topo, unsigned int height);

void json_dev_broadcast(struct command *cmd,
			struct chain_topology *topo,
			const char *buffer, const jsmntok_t *params);

#endif /* LIGHTNING_DAEMON_CRYPTOPKT_H */
