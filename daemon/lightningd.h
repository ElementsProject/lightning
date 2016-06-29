#ifndef LIGHTNING_DAEMON_LIGHTNING_H
#define LIGHTNING_DAEMON_LIGHTNING_H
#include "config.h"
#include "bitcoin/pubkey.h"
#include "watch.h"
#include <ccan/list/list.h>
#include <ccan/short_types/short_types.h>
#include <ccan/timer/timer.h>
#include <secp256k1.h>
#include <stdio.h>

/* Various adjustable things. */
struct config {
	/* Are we on testnet? */
	bool testnet;

	/* How long do we want them to lock up their funds? (blocks) */
	u32 locktime_blocks;

	/* How long do we let them lock up our funds? (blocks) */
	u32 locktime_max;

	/* How many confirms until we consider an anchor "settled". */
	u32 anchor_confirms;

	/* How long will we accept them waiting? */
	u32 anchor_confirms_max;

	/* How many blocks until we stop watching a close commit? */
	u32 forever_confirms;

	/* What are we prepared to pay in commitment fee (satoshis/kb). */
	u64 commitment_fee_rate;

	/* How little are we prepared to have them pay? */
	u64 commitment_fee_rate_min;

	/* What fee we use for the closing transaction (satoshis/kb) */
	u64 closing_fee_rate;

	/* Minimum/maximum time for an expiring HTLC (blocks). */
	u32 min_htlc_expiry, max_htlc_expiry;

	/* Fee rates. */
	u32 fee_base;
	s32 fee_per_satoshi;
	
	/* How long between polling bitcoind. */
	struct timerel poll_time;

	/* How long between changing commit and sending COMMIT message. */
	struct timerel commit_time;
};

/* Here's where the global variables hide! */
struct lightningd_state {
	/* Where all our logging goes. */ 
	struct log_record *log_record;
	struct log *base_log;
	FILE *logf;

	/* Our config dir, and rpc file */
	char *config_dir;
	char *rpc_filename;

	/* Configuration settings. */
	struct config config;

	/* Any pending timers. */
	struct timers timers;

	/* Cached block topology. */
	struct topology *topology;
	
	/* Our peers. */
	struct list_head peers;

	/* Crypto tables for global use. */
	secp256k1_context *secpctx;

	/* Our private key */
	struct secret *secret;

	/* This is us. */
	struct pubkey id;

	/* Transactions/txos we are watching. */
	struct txwatch_hash txwatches;
	struct txowatch_hash txowatches;

	/* Outstanding bitcoind requests. */
	struct list_head bitcoin_req;
	bool bitcoin_req_running;

	/* Wallet addresses we maintain. */
	struct list_head wallet;

	/* Payments for r values we know about. */
	struct list_head payments;

	/* All known nodes. */
	struct node_map *nodes;

	/* For testing: don't fail if we can't route. */
	bool dev_never_routefail;
};
#endif /* LIGHTNING_DAEMON_LIGHTNING_H */
