#include "config.h"
#include <ccan/io/io.h>
#include <ccan/tal/str/str.h>
#include <common/timeout.h>
#include <lightningd/bitcoind.h>
#include <lightningd/chaintopology.h>
#include <lightningd/io_loop_with_timers.h>
#include <lightningd/lightningd.h>
#include <lightningd/log.h>
#include <lightningd/watchman.h>
#include <wallet/wallet.h>

u32 get_block_height(const struct chain_topology *topo)
{
	/* bwatch is the source of truth for processed-block height; the
	 * watchman holds the cached value persisted in the wallet db. */
	if (!topo->ld->watchman)
		return 0;
	return topo->ld->watchman->last_processed_height;
}

u32 get_network_blockheight(const struct chain_topology *topo)
{
	u32 height = get_block_height(topo);
	if (height > topo->headercount)
		return height;
	else
		return topo->headercount;
}

/* On shutdown, channels get deleted last.  That frees from our list, so
 * do it now instead. */
static void destroy_chain_topology(struct chain_topology *topo)
{
	broadcast_shutdown(topo->ld);
}

struct chain_topology *new_topology(struct lightningd *ld, struct logger *log)
{
	struct chain_topology *topo = tal(ld, struct chain_topology);

	topo->ld = ld;
	topo->log = log;
	topo->checkchain_timer = NULL;

	return topo;
}

static bool check_sync(struct bitcoind *bitcoind,
		       const u32 headercount, const u32 blockcount, const bool ibd,
		       struct chain_topology *topo, bool first_call)
{
	topo->headercount = headercount;

	if (ibd) {
		if (first_call)
			log_unusual(bitcoind->log,
				    "Waiting for initial block download (this can take"
				    " a while!)");
		else
			log_debug(bitcoind->log,
				  "Still waiting for initial block download");
	} else if (headercount != blockcount) {
		if (first_call)
			log_unusual(bitcoind->log,
				    "Waiting for bitcoind to catch up"
				    " (%u blocks of %u)",
				    blockcount, headercount);
		else
			log_debug(bitcoind->log,
				  "Waiting for bitcoind to catch up"
				  " (%u blocks of %u)",
				  blockcount, headercount);
	} else {
		bitcoind->synced = true;
		return true;
	}
	return false;
}

/* Loop to see if bitcoind is synced */
static void retry_sync(struct chain_topology *topo);
static void retry_sync_getchaininfo_done(struct bitcoind *bitcoind, const char *chain,
					 const u32 headercount, const u32 blockcount, const bool ibd,
					 struct chain_topology *topo)
{
	if (check_sync(bitcoind, headercount, blockcount, ibd, topo, false)) {
		log_unusual(bitcoind->log, "Bitcoin backend now synced.");
		return;
	}

	topo->checkchain_timer = new_reltimer(bitcoind->ld->timers, topo,
					      /* Be 4x more aggressive in this case. */
					      time_divide(time_from_sec(BITCOIND_POLL_SECONDS), 4),
					      retry_sync, topo);
}

static void retry_sync(struct chain_topology *topo)
{
	topo->checkchain_timer = NULL;
	bitcoind_getchaininfo(topo, topo->ld->bitcoind, get_block_height(topo),
			      retry_sync_getchaininfo_done, topo);
}

struct chaininfo_once {
	const char *chain;
	u32 headercount, blockcount;
	bool ibd;
};

static void get_chaininfo_once(struct bitcoind *bitcoind, const char *chain,
			       const u32 headercount, const u32 blockcount, const bool ibd,
			       struct chaininfo_once *once)
{
	once->chain = tal_strdup(once, chain);
	once->headercount = headercount;
	once->blockcount = blockcount;
	once->ibd = ibd;
	io_break(bitcoind->ld->topology);
}

/* We want to loop and poll until bitcoind has this height */
struct wait_for_height {
	struct bitcoind *bitcoind;
	u32 minheight;
};

/* Timer recursion */
static void retry_height_reached(struct wait_for_height *wh);

static void wait_until_height_reached(struct bitcoind *bitcoind, const char *chain,
				      const u32 headercount, const u32 blockcount, const bool ibd,
				      struct wait_for_height *wh)
{
	if (blockcount >= wh->minheight) {
		io_break(wh);
		return;
	}

	log_debug(bitcoind->ld->log, "bitcoind now at %u of %u blocks, waiting...",
		  blockcount, wh->minheight);
	new_reltimer(bitcoind->ld->timers, bitcoind, time_from_sec(5),
		     retry_height_reached, wh);
}

static void retry_height_reached(struct wait_for_height *wh)
{
	bitcoind_getchaininfo(wh, wh->bitcoind, wh->minheight,
			      wait_until_height_reached, wh);
}

/* Subtract, but floored at 0 */
static u32 blocknum_reduce(u32 blockheight, s32 sub)
{
	if ((u32)sub > blockheight)
		return 0;
	return blockheight - sub;
}

void setup_topology(struct chain_topology *topo)
{
	void *ret;
	/* Since we loop below, we free tmpctx, so we need a local */
	const tal_t *local_ctx = tal(NULL, char);
	struct chaininfo_once *chaininfo = tal(local_ctx, struct chaininfo_once);
	bool blockscan_start_set;
	u32 blockscan_start;

	/* This waits for bitcoind. */
	bitcoind_check_commands(topo->ld->bitcoind);

	/* For testing.. */
	log_debug(topo->ld->log, "All Bitcoin plugin commands registered");

	/*~ If we were asked to rescan from an absolute height (--rescan < 0)
	 * then just go there. Otherwise compute the diff to our current height,
	 * lowerbounded by 0. */
	if (topo->ld->config.rescan < 0) {
		blockscan_start = -topo->ld->config.rescan;
		blockscan_start_set = true;
	} else {
		/* Get the blockheight bwatch reached on the previous run, or 0 */
		blockscan_start = get_block_height(topo);
		blockscan_start_set = (blockscan_start != 0);

		/* If we don't know blockscan_start, can't do this yet */
		if (blockscan_start_set)
			blockscan_start = blocknum_reduce(blockscan_start, topo->ld->config.rescan);
	}

	/* Sanity checks, then topology initialization. */
	chaininfo->chain = NULL;
	bitcoind_getchaininfo(chaininfo, topo->ld->bitcoind, blockscan_start,
			      get_chaininfo_once, chaininfo);

	ret = io_loop_with_timers(topo->ld);
	assert(ret == topo);

	topo->headercount = chaininfo->headercount;
	if (!streq(chaininfo->chain, chainparams->bip70_name))
		fatal("Wrong network! Our Bitcoin backend is running on '%s',"
		      " but we expect '%s'.", chaininfo->chain, chainparams->bip70_name);

	if (!blockscan_start_set) {
		blockscan_start = blocknum_reduce(chaininfo->blockcount, topo->ld->config.rescan);
	} else {
		/* If bitcoind's current blockheight is below the requested
		 * height, wait, as long as header count is greater.  You can
		 * always explicitly request a reindex from that block number
		 * using --rescan=. */
		if (chaininfo->headercount < blockscan_start) {
			fatal("bitcoind has gone backwards from %u to %u blocks!",
			      blockscan_start, chaininfo->blockcount);
		} else if (chaininfo->blockcount < blockscan_start) {
			struct wait_for_height *wh = tal(local_ctx, struct wait_for_height);
			wh->bitcoind = topo->ld->bitcoind;
			wh->minheight = blockscan_start;

			/* We're not happy, but we'll wait... */
			log_broken(topo->ld->log,
				   "bitcoind has gone backwards from %u to %u blocks, waiting...",
				   blockscan_start, chaininfo->blockcount);
			bitcoind_getchaininfo(wh, topo->ld->bitcoind, blockscan_start,
					      wait_until_height_reached, wh);
			ret = io_loop_with_timers(topo->ld);
			assert(ret == wh);
		}
	}

	/* Sets bitcoin->synced or logs warnings */
	check_sync(topo->ld->bitcoind, chaininfo->headercount, chaininfo->blockcount,
		   chaininfo->ibd, topo, true);

	tal_free(local_ctx);

	tal_add_destructor(topo, destroy_chain_topology);
}

void begin_topology(struct chain_topology *topo)
{
	/* If we were not synced, start looping to check */
	if (!topo->ld->bitcoind->synced)
		retry_sync(topo);
	/* Bootstrap the rebroadcast timer; it self-perpetuates from there. */
	rebroadcast_txs(topo->ld);
}

void stop_topology(struct chain_topology *topo)
{
	/* Remove timers while we're cleaning up plugins. */
	tal_free(topo->checkchain_timer);
}
