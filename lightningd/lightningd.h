#ifndef LIGHTNING_LIGHTNINGD_LIGHTNINGD_H
#define LIGHTNING_LIGHTNINGD_LIGHTNINGD_H
#include "config.h"
#include <bitcoin/chainparams.h>
#include <bitcoin/privkey.h>
#include <ccan/container_of/container_of.h>
#include <ccan/time/time.h>
#include <ccan/timer/timer.h>
#include <common/json_escaped.h>
#include <lightningd/htlc_end.h>
#include <stdio.h>
#include <wallet/txfilter.h>
#include <wallet/wallet.h>

/* BOLT #1:
 *
 * The default TCP port is 9735. This corresponds to hexadecimal
 * `0x2607`, the Unicode code point for LIGHTNING.
 */
#define DEFAULT_PORT 9735

/* Various adjustable things. */
struct config {
	/* How long do we want them to lock up their funds? (blocks) */
	u32 locktime_blocks;

	/* How long do we let them lock up our funds? (blocks) */
	u32 locktime_max;

	/* How many blocks before we expect to see anchor?. */
	u32 anchor_onchain_wait;

	/* How many confirms until we consider an anchor "settled". */
	u32 anchor_confirms;

	/* How long will we accept them waiting? */
	u32 anchor_confirms_max;

	/* Maximum percent of fee rate we'll accept. */
	u32 commitment_fee_max_percent;

	/* Minimum percent of fee rate we'll accept. */
	u32 commitment_fee_min_percent;

	/* Percent of fee rate we'll use. */
	u32 commitment_fee_percent;

	/* Minimum CLTV to subtract from incoming HTLCs to outgoing */
	u32 cltv_expiry_delta;

	/* Minimum CLTV if we're the final hop.*/
	u32 cltv_final;

	/* Maximum time for an expiring HTLC (blocks). */
	u32 max_htlc_expiry;

	/* Fee rates. */
	u32 fee_base;
	s32 fee_per_satoshi;

	/* How long between polling bitcoind. */
	struct timerel poll_time;

	/* How long between changing commit and sending COMMIT message. */
	struct timerel commit_time;

	/* How often to broadcast gossip (msec) */
	u32 broadcast_interval;

	/* Channel update interval */
	u32 channel_update_interval;

	/* Do we let the funder set any fee rate they want */
	bool ignore_fee_limits;
};

struct lightningd {
	/* The directory to find all the subdaemons. */
	const char *daemon_dir;

	/* Are we told to run in the background. */
	bool daemon;

	/* Our config dir, and rpc file */
	char *config_dir;
	char *rpc_filename;

	/* Configuration settings. */
	struct config config;

	/* This log_book is owned by all the struct logs */
	struct log_book *log_book;
	/* Log for general stuff. */
	struct log *log;
	const char *logfile;

	/* This is us. */
	struct pubkey id;

	/* My name is... my favorite color is... */
	u8 *alias; /* At least 32 bytes (zero-filled) */
	u8 *rgb; /* tal_len() == 3. */

	/* Any pending timers. */
	struct timers timers;

	/* Port we're listening on */
	u16 portnum;

	/* Addresses to announce to the network (tal_count()) */
	struct wireaddr *wireaddrs;

	/* Bearer of all my secrets. */
	int hsm_fd;
	struct log *hsm_log;

	/* Daemon looking after peers during init / before channel. */
	struct subd *gossip;

	/* All peers we're tracking. */
	struct list_head peers;
	/* FIXME: This should stay in HSM */
	struct secret peer_seed;

	/* Outstanding connect commands. */
	struct list_head connects;

	/* Our chain topology. */
	struct chain_topology *topology;

	/* HTLCs in flight. */
	struct htlc_in_map htlcs_in;
	struct htlc_out_map htlcs_out;

	struct wallet *wallet;

	/* Outstanding waitsendpay commands. */
	struct list_head waitsendpay_commands;
	/* Outstanding sendpay commands. */
	struct list_head sendpay_commands;
	/* Outstanding close commands. */
	struct list_head close_commands;

	/* Maintained by invoices.c */
	struct invoices *invoices;

	/* Transaction filter matching what we're interested in */
	struct txfilter *owned_txfilter;

	/* PID file */
	char *pidfile;

	/* May be useful for non-developers debugging in the field */
	char *debug_subdaemon_io;

	/* Disable automatic reconnects */
	bool no_reconnect;

	/* Initial autocleaninvoice settings. */
	u64 ini_autocleaninvoice_cycle;
	u64 ini_autocleaninvoice_expiredby;

#if DEVELOPER
	/* If we want to debug a subdaemon. */
	const char *dev_debug_subdaemon;

	/* If we want to set a specific non-random HSM seed. */
	const u8 *dev_hsm_seed;

	/* If we have a --dev-disconnect file */
	int dev_disconnect_fd;

	/* If we have --dev-fail-on-subdaemon-fail */
	bool dev_subdaemon_fail;

	/* Things we've marked as not leaking. */
	const void **notleaks;
#endif /* DEVELOPER */
};

const struct chainparams *get_chainparams(const struct lightningd *ld);

/* State for performing backtraces. */
struct backtrace_state *backtrace_state;

/* Check we can run subdaemons, and check their versions */
void test_daemons(const struct lightningd *ld);

#endif /* LIGHTNING_LIGHTNINGD_LIGHTNINGD_H */
