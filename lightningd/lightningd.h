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

/* Various adjustable things. */
struct config {
	/* How long do we want them to lock up their funds? (blocks) */
	u32 locktime_blocks;

	/* How long do we let them lock up our funds? (blocks) */
	u32 locktime_max;

	/* How many confirms until we consider an anchor "settled". */
	u32 anchor_confirms;

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

	/* Fee rates. */
	u32 fee_base;
	s32 fee_per_satoshi;

	/* How long between changing commit and sending COMMIT message. */
	u32 commit_time_ms;

	/* How often to broadcast gossip (msec) */
	u32 broadcast_interval;

	/* Channel update interval */
	u32 channel_update_interval;

	/* Do we let the funder set any fee rate they want */
	bool ignore_fee_limits;

	/* Number of blocks to rescan from the current head, or absolute
	 * blockheight if rescan >= 500'000 */
	s32 rescan;

	/* ipv6 bind disable */
	bool no_ipv6_bind;

	/* Accept fee changes only if they are in the range our_fee -
	 * our_fee*multiplier */
	u32 max_fee_multiplier;

	/* Are we allowed to use DNS lookup for peers. */
	bool use_dns;
};

struct lightningd {
	/* The directory to find all the subdaemons. */
	const char *daemon_dir;

	/* Are we told to run in the background. */
	bool daemon;

	/* Our config dir, and rpc file */
	char *config_dir;

	/* Location of the RPC socket. */
	char *rpc_filename;

	/* The listener for the RPC socket. Can be shut down separately from the
	 * rest of the daemon to allow a clean shutdown, which frees all pending
	 * cmds in a DB transaction. */
	struct io_listener *rpc_listener;

	/* Configuration file name */
	char *config_filename;
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

	/* Do we want to reconnect to other peers? */
	bool reconnect;

	/* Do we want to listen for other peers? */
	bool listen;

	/* Do we want to guess addresses to listen and announce? */
	bool autolisten;

	/* Setup: Addresses to bind/announce to the network (tal_count()) */
	struct wireaddr_internal *proposed_wireaddr;
	/* Setup: And the bitset for each, whether to listen, announce or both */
	enum addr_listen_announce *proposed_listen_announce;

	/* Actual bindings and announcables from gossipd */
	struct wireaddr_internal *binding;
	struct wireaddr *announcable;

	/* Bearer of all my secrets. */
	int hsm_fd;
	struct subd *hsm;

	/* Daemon for routing */
 	struct subd *gossip;

	/* Daemon looking after peers during init / before channel. */
	struct subd *connectd;

	/* All peers we're tracking. */
	struct list_head peers;

	/* Outstanding connect commands. */
	struct list_head connects;

	/* Outstanding fundchannel commands. */
	struct list_head fundchannels;

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

	/* Initial autocleaninvoice settings. */
	u64 ini_autocleaninvoice_cycle;
	u64 ini_autocleaninvoice_expiredby;

	/* Number of blocks we wait for a channel to get funded
	 * if we are the fundee. */
	u32 max_funding_unconfirmed;

#if DEVELOPER
	/* If we want to debug a subdaemon. */
	const char *dev_debug_subdaemon;

	/* If we have a --dev-disconnect file */
	int dev_disconnect_fd;

	/* If we have --dev-fail-on-subdaemon-fail */
	bool dev_subdaemon_fail;

	/* Allow and accept localhost node_announcement addresses */
	bool dev_allow_localhost;

	/* Things we've marked as not leaking. */
	const void **notleaks;
#endif /* DEVELOPER */

	/* tor support */
	struct wireaddr *proxyaddr;
	bool use_proxy_always;
	char *tor_service_password;
	bool pure_tor_setup;
};

const struct chainparams *get_chainparams(const struct lightningd *ld);

/* State for performing backtraces. */
struct backtrace_state *backtrace_state;

/* Check we can run subdaemons, and check their versions */
void test_daemons(const struct lightningd *ld);

/* Notify lightningd about new blocks. */
void notify_new_block(struct lightningd *ld, u32 block_height);

#endif /* LIGHTNING_LIGHTNINGD_LIGHTNINGD_H */
