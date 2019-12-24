#ifndef LIGHTNING_LIGHTNINGD_LIGHTNINGD_H
#define LIGHTNING_LIGHTNINGD_LIGHTNINGD_H
#include "config.h"
#include <bitcoin/chainparams.h>
#include <bitcoin/privkey.h>
#include <ccan/container_of/container_of.h>
#include <ccan/strmap/strmap.h>
#include <ccan/time/time.h>
#include <ccan/timer/timer.h>
#include <lightningd/htlc_end.h>
#include <lightningd/htlc_set.h>
#include <lightningd/plugin.h>
#include <stdio.h>
#include <sys/stat.h>
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
	u32 fee_per_satoshi;

	/* htlcs per channel */
	u32 max_concurrent_htlcs;

	/* How long between changing commit and sending COMMIT message. */
	u32 commit_time_ms;

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

	/* Minimal amount of effective funding_satoshis for accepting channels */
	u64 min_capacity_sat;

	/* Allow to define the default behavior of tor services calls*/
	bool use_v3_autotor;

	/* This is the key we use to encrypt `hsm_secret`. */
	struct secret *keypass;
};

struct lightningd {
	/* The directory to find all the subdaemons. */
	const char *daemon_dir;

	/* If we told to run in the background, this is our parent fd, otherwise
	 * -1. */
	int daemon_parent_fd;

	int pid_fd;

	/* Our config basedir, network directory, and rpc file */
	char *config_basedir, *config_netdir;

	/* Location of the RPC socket. */
	char *rpc_filename;
	/* Mode of the RPC filename. */
	mode_t rpc_filemode;

	/* The root of the jsonrpc interface. Can be shut down
	 * separately from the rest of the daemon to allow a clean
	 * shutdown, which frees all pending cmds in a DB
	 * transaction. */
	struct jsonrpc *jsonrpc;

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
	struct node_id id;

	/* My name is... my favorite color is... */
	u8 *alias; /* At least 32 bytes (zero-filled) */
	u8 *rgb; /* tal_len() == 3. */

	/* Any pending timers. */
	struct timers *timers;

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

	/* Our chain topology. */
	struct chain_topology *topology;

	/* HTLCs in flight. */
	struct htlc_in_map htlcs_in;
	struct htlc_out_map htlcs_out;

	/* Sets of HTLCs we are holding onto for MPP. */
	struct htlc_set_map htlc_sets;

	struct wallet *wallet;

	/* Outstanding waitsendpay commands. */
	struct list_head waitsendpay_commands;
	/* Outstanding sendpay commands. */
	struct list_head sendpay_commands;
	/* Outstanding close commands. */
	struct list_head close_commands;
	/* Outstanding ping commands. */
	struct list_head ping_commands;

	/* Maintained by invoices.c */
	struct invoices *invoices;

	/* Transaction filter matching what we're interested in */
	struct txfilter *owned_txfilter;

	/* PID file */
	char *pidfile;

	/* Number of blocks we wait for a channel to get funded
	 * if we are the fundee. */
	u32 max_funding_unconfirmed;

	/* If we want to debug a subdaemon/plugin. */
	const char *dev_debug_subprocess;

	/* RPC which asked us to shutdown, if non-NULL */
	struct io_conn *stop_conn;
	/* RPC response to send once we've shut down. */
	const char *stop_response;

#if DEVELOPER
	/* If we have a --dev-disconnect file */
	int dev_disconnect_fd;

	/* If we have --dev-fail-on-subdaemon-fail */
	bool dev_subdaemon_fail;

	/* Allow and accept localhost node_announcement addresses */
	bool dev_allow_localhost;

	/* Timestamp to use for gossipd, iff non-zero */
	u32 dev_gossip_time;

	/* Speedup gossip propagation, for testing. */
	bool dev_fast_gossip;
	bool dev_fast_gossip_prune;

	/* Things we've marked as not leaking. */
	const void **notleaks;

	/* This is the forced private key for the node. */
	struct privkey *dev_force_privkey;

	/* This is the forced bip32 seed for the node. */
	struct secret *dev_force_bip32_seed;

	/* These are the forced channel secrets for the node. */
	struct secrets *dev_force_channel_secrets;
	struct sha256 *dev_force_channel_secrets_shaseed;

	struct channel_id *dev_force_tmp_channel_id;

	/* For slow tests (eg protocol tests) don't die if HTLC not
	 * committed in 30 secs */
	bool dev_no_htlc_timeout;
#endif /* DEVELOPER */

	/* tor support */
	struct wireaddr *proxyaddr;
	bool use_proxy_always;
	char *tor_service_password;
	bool pure_tor_setup;

	/* Original directory for deprecated plugin-relative-to-cwd */
	const char *original_directory;

	struct plugins *plugins;

	char *wallet_dsn;

	bool encrypted_hsm;

	mode_t initial_umask;

	/* Outstanding waitblockheight commands.  */
	struct list_head waitblockheight_commands;

	STRMAP(const char *) alt_subdaemons;
};

/* Turning this on allows a tal allocation to return NULL, rather than aborting.
 * Use only on carefully tested code! */
extern bool tal_oom_ok;

/* Returns true if called with a recognized subdaemon, eg: "lightning_hsmd" */
bool is_subdaemon(const char *sdname);

/* Returns the path to the subdaemon. Considers alternate subdaemon paths. */
const char *subdaemon_path(const tal_t *ctx, const struct lightningd *ld, const char *name);

/* Check we can run subdaemons, and check their versions */
void test_subdaemons(const struct lightningd *ld);

/* Notify lightningd about new blocks. */
void notify_new_block(struct lightningd *ld, u32 block_height);

#endif /* LIGHTNING_LIGHTNINGD_LIGHTNINGD_H */
