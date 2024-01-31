#ifndef LIGHTNING_LIGHTNINGD_LIGHTNINGD_H
#define LIGHTNING_LIGHTNINGD_LIGHTNINGD_H
#include "config.h"
#include <ccan/ccan/opt/opt.h>
#include <lightningd/htlc_end.h>
#include <lightningd/htlc_set.h>
#include <lightningd/options.h>
#include <lightningd/peer_control.h>
#include <lightningd/wait.h>
#include <signal.h>
#include <sys/stat.h>
#include <wallet/wallet.h>

struct amount_msat;

/* Various adjustable things. */
struct config {
	/* How long do we want them to lock up their funds? (blocks) */
	u32 locktime_blocks;

	/* How long do we let them lock up our funds? (blocks) */
	u32 locktime_max;

	/* How many confirms until we consider an anchor "settled". */
	u32 anchor_confirms;

	/* Minimum CLTV to subtract from incoming HTLCs to outgoing */
	u32 cltv_expiry_delta;

	/* Minimum CLTV if we're the final hop.*/
	u32 cltv_final;

	/* Fee rates. */
	u32 fee_base;
	u32 fee_per_satoshi;

	/* htlcs per channel */
	u32 max_concurrent_htlcs;

	/* htlc min/max values */
	struct amount_msat htlc_minimum_msat;
	struct amount_msat htlc_maximum_msat;

	/* Max amount of dust allowed per channel */
	struct amount_msat max_dust_htlc_exposure_msat;

	/* How long between changing commit and sending COMMIT message. */
	u32 commit_time_ms;

	/* Do we let the opener set any fee rate they want */
	bool ignore_fee_limits;

	/* Number of blocks to rescan from the current head, or absolute
	 * blockheight if rescan >= 500'000 */
	s32 rescan;

	/* ipv6 bind disable */
	bool no_ipv6_bind;

	/* Are we allowed to use DNS lookup for peers. */
	bool use_dns;

	/* Excplicitly turns 'on' or 'off' IP discovery feature. */
	enum opt_autobool ip_discovery;

	/* Public TCP port assumed for IP discovery. Defaults to chainparams. */
	u32 ip_discovery_port;

	/* Minimal amount of effective funding_satoshis for accepting channels */
	u64 min_capacity_sat;

	/* This is the key we use to encrypt `hsm_secret`. */
	struct secret *keypass;

	/* How long before we give up waiting for INIT msg */
	u32 connection_timeout_secs;

	/* EXPERIMENTAL: offers support */
	bool exp_offers;

	/* Allow dust reserves (including 0) when being called via
	 * `fundchannel` or in the `openchannel` hook. This is a
	 * slight spec incompatibility, but implementations do this
	 * already. */
	bool allowdustreserve;

	/* Require peer to send confirmed inputs */
	bool require_confirmed_inputs;

	/* The factor to time the urgent feerate by to get the maximum
	 * acceptable feerate.  (10, but can be overridden by dev-max-fee-multiplier) */
	u32 max_fee_multiplier;

	/* Percent of CONSERVATIVE/2 feerate we'll use for commitment txs. */
	u64 commit_fee_percent;

	/* Commit feerate offset above min_feerate to use as a channel opener */
	u32 feerate_offset;
};

typedef STRMAP(const char *) alt_subdaemon_map;

enum lightningd_state {
	LD_STATE_INITIALIZING,
	LD_STATE_RUNNING,
	LD_STATE_SHUTDOWN,
};

struct lightningd {
	/* The directory to find all the subdaemons. */
	const char *daemon_dir;

	/* Are deprecated APIs enabled? */
	bool deprecated_ok;

	/* If we told to run in the background, this is our parent fd, otherwise
	 * -1. */
	int daemon_parent_fd;

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

	/* --developer? */
	bool developer;

	/* Configuration file name */
	char *config_filename;
	/* Configuration settings. */
	struct config config;
	/* Where each configuration setting came from */
	struct configvar **configvars;

	/* This log_book is owned by all the struct loggers */
	struct log_book *log_book;
	/* Log for general stuff. */
	struct logger *log;
	const char **logfiles;

	/* This is us. */
	struct node_id id;

	/* The public base for our payer_id keys */
	struct pubkey bolt12_base;

	/* Secret base for our invoices */
	struct secret invoicesecret_base;

	/* Feature set we offer. */
	struct feature_set *our_features;

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

	/* Actual bindings and announceables from connectd */
	struct wireaddr_internal *binding;
	struct wireaddr *announceable;

	/* Current node announcement (if any) */
	const u8 *node_announcement;

	/* Lease rates to advertize, set by json_setleaserates */
	struct lease_rates *lease_rates;

	/* unverified remote_addr as reported by recent peers */
	struct wireaddr *remote_addr_v4;
	struct wireaddr *remote_addr_v6;
	struct node_id remote_addr_v4_peer;
	struct node_id remote_addr_v6_peer;

	/* verified discovered IPs to be used for anouncement */
	struct wireaddr *discovered_ip_v4;
	struct wireaddr *discovered_ip_v6;

	/* Bearer of all my secrets. */
	int hsm_fd;
	struct subd *hsm;

	/* Daemon for routing */
 	struct subd *gossip;

	/* Daemon looking after peers during init / before channel. */
	struct subd *connectd;
	/* Reconnection attempts */
	struct delayed_reconnect_map *delayed_reconnect_map;

	/* All peers we're tracking (by node_id) */
	struct peer_node_id_map *peers;
	/* And those in database by dbid */
	struct peer_dbid_map *peers_by_dbid;

	/* Outstanding connect commands. */
	struct list_head connects;

	/* Our chain topology. */
	struct chain_topology *topology;

	/* Blockheight (as acknowledged by gossipd) */
	u32 gossip_blockheight;

	/* HTLCs in flight. */
	struct htlc_in_map *htlcs_in;
	struct htlc_out_map *htlcs_out;

	/* Sets of HTLCs we are holding onto for MPP. */
	struct htlc_set_map *htlc_sets;

	/* Derive all our keys from here (see bip32_pubkey) */
	struct ext_key *bip32_base;
	struct wallet *wallet;

	/* Outstanding waitsendpay commands. */
	struct list_head waitsendpay_commands;
	/* Outstanding close commands. */
	struct list_head close_commands;
	/* Outstanding ping commands. */
	struct list_head ping_commands;
	/* Outstanding disconnect commands. */
	struct list_head disconnect_commands;
	/* Outstanding wait commands */
	struct list_head wait_commands;

	/* Outstanding splice commands. */
	struct list_head splice_commands;

	/* Maintained by invoices.c */
	struct invoices *invoices;

	/* Transaction filter matching what we're interested in */
	struct txfilter *owned_txfilter;

	/* PID file */
	char *pidfile;

	/* RPC which asked us to shutdown, if non-NULL */
	struct io_conn *stop_conn;
	/* RPC response to send once we've shut down. */
	const char *stop_response;

	/* All the subdaemons. */
	struct list_head subds;

	/* Used these feerates instead of whatever bcli returns (up to
	 * FEERATE_PENALTY). */
	u32 *force_feerates;

	/* If they force db upgrade on or off this is set. */
	bool *db_upgrade_ok;

	/* Announce names in config as DNS records (recently BOLT 7 addition) */
	bool announce_dns;

	/* Indexes used by all the wait infra */
	struct indexes indexes[NUM_WAIT_SUBSYSTEM];

	/* Contains the codex32 string used with --recover flag */
	char *recover;

	/* If we want to debug a subdaemon/plugin. */
	char *dev_debug_subprocess;

	/* If we have --dev-no-plugin-checksum */
	bool dev_no_plugin_checksum;

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

	/* Speedup reconnect delay, for testing. */
	bool dev_fast_reconnect;

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

	bool dev_no_version_checks;

	/* Number of blocks we wait for a channel to get funded
	 * if we are the fundee. */
	u32 dev_max_funding_unconfirmed;

	/* Special switches to test onion compatibility */
	bool dev_ignore_modern_onion;

	/* Tell channeld to disable commits after this many. */
	int dev_disable_commit;

	/* Tell channeld not to worry about pings. */
	bool dev_no_ping_timer;

	/* Tell openingd/dualopend to accept all, allow sending any. */
	bool dev_any_channel_type;

	/* tor support */
	struct wireaddr *proxyaddr;
	bool always_use_proxy;
	char *tor_service_password;
	bool pure_tor_setup;

	struct plugins *plugins;

	char *wallet_dsn;

	bool encrypted_hsm;
	/* What (additional) messages the HSM accepts */
	u32 *hsm_capabilities;

	mode_t initial_umask;

	/* Outstanding waitblockheight commands.  */
	struct list_head waitblockheight_commands;

	alt_subdaemon_map alt_subdaemons;

	enum lightningd_state state;

	/* Total number of coin moves we've seen, since
	 * coin move tracking was cool */
	s64 coin_moves_count;

	/* If non-NULL, contains the exit code to use.  */
	int *exit_code;

	/* The round-robin list of channels, for use when doing MPP.  */
	u64 rr_counter;

	/* Should we re-exec ourselves instead of just exiting? */
	bool try_reexec;
	/* If set, we are to restart with --recover=... */
	const char *recover_secret;

	/* Array of (even) TLV types that we should allow. This is required
	 * since we otherwise would outright reject them. */
	u64 *accept_extra_tlv_types;

	/* EXPERIMENTAL: websocket port if non-zero */
	u16 websocket_port;

	/* --experimental-upgrade-protocol */
	bool experimental_upgrade_protocol;

	/* --invoices-onchain-fallback */
	bool unified_invoices;

	/* For anchors: how much do we keep for spending close txs? */
	struct amount_sat emergency_sat;

	/* runes! */
	struct runes *runes;

	/* Explicitly re-enabled deprecated APIs. */
	const char **api_begs;
};

/* Turning this on allows a tal allocation to return NULL, rather than aborting.
 * Use only on carefully tested code! */
extern bool tal_oom_ok;

/* Returns true if called with a recognized subdaemon, eg: "hsmd" */
bool is_subdaemon(const char *sdname);

/* Returns the path to the subdaemon. Considers alternate subdaemon paths. */
const char *subdaemon_path(const tal_t *ctx, const struct lightningd *ld, const char *name);

/* Check we can run subdaemons, and check their versions */
void test_subdaemons(const struct lightningd *ld);

/* Notify lightningd about new blocks. */
void notify_new_block(struct lightningd *ld, u32 block_height);

/* Signal a clean exit from lightningd.
 * NOTE! This function **returns**.
 * This just causes the main loop to exit, so you have to return
 * all the way to the main loop for `lightningd` to exit.
 */
void lightningd_exit(struct lightningd *ld, int exit_code);

/* Should we accept them using this deprecated API?  (add details to
 * log msg if non-NULL) */
bool lightningd_deprecated_in_ok(struct lightningd *ld,
				 struct logger *log,
				 bool deprecated_apis,
				 const char *subsys,
				 const char *api,
				 const char *start,
				 const char *end,
				 const char *details);

/* Should we output this deprecated field? */
bool lightningd_deprecated_out_ok(struct lightningd *ld,
				  bool deprecated_apis,
				  const char *subsys,
				  const char *api,
				  const char *start,
				  const char *end);

#endif /* LIGHTNING_LIGHTNINGD_LIGHTNINGD_H */
