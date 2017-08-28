#ifndef LIGHTNING_LIGHTNINGD_LIGHTNINGD_H
#define LIGHTNING_LIGHTNINGD_LIGHTNINGD_H
#include "config.h"
#include <bitcoin/chainparams.h>
#include <bitcoin/privkey.h>
#include <ccan/container_of/container_of.h>
#include <ccan/time/time.h>
#include <ccan/timer/timer.h>
#include <lightningd/htlc_end.h>
#include <stdio.h>
#include <wallet/wallet.h>

/* BOLT #1:
 *
 * The default TCP port is 9735. This corresponds to hexadecimal
 * `0x2607`, the Unicode code point for LIGHTNING.
 */
#define DEFAULT_PORT 0x2607

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

	/* How many blocks until we stop watching a close commit? */
	u32 forever_confirms;

	/* Maximum percent of fee rate we'll accept. */
	u32 commitment_fee_max_percent;

	/* Minimum percent of fee rate we'll accept. */
	u32 commitment_fee_min_percent;

	/* Percent of fee rate we'll use. */
	u32 commitment_fee_percent;

	/* Minimum/maximum time for an expiring HTLC (blocks). */
	u32 min_htlc_expiry, max_htlc_expiry;

	/* How many blocks before upstream HTLC expiry do we panic and dump? */
	u32 deadline_blocks;

	/* Fee rates. */
	u32 fee_base;
	s32 fee_per_satoshi;

	/* How long between polling bitcoind. */
	struct timerel poll_time;

	/* How long between changing commit and sending COMMIT message. */
	struct timerel commit_time;

	/* Whether to enable IRC peer discovery. */
	bool use_irc;

	/* Whether to ignore database version. */
	bool db_version_ignore;

	/* IPv4 or IPv6 address to announce to the network */
	struct ipaddr ipaddr;
};

/* Here's where the global variables hide! */
struct lightningd_state {
	/* Where all our logging goes. */
	struct log_book *log_book;
	struct log *base_log;
	FILE *logf;

	/* Our config dir, and rpc file */
	char *config_dir;
	char *rpc_filename;

	/* Port we're listening on */
	u16 portnum;

	/* We're on testnet. */
	bool testnet;

	/* Configuration settings. */
	struct config config;

	/* The database where we keep our stuff. */
	struct db *db;

	/* Any pending timers. */
	struct timers timers;

	/* Cached block topology. */
	struct chain_topology *topology;

	/* Our peers. */
	struct list_head peers;

	/* Addresses to contact peers. */
	struct list_head addresses;

	/* Any outstanding "pay" commands. */
	struct list_head pay_commands;

	/* Our private key */
	struct privkey *privkey;

	/* This is us. */
	struct pubkey id;

	/* Our tame bitcoind. */
	struct bitcoind *bitcoind;

	/* Wallet addresses we maintain. */
	struct list_head wallet;

	/* Maintained by invoices.c */
	struct invoices *invoices;

	/* Routing information */
	struct routing_state *rstate;

	/* For testing: don't fail if we can't route. */
	bool dev_never_routefail;

	/* Re-exec hack for testing. */
	char **reexec;

	/* IP/hostname to be announced for incoming connections */
	char *external_ip;

	/* Announce timer. */
	struct oneshot *announce;
};

/* FIXME: This is two structures, during the migration from old setup to new */
struct lightningd {
	/* Must be first, since things assume we can tal() off it */
	struct lightningd_state dstate;

	/* The directory to find all the subdaemons. */
	const char *daemon_dir;

	/* Log for general stuff. */
	struct log *log;

	/* Bearer of all my secrets. */
	int hsm_fd;

	/* Daemon looking after peers during init / before channel. */
	struct subd *gossip;

	/* All peers we're tracking. */
	struct list_head peers;
	/* FIXME: This should stay in HSM */
	struct secret peer_seed;
	/* Used to give a unique seed to every peer. */
	u64 peer_counter;

	/* Public base for bip32 keys, and max we've ever used. */
	struct ext_key *bip32_base;

	/* Our bitcoind context. */
	struct bitcoind *bitcoind;

	/* Our chain topology. */
	struct chain_topology *topology;

	/* If we want to debug a subdaemon. */
	const char *dev_debug_subdaemon;

	/* If we have a --dev-disconnect file */
	int dev_disconnect_fd;

	/* HTLCs in flight. */
	struct htlc_in_map htlcs_in;
	struct htlc_out_map htlcs_out;

	u32 broadcast_interval;

	struct wallet *wallet;

	const struct chainparams *chainparams;
};

/**
 * derive_peer_seed - Generate a unique secret for this peer's channel
 *
 * @ld: the lightning daemon to get global secret from
 * @peer_seed: where to store the generated secret
 * @peer_id: the id node_id of the remote peer
 * @chan_id: channel ID
 *
 * This method generates a unique secret from the given parameters. It
 * is important that this secret be unique for each channel, but it
 * must be reproducible for the same channel in case of
 * reconnection. We use the DB channel ID to guarantee unique secrets
 * per channel.
 */
void derive_peer_seed(struct lightningd *ld, struct privkey *peer_seed,
		      const struct pubkey *peer_id, const u64 channel_id);

struct peer *find_peer_by_unique_id(struct lightningd *ld, u64 unique_id);
/* FIXME */
static inline struct lightningd *
ld_from_dstate(const struct lightningd_state *dstate)
{
	return container_of(dstate, struct lightningd, dstate);
}
#endif /* LIGHTNING_LIGHTNINGD_LIGHTNINGD_H */
