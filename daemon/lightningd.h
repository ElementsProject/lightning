#ifndef LIGHTNING_DAEMON_LIGHTNING_H
#define LIGHTNING_DAEMON_LIGHTNING_H
#include "config.h"
#include "bitcoin/pubkey.h"
#include "watch.h"
#include <ccan/list/list.h>
#include <ccan/short_types/short_types.h>
#include <ccan/timer/timer.h>
#include <stdio.h>

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
	struct topology *topology;

	/* Our peers. */
	struct list_head peers;

	/* Addresses to contact peers. */
	struct list_head addresses;

	/* Any outstanding "pay" commands. */
	struct list_head pay_commands;

	/* Our private key */
	struct secret *secret;

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
#endif /* LIGHTNING_DAEMON_LIGHTNING_H */
