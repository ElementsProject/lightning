#ifndef LIGHTNING_DAEMON_LIGHTNING_H
#define LIGHTNING_DAEMON_LIGHTNING_H
#include "config.h"
#include "bitcoin/pubkey.h"
#include <ccan/list/list.h>
#include <ccan/short_types/short_types.h>
#include <ccan/timer/timer.h>
#include <secp256k1.h>
#include <stdio.h>

/* Various adjustable things. */
struct config {
	/* How long do we want them to lock up their funds? (seconds) */
	u32 rel_locktime;

	/* How long do we let them lock up our funds? (seconds) */
	u32 rel_locktime_max;

	/* How many confirms until we consider an anchor "settled". */
	u32 anchor_confirms;

	/* How long will we accept them waiting? */
	u32 anchor_confirms_max;

	/* What are we prepared to pay in commitment fee (satoshis). */
	u64 commitment_fee;

	/* How little are we prepared to have them pay? */
	u64 commitment_fee_min;
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

	/* Our peers. */
	struct list_head peers;

	/* Crypto tables for global use. */
	secp256k1_context *secpctx;

	/* Our private key */
	struct secret *secret;

	/* This is us. */
	struct pubkey id;
};
#endif /* LIGHTNING_DAEMON_LIGHTNING_H */
