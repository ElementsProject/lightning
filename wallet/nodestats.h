#ifndef LIGHTNING_WALLET_NODESTATS_H
#define LIGHTNING_WALLET_NODESTATS_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

struct db;
struct log;
struct nodestats;
struct nodestats_detail;
struct pubkey;

/**
 * nodestats_new - Constructor for a new node statistics handler
 *
 * @ctx - the owner of the node statistics handler.
 * @db - the database connection to use for tracking node statistics.
 * @log - the log to report to.
 */
struct nodestats *nodestats_new(const tal_t *ctx,
				struct db *db,
				struct log *log);

/**
 * nodestats_mark_seen - Inform the node statistics handler that
 * we have seen a node.
 *
 * @nodestats - the node statistics handler
 * @node - the node
 */
void nodestats_mark_seen(struct nodestats *nodestats,
			 const struct pubkey *node);

/**
 * nodestats_incr_* - Inform the node statistics handler to
 * increment a counter.
 *
 * @nodestats - the node statistics handler
 * @node - the node
 */
void nodestats_incr_forwarding_failures(struct nodestats *nodestats,
					const struct pubkey *node);
void nodestats_incr_connect_failures(struct nodestats *nodestats,
				     const struct pubkey *node);
void nodestats_incr_channel_failures(struct nodestats *nodestats,
				     const struct pubkey *node);

/**
 * nodestats_iterate - Iterate over indices of the nodestats
 * table.
 *
 * Start iteration with 0, which returns an index that can
 * be used with nodestats_get_by_index.
 * If this returns a 0, no more node statistics.
 *
 * @nodestats - the node statistics handler
 * @previndex - Previous index.
 */
u64 nodestats_iterate(struct nodestats *nodestats,
		      u64 previndex);

/**
 * nodestats_get_by_index/pubkey - Get detailed node statistics.
 *
 * @nodestats - the node statistics handler.
 * @detail - the statistics to load.
 * @index/@pubkey - key to find node.
 *
 * Return false if not found
 */
bool nodestats_get_by_index(struct nodestats *nodestats,
			    struct nodestats_detail *detail,
			    u64 index);
bool nodestats_get_by_pubkey(struct nodestats *nodestats,
			     struct nodestats_detail *detail,
			     const struct pubkey *pubkey);

#endif /* LIGHTNING_WALLET_NODESTATS_H */
