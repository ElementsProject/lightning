#ifndef LIGHTNING_WALLET_DB_H
#define LIGHTNING_WALLET_DB_H
#include "config.h"

struct ext_key;
struct lightningd;
struct db_stmt;
struct db;

/**
 * db_setup - Open a the lightningd database and update the schema
 *
 * Opens the database, creating it if necessary, and applying
 * migrations until the schema is updated to the current state.
 * Calls fatal() on error.
 *
 * Params:
 *  @ctx: the tal_t context to allocate from
 *  @ld: the lightningd context to hand to upgrade functions.
 *  @bip32_base: the base all of our pubkeys are constructed on
 */
struct db *db_setup(const tal_t *ctx, struct lightningd *ld,
		    const struct ext_key *bip32_base);

#endif /* LIGHTNING_WALLET_DB_H */
