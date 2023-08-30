#ifndef LIGHTNING_WALLET_DB_H
#define LIGHTNING_WALLET_DB_H
#include "config.h"

struct ext_key;
struct indexes;
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

/* We store last wait indices in our var table. */
void load_indexes(struct db *db, struct indexes *indexes);

/* Migration function for old commando datastore runes. */
void migrate_datastore_commando_runes(struct lightningd *ld, struct db *db);
/* Migrate old runes with incorrect id fields */
void migrate_runes_idfix(struct lightningd *ld, struct db *db);
#endif /* LIGHTNING_WALLET_DB_H */
