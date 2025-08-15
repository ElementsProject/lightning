#ifndef LIGHTNING_WALLET_ACCOUNT_MIGRATION_H
#define LIGHTNING_WALLET_ACCOUNT_MIGRATION_H
#include "config.h"

struct lightningd;
struct db;

/* Some migrations are so epic they get their own file.  Not in a good way. */
void migrate_from_account_db(struct lightningd *ld, struct db *db);
#endif /* LIGHTNING_WALLET_ACCOUNT_MIGRATION_H */
