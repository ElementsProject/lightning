#ifndef LIGHTNING_WALLET_DATASTORE_H
#define LIGHTNING_WALLET_DATASTORE_H
/* Access routines for the datastore: here so that tools/lightningd-downgrade
 * can use them */
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <stdbool.h>

struct db;
struct db_stmt;

/* Does k1 match k2 as far as k2 goes? */
bool datastore_key_startswith(const char **k1, const char **k2);
bool datastore_key_eq(const char **k1, const char **k2);
void db_bind_datastore_key(struct db_stmt *stmt, const char **key);
u8 *db_datastore_get(const tal_t *ctx,
		     struct db *db,
		     const char **key,
		     u64 *generation);
struct db_stmt *db_datastore_next(const tal_t *ctx,
				  struct db_stmt *stmt,
				  const char **startkey,
				  const char ***key,
				  const u8 **data,
				  u64 *generation);

struct db_stmt *db_datastore_first(const tal_t *ctx,
				   struct db *db,
				   const char **startkey,
				   const char ***key,
				   const u8 **data,
				   u64 *generation);

/* Update existing record */
void db_datastore_update(struct db *db, const char **key, const u8 *data);
#endif /* LIGHTNING_WALLET_DATASTORE_H */
