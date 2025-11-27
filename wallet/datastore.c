#include "config.h"
#include <ccan/cast/cast.h>
#include <ccan/str/str.h>
#include <ccan/tal/str/str.h>
#include <db/bindings.h>
#include <db/common.h>
#include <db/utils.h>
#include <wallet/datastore.h>
#include <wallet/db.h>

/* Does k1 match k2 as far as k2 goes? */
bool datastore_key_startswith(const char **k1, const char **k2)
{
	size_t k1len = tal_count(k1), k2len = tal_count(k2);

	if (k2len > k1len)
		return false;

	for (size_t i = 0; i < k2len; i++) {
		if (!streq(k1[i], k2[i]))
			return false;
	}
	return true;
}

bool datastore_key_eq(const char **k1, const char **k2)
{
	return tal_count(k1) == tal_count(k2)
		&& datastore_key_startswith(k1, k2);
}

/* We join key parts with nuls for now. */
void db_bind_datastore_key(struct db_stmt *stmt, const char **key)
{
	u8 *joined;
	size_t len;

	if (tal_count(key) == 1) {
		db_bind_blob(stmt, (u8 *)key[0], strlen(key[0]));
		return;
	}

	len = strlen(key[0]);
	joined = (u8 *)tal_strdup(tmpctx, key[0]);
	for (size_t i = 1; i < tal_count(key); i++) {
		tal_resize(&joined, len + 1 + strlen(key[i]));
		joined[len] = '\0';
		memcpy(joined + len + 1, key[i], strlen(key[i]));
		len += 1 + strlen(key[i]);
	}
	db_bind_blob(stmt, joined, len);
}

u8 *db_datastore_get(const tal_t *ctx,
		     struct db *db,
		     const char **key,
		     u64 *generation)
{
	struct db_stmt *stmt;
	u8 *ret;

	stmt = db_prepare_v2(db,
			     SQL("SELECT data, generation"
				 " FROM datastore"
				 " WHERE key = ?"));
	db_bind_datastore_key(stmt, key);
	db_query_prepared(stmt);

	if (!db_step(stmt)) {
		tal_free(stmt);
		return NULL;
	}

	ret = db_col_arr(ctx, stmt, "data", u8);
	if (generation)
		*generation = db_col_u64(stmt, "generation");
	else
		db_col_ignore(stmt, "generation");
	tal_free(stmt);
	return ret;
}

static const char **db_col_datastore_key(const tal_t *ctx,
					 struct db_stmt *stmt,
					 const char *colname)
{
	char **key;
	const u8 *joined = db_col_blob(stmt, colname);
	size_t len = db_col_bytes(stmt, colname);

	key = tal_arr(ctx, char *, 0);
	do {
		size_t partlen;
		for (partlen = 0; partlen < len; partlen++) {
			if (joined[partlen] == '\0') {
				partlen++;
				break;
			}
		}
		tal_arr_expand(&key, tal_strndup(key, (char *)joined, partlen));
		len -= partlen;
		joined += partlen;
	} while (len != 0);

	return cast_const2(const char **, key);
}

struct db_stmt *db_datastore_next(const tal_t *ctx,
				  struct db_stmt *stmt,
				  const char **startkey,
				  const char ***key,
				  const u8 **data,
				  u64 *generation)
{
	if (!db_step(stmt))
		return tal_free(stmt);

	*key = db_col_datastore_key(ctx, stmt, "key");

	/* We select from startkey onwards, so once we're past it, stop */
	if (startkey && !datastore_key_startswith(*key, startkey)) {
		db_col_ignore(stmt, "data");
		db_col_ignore(stmt, "generation");
		return tal_free(stmt);
	}

	if (data)
		*data = db_col_arr(ctx, stmt, "data", u8);
	else
		db_col_ignore(stmt, "data");

	if (generation)
		*generation = db_col_u64(stmt, "generation");
	else
		db_col_ignore(stmt, "generation");

	return stmt;
}

struct db_stmt *db_datastore_first(const tal_t *ctx,
				   struct db *db,
				   const char **startkey,
				   const char ***key,
				   const u8 **data,
				   u64 *generation)
{
	struct db_stmt *stmt;

	if (startkey) {
		stmt = db_prepare_v2(db,
				     SQL("SELECT key, data, generation"
					 " FROM datastore"
					 " WHERE key >= ?"
					 " ORDER BY key;"));
		db_bind_datastore_key(stmt, startkey);
	} else {
		stmt = db_prepare_v2(db,
				     SQL("SELECT key, data, generation"
					 " FROM datastore"
					 " ORDER BY key;"));
	}
	db_query_prepared(stmt);

	return db_datastore_next(ctx, stmt, startkey, key, data, generation);
}

void db_datastore_update(struct db *db, const char **key, const u8 *data)
{
	struct db_stmt *stmt;

	stmt = db_prepare_v2(db,
			     SQL("UPDATE datastore SET data=?, generation=generation+1 WHERE key=?;"));
	db_bind_talarr(stmt, data);
	db_bind_datastore_key(stmt, key);
	db_exec_prepared_v2(take(stmt));
}

