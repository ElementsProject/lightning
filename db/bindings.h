#ifndef LIGHTNING_DB_BINDINGS_H
#define LIGHTNING_DB_BINDINGS_H
#include "config.h"

#include <bitcoin/preimage.h>
#include <bitcoin/pubkey.h>
#include <bitcoin/short_channel_id.h>
#include <bitcoin/tx.h>
#include <ccan/json_escape/json_escape.h>
#include <ccan/time/time.h>

struct channel_id;
struct channel_type;
struct db_stmt;
struct node_id;
struct onionreply;
struct wally_psbt;
struct wally_tx;

/* These bind the next `?` in stmt (they keep an internal counter). */
void db_bind_null(struct db_stmt *stmt);
void db_bind_int(struct db_stmt *stmt, int val);
void db_bind_u64(struct db_stmt *stmt, u64 val);
void db_bind_s64(struct db_stmt *stmt, s64 val);
void db_bind_blob(struct db_stmt *stmt, const u8 *val, size_t len);
void db_bind_text(struct db_stmt *stmt, const char *val);
void db_bind_preimage(struct db_stmt *stmt, const struct preimage *p);
void db_bind_sha256(struct db_stmt *stmt, const struct sha256 *s);
void db_bind_sha256d(struct db_stmt *stmt, const struct sha256_double *s);
void db_bind_secret(struct db_stmt *stmt, const struct secret *s);
void db_bind_secret_arr(struct db_stmt *stmt, const struct secret *s);
void db_bind_txid(struct db_stmt *stmt, const struct bitcoin_txid *t);
void db_bind_channel_id(struct db_stmt *stmt, const struct channel_id *id);
void db_bind_channel_type(struct db_stmt *stmt, const struct channel_type *type);
void db_bind_node_id(struct db_stmt *stmt, const struct node_id *ni);
void db_bind_node_id_arr(struct db_stmt *stmt,
			 const struct node_id *ids);
void db_bind_pubkey(struct db_stmt *stmt, const struct pubkey *p);
void db_bind_short_channel_id(struct db_stmt *stmt,
			      struct short_channel_id scid);
void db_bind_short_channel_id_arr(struct db_stmt *stmt,
				  const struct short_channel_id *id);
void db_bind_signature(struct db_stmt *stmt,
		       const secp256k1_ecdsa_signature *sig);
void db_bind_timeabs(struct db_stmt *stmt, struct timeabs t);
void db_bind_tx(struct db_stmt *stmt, const struct wally_tx *tx);
void db_bind_psbt(struct db_stmt *stmt, const struct wally_psbt *psbt);
void db_bind_amount_msat(struct db_stmt *stmt,
			 const struct amount_msat *msat);
void db_bind_amount_sat(struct db_stmt *stmt,
			const struct amount_sat *sat);
void db_bind_json_escape(struct db_stmt *stmt,
			 const struct json_escape *esc);
void db_bind_onionreply(struct db_stmt *stmt,
			const struct onionreply *r);
void db_bind_talarr(struct db_stmt *stmt, const u8 *arr);

/* Modern variants: get columns by name from SELECT */
/* Bridge function to get column number from SELECT
   (must exist) */
size_t db_query_colnum(const struct db_stmt *stmt, const char *colname);

int db_col_is_null(struct db_stmt *stmt, const char *colname);
int db_col_int(struct db_stmt *stmt, const char *colname);
u64 db_col_u64(struct db_stmt *stmt, const char *colname);
u64 db_col_s64(struct db_stmt *stmt, const char *colname);
size_t db_col_bytes(struct db_stmt *stmt, const char *colname);
const void* db_col_blob(struct db_stmt *stmt, const char *colname);
char *db_col_strdup(const tal_t *ctx,
		    struct db_stmt *stmt,
		    const char *colname);
/* string or NULL */
char *db_col_strdup_optional(const tal_t *ctx,
			     struct db_stmt *stmt,
			     const char *colname);
void db_col_preimage(struct db_stmt *stmt, const char *colname, struct preimage *preimage);
struct amount_msat db_col_amount_msat(struct db_stmt *stmt, const char *colname);
struct amount_sat db_col_amount_sat(struct db_stmt *stmt, const char *colname);
struct json_escape *db_col_json_escape(const tal_t *ctx, struct db_stmt *stmt, const char *colname);
void db_col_sha256(struct db_stmt *stmt, const char *colname, struct sha256 *sha);
void db_col_sha256d(struct db_stmt *stmt, const char *colname, struct sha256_double *shad);
void db_col_secret(struct db_stmt *stmt, const char *colname, struct secret *s);
struct secret *db_col_secret_arr(const tal_t *ctx, struct db_stmt *stmt,
				 const char *colname);
void db_col_txid(struct db_stmt *stmt, const char *colname, struct bitcoin_txid *t);
void db_col_channel_id(struct db_stmt *stmt, const char *colname, struct channel_id *dest);
struct channel_type *db_col_channel_type(const tal_t *ctx, struct db_stmt *stmt,
					 const char *colname);
void db_col_node_id(struct db_stmt *stmt, const char *colname, struct node_id *ni);
struct node_id *db_col_node_id_arr(const tal_t *ctx, struct db_stmt *stmt,
				   const char *colname);
void db_col_pubkey(struct db_stmt *stmt, const char *colname,
		   struct pubkey *p);
struct short_channel_id db_col_short_channel_id(struct db_stmt *stmt, const char *colname);
struct short_channel_id *
db_col_short_channel_id_arr(const tal_t *ctx, struct db_stmt *stmt, const char *colname);
bool db_col_signature(struct db_stmt *stmt, const char *colname,
			 secp256k1_ecdsa_signature *sig);
struct timeabs db_col_timeabs(struct db_stmt *stmt, const char *colname);
struct bitcoin_tx *db_col_tx(const tal_t *ctx, struct db_stmt *stmt, const char *colname);
struct wally_psbt *db_col_psbt(const tal_t *ctx, struct db_stmt *stmt, const char *colname);
struct bitcoin_tx *db_col_psbt_to_tx(const tal_t *ctx, struct db_stmt *stmt, const char *colname);

struct onionreply *db_col_onionreply(const tal_t *ctx,
					struct db_stmt *stmt, const char *colname);

#define db_col_arr(ctx, stmt, colname, type)			\
	((type *)db_col_arr_((ctx), (stmt), (colname),		\
				sizeof(type), TAL_LABEL(type, "[]"),	\
				__func__))
void *db_col_arr_(const tal_t *ctx, struct db_stmt *stmt, const char *colname,
		     size_t bytes, const char *label, const char *caller);


/* Assumes void db_col_@type(stmt, colname, addr), and struct @type! */
#define db_col_optional(ctx, stmt, colname, type)			\
	((struct type *)db_col_optional_(tal(ctx, struct type),		\
					 (stmt), (colname),		\
					 typesafe_cb_cast(void (*)(struct db_stmt *, const char *, void *), \
							  void (*)(struct db_stmt *, const char *, struct type *), \
							  db_col_##type)))

void *WARN_UNUSED_RESULT db_col_optional_(tal_t *dst,
					  struct db_stmt *stmt,
					  const char *colname,
					  void (*colfn)(struct db_stmt *,
							const char *, void *));

/* Some useful default variants */
int db_col_int_or_default(struct db_stmt *stmt, const char *colname, int def);
void db_col_amount_msat_or_default(struct db_stmt *stmt, const char *colname,
				      struct amount_msat *msat,
				      struct amount_msat def);


/* Explicitly ignore a column (so we don't complain you didn't use it!) */
void db_col_ignore(struct db_stmt *stmt, const char *colname);

#endif /* LIGHTNING_DB_BINDINGS_H */
