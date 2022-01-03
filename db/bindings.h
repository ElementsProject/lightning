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
struct db_stmt;
struct node_id;
struct onionreply;
struct wally_psbt;
struct wally_tx;

int db_col_is_null(struct db_stmt *stmt, const char *colname);

void db_bind_int(struct db_stmt *stmt, int pos, int val);
int db_col_int(struct db_stmt *stmt, const char *colname);

void db_bind_null(struct db_stmt *stmt, int pos);
void db_bind_int(struct db_stmt *stmt, int pos, int val);
void db_bind_u64(struct db_stmt *stmt, int pos, u64 val);
void db_bind_blob(struct db_stmt *stmt, int pos, const u8 *val, size_t len);
void db_bind_text(struct db_stmt *stmt, int pos, const char *val);
void db_bind_preimage(struct db_stmt *stmt, int pos, const struct preimage *p);
void db_bind_sha256(struct db_stmt *stmt, int pos, const struct sha256 *s);
void db_bind_sha256d(struct db_stmt *stmt, int pos, const struct sha256_double *s);
void db_bind_secret(struct db_stmt *stmt, int pos, const struct secret *s);
void db_bind_secret_arr(struct db_stmt *stmt, int col, const struct secret *s);
void db_bind_txid(struct db_stmt *stmt, int pos, const struct bitcoin_txid *t);
void db_bind_channel_id(struct db_stmt *stmt, int pos, const struct channel_id *id);
void db_bind_node_id(struct db_stmt *stmt, int pos, const struct node_id *ni);
void db_bind_node_id_arr(struct db_stmt *stmt, int col,
			 const struct node_id *ids);
void db_bind_pubkey(struct db_stmt *stmt, int pos, const struct pubkey *p);
void db_bind_short_channel_id(struct db_stmt *stmt, int col,
			      const struct short_channel_id *id);
void db_bind_short_channel_id_arr(struct db_stmt *stmt, int col,
				  const struct short_channel_id *id);
void db_bind_signature(struct db_stmt *stmt, int col,
		       const secp256k1_ecdsa_signature *sig);
void db_bind_timeabs(struct db_stmt *stmt, int col, struct timeabs t);
void db_bind_tx(struct db_stmt *stmt, int col, const struct wally_tx *tx);
void db_bind_psbt(struct db_stmt *stmt, int col, const struct wally_psbt *psbt);
void db_bind_amount_msat(struct db_stmt *stmt, int pos,
			 const struct amount_msat *msat);
void db_bind_amount_sat(struct db_stmt *stmt, int pos,
			const struct amount_sat *sat);
void db_bind_json_escape(struct db_stmt *stmt, int pos,
			 const struct json_escape *esc);
void db_bind_onionreply(struct db_stmt *stmt, int col,
			const struct onionreply *r);
void db_bind_talarr(struct db_stmt *stmt, int col, const u8 *arr);

/* Modern variants: get columns by name from SELECT */
/* Bridge function to get column number from SELECT
   (must exist) */
size_t db_query_colnum(const struct db_stmt *stmt, const char *colname);

u64 db_col_u64(struct db_stmt *stmt, const char *colname);
size_t db_col_bytes(struct db_stmt *stmt, const char *colname);
const void* db_col_blob(struct db_stmt *stmt, const char *colname);
char *db_col_strdup(const tal_t *ctx,
		    struct db_stmt *stmt,
		    const char *colname);
void db_col_preimage(struct db_stmt *stmt, const char *colname, struct preimage *preimage);
void db_col_amount_msat(struct db_stmt *stmt, const char *colname, struct amount_msat *msat);
void db_col_amount_sat(struct db_stmt *stmt, const char *colname, struct amount_sat *sat);
struct json_escape *db_col_json_escape(const tal_t *ctx, struct db_stmt *stmt, const char *colname);
void db_col_sha256(struct db_stmt *stmt, const char *colname, struct sha256 *sha);
void db_col_sha256d(struct db_stmt *stmt, const char *colname, struct sha256_double *shad);
void db_col_secret(struct db_stmt *stmt, const char *colname, struct secret *s);
struct secret *db_col_secret_arr(const tal_t *ctx, struct db_stmt *stmt,
				 const char *colname);
void db_col_txid(struct db_stmt *stmt, const char *colname, struct bitcoin_txid *t);
void db_col_channel_id(struct db_stmt *stmt, const char *colname, struct channel_id *dest);
void db_col_node_id(struct db_stmt *stmt, const char *colname, struct node_id *ni);
struct node_id *db_col_node_id_arr(const tal_t *ctx, struct db_stmt *stmt,
				   const char *colname);
void db_col_pubkey(struct db_stmt *stmt, const char *colname,
		   struct pubkey *p);
bool db_col_short_channel_id_str(struct db_stmt *stmt, const char *colname,
				struct short_channel_id *dest);
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


/* Some useful default variants */
int db_col_int_or_default(struct db_stmt *stmt, const char *colname, int def);
void db_col_amount_msat_or_default(struct db_stmt *stmt, const char *colname,
				      struct amount_msat *msat,
				      struct amount_msat def);


/* Explicitly ignore a column (so we don't complain you didn't use it!) */
void db_col_ignore(struct db_stmt *stmt, const char *colname);

#endif /* LIGHTNING_DB_BINDINGS_H */
