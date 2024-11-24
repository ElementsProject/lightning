#include "config.h"
#include <bitcoin/privkey.h>
#include <bitcoin/psbt.h>
#include <ccan/mem/mem.h>
#include <ccan/take/take.h>
#include <ccan/tal/str/str.h>
#include <ccan/tal/tal.h>
#include <common/channel_id.h>
#include <common/channel_type.h>
#include <common/htlc_state.h>
#include <common/node_id.h>
#include <common/onionreply.h>
#include <db/bindings.h>
#include <db/common.h>
#include <db/utils.h>

#define NSEC_IN_SEC 1000000000

static size_t check_bind_pos(struct db_stmt *stmt)
{
	size_t pos = ++stmt->bind_pos;
	assert(pos < tal_count(stmt->bindings));

	return pos;
}

/* Local helpers once you have column number */
static bool db_column_is_null(struct db_stmt *stmt, int col)
{
	return stmt->db->config->column_is_null_fn(stmt, col);
}

/* Returns true (and warns) if it's nul */
static bool db_column_null_warn(struct db_stmt *stmt, const char *colname,
				int col)
{
	if (!db_column_is_null(stmt, col))
		return false;

	db_warn(stmt->db, "Accessing a null column %s/%i in query %s",
		colname, col, stmt->query->query);

	return true;
}

void db_bind_int(struct db_stmt *stmt, int val)
{
	size_t pos = check_bind_pos(stmt);
	memcheck(&val, sizeof(val));
	stmt->bindings[pos].type = DB_BINDING_INT;
	stmt->bindings[pos].v.i = val;
}

int db_col_int(struct db_stmt *stmt, const char *colname)
{
	size_t col = db_query_colnum(stmt, colname);

	if (db_column_null_warn(stmt, colname, col))
		return 0;

	return stmt->db->config->column_int_fn(stmt, col);
}

int db_col_is_null(struct db_stmt *stmt, const char *colname)
{
	return db_column_is_null(stmt, db_query_colnum(stmt, colname));
}

void db_bind_null(struct db_stmt *stmt)
{
	size_t pos = check_bind_pos(stmt);
	stmt->bindings[pos].type = DB_BINDING_NULL;
}

void db_bind_u64(struct db_stmt *stmt, u64 val)
{
	size_t pos = check_bind_pos(stmt);

	memcheck(&val, sizeof(val));
	stmt->bindings[pos].type = DB_BINDING_UINT64;
	stmt->bindings[pos].v.u64 = val;
}

void db_bind_s64(struct db_stmt *stmt, s64 val)
{
	u64 uval = val;
	db_bind_u64(stmt, uval);
}

void db_bind_blob(struct db_stmt *stmt, const u8 *val, size_t len)
{
	size_t pos = check_bind_pos(stmt);
	stmt->bindings[pos].type = DB_BINDING_BLOB;
	stmt->bindings[pos].v.blob = memcheck(val, len);
	stmt->bindings[pos].len = len;
}

void db_bind_text(struct db_stmt *stmt, const char *val)
{
	size_t pos = check_bind_pos(stmt);
	stmt->bindings[pos].type = DB_BINDING_TEXT;
	stmt->bindings[pos].v.text = val;
	stmt->bindings[pos].len = strlen(val);
}

void db_bind_preimage(struct db_stmt *stmt, const struct preimage *p)
{
	db_bind_blob(stmt, p->r, sizeof(struct preimage));
}

void db_bind_sha256(struct db_stmt *stmt, const struct sha256 *s)
{
	db_bind_blob(stmt, s->u.u8, sizeof(struct sha256));
}

void db_bind_sha256d(struct db_stmt *stmt, const struct sha256_double *s)
{
	db_bind_sha256(stmt, &s->sha);
}

void db_bind_secret(struct db_stmt *stmt, const struct secret *s)
{
	assert(sizeof(s->data) == 32);
	db_bind_blob(stmt, s->data, sizeof(s->data));
}

void db_bind_secret_arr(struct db_stmt *stmt, const struct secret *s)
{
	size_t num = tal_count(s), elsize = sizeof(s->data);
	u8 *ser = tal_arr(stmt, u8, num * elsize);

	for (size_t i = 0; i < num; ++i)
		memcpy(ser + i * elsize, &s[i], elsize);

	db_bind_blob(stmt, ser, tal_count(ser));
}

void db_bind_txid(struct db_stmt *stmt, const struct bitcoin_txid *t)
{
	db_bind_sha256d(stmt, &t->shad);
}

void db_bind_channel_id(struct db_stmt *stmt, const struct channel_id *id)
{
	db_bind_blob(stmt, id->id, sizeof(id->id));
}

void db_bind_channel_type(struct db_stmt *stmt, const struct channel_type *type)
{
	db_bind_talarr(stmt, type->features);
}

void db_bind_node_id(struct db_stmt *stmt, const struct node_id *id)
{
	db_bind_blob(stmt, id->k, sizeof(id->k));
}

void db_bind_node_id_arr(struct db_stmt *stmt,
			 const struct node_id *ids)
{
	/* Copy into contiguous array: ARM will add padding to struct node_id! */
	size_t n = tal_count(ids);
	u8 *arr = tal_arr(stmt, u8, n * sizeof(ids[0].k));

	for (size_t i = 0; i < n; ++i) {
		assert(node_id_valid(&ids[i]));
		memcpy(arr + sizeof(ids[i].k) * i,
		       ids[i].k,
		       sizeof(ids[i].k));
	}
	db_bind_blob(stmt, arr, tal_count(arr));
}

void db_bind_pubkey(struct db_stmt *stmt, const struct pubkey *pk)
{
	u8 *der = tal_arr(stmt, u8, PUBKEY_CMPR_LEN);
	pubkey_to_der(der, pk);
	db_bind_blob(stmt, der, PUBKEY_CMPR_LEN);
}

void db_bind_short_channel_id(struct db_stmt *stmt, struct short_channel_id scid)
{
	db_bind_u64(stmt, scid.u64);
}

void db_bind_short_channel_id_arr(struct db_stmt *stmt,
				  const struct short_channel_id *id)
{
	u8 *ser = tal_arr(stmt, u8, 0);
	size_t num = tal_count(id);

	for (size_t i = 0; i < num; ++i)
		towire_short_channel_id(&ser, id[i]);

	db_bind_talarr(stmt, ser);
}

void db_bind_signature(struct db_stmt *stmt,
		       const secp256k1_ecdsa_signature *sig)
{
	u8 *buf = tal_arr(stmt, u8, 64);
	int ret = secp256k1_ecdsa_signature_serialize_compact(secp256k1_ctx,
							      buf, sig);
	assert(ret == 1);
	db_bind_blob(stmt, buf, 64);
}

void db_bind_timeabs(struct db_stmt *stmt, struct timeabs t)
{
	u64 timestamp =  t.ts.tv_nsec + (((u64) t.ts.tv_sec) * ((u64) NSEC_IN_SEC));
	db_bind_u64(stmt, timestamp);
}

void db_bind_tx(struct db_stmt *stmt, const struct wally_tx *tx)
{
	u8 *ser = linearize_wtx(stmt, tx);
	assert(ser);
	db_bind_talarr(stmt, ser);
}

void db_bind_psbt(struct db_stmt *stmt, const struct wally_psbt *psbt)
{
	size_t bytes_written;
	const u8 *ser = psbt_get_bytes(stmt, psbt, &bytes_written);
	assert(ser);
	db_bind_blob(stmt, ser, bytes_written);
}

void db_bind_amount_msat(struct db_stmt *stmt,
			 const struct amount_msat *msat)
{
	db_bind_u64(stmt, msat->millisatoshis); /* Raw: low level function */
}

void db_bind_amount_sat(struct db_stmt *stmt,
			 const struct amount_sat *sat)
{
	db_bind_u64(stmt, sat->satoshis); /* Raw: low level function */
}

void db_bind_json_escape(struct db_stmt *stmt,
			 const struct json_escape *esc)
{
	db_bind_text(stmt, esc->s);
}

void db_bind_onionreply(struct db_stmt *stmt, const struct onionreply *r)
{
	db_bind_talarr(stmt, r->contents);
}

void db_bind_talarr(struct db_stmt *stmt, const u8 *arr)
{
	if (!arr)
		db_bind_null(stmt);
	else
		db_bind_blob(stmt, arr, tal_bytelen(arr));
}

static size_t db_column_bytes(struct db_stmt *stmt, int col)
{
	if (db_column_is_null(stmt, col))
		return 0;
	return stmt->db->config->column_bytes_fn(stmt, col);
}

static const void *db_column_blob(struct db_stmt *stmt, int col)
{
	if (db_column_is_null(stmt, col))
		return NULL;
	return stmt->db->config->column_blob_fn(stmt, col);
}


u64 db_col_u64(struct db_stmt *stmt, const char *colname)
{
	size_t col = db_query_colnum(stmt, colname);

	if (db_column_null_warn(stmt, colname, col))
		return 0;

	return stmt->db->config->column_u64_fn(stmt, col);
}

u64 db_col_s64(struct db_stmt *stmt, const char *colname)
{
	return db_col_u64(stmt, colname);
}

int db_col_int_or_default(struct db_stmt *stmt, const char *colname, int def)
{
	size_t col = db_query_colnum(stmt, colname);

	if (db_column_is_null(stmt, col))
		return def;
	else
		return stmt->db->config->column_int_fn(stmt, col);
}

size_t db_col_bytes(struct db_stmt *stmt, const char *colname)
{
	size_t col = db_query_colnum(stmt, colname);

	if (db_column_null_warn(stmt, colname, col))
		return 0;

	return stmt->db->config->column_bytes_fn(stmt, col);
}

const void *db_col_blob(struct db_stmt *stmt, const char *colname)
{
	size_t col = db_query_colnum(stmt, colname);

	if (db_column_null_warn(stmt, colname, col))
		return NULL;

	return stmt->db->config->column_blob_fn(stmt, col);
}

char *db_col_strdup(const tal_t *ctx,
		    struct db_stmt *stmt,
		    const char *colname)
{
	size_t col = db_query_colnum(stmt, colname);

	if (db_column_null_warn(stmt, colname, col))
		return NULL;

	return tal_strdup(ctx, (char *)stmt->db->config->column_text_fn(stmt, col));
}

char *db_col_strdup_optional(const tal_t *ctx,
			     struct db_stmt *stmt,
			     const char *colname)
{
	size_t col = db_query_colnum(stmt, colname);
	if (db_column_is_null(stmt, col))
		return NULL;

	return tal_strdup(ctx, (char *)stmt->db->config->column_text_fn(stmt, col));
}

void db_col_preimage(struct db_stmt *stmt, const char *colname,
			struct preimage *preimage)
{
	size_t col = db_query_colnum(stmt, colname);
	const u8 *raw;
	size_t size = sizeof(struct preimage);
	assert(db_column_bytes(stmt, col) == size);
	raw = db_column_blob(stmt, col);
	memcpy(preimage, raw, size);
}

void db_col_channel_id(struct db_stmt *stmt, const char *colname, struct channel_id *dest)
{
	size_t col = db_query_colnum(stmt, colname);

	assert(db_column_bytes(stmt, col) == sizeof(dest->id));
	memcpy(dest->id, db_column_blob(stmt, col), sizeof(dest->id));
}

void db_col_node_id(struct db_stmt *stmt, const char *colname, struct node_id *dest)
{
	size_t col = db_query_colnum(stmt, colname);

	assert(db_column_bytes(stmt, col) == sizeof(dest->k));
	memcpy(dest->k, db_column_blob(stmt, col), sizeof(dest->k));
}

/* We don't assume sizeof(struct node_id) == sizeof(struct node_id.k),
 * otherwise this would simply be a call to db_col_arr!
 * Thanks ARM! */
struct node_id *db_col_node_id_arr(const tal_t *ctx, struct db_stmt *stmt,
				   const char *colname)
{
	size_t col = db_query_colnum(stmt, colname);
	struct node_id *ret;
	size_t n = db_column_bytes(stmt, col) / sizeof(ret->k);
	const u8 *arr = db_column_blob(stmt, col);
	assert(n * sizeof(ret->k) == (size_t)db_column_bytes(stmt, col));

	if (db_column_is_null(stmt, col))
		return NULL;

	ret = tal_arr(ctx, struct node_id, n);
	for (size_t i = 0; i < n; i++)
		memcpy(ret[i].k, arr + i * sizeof(ret[i].k), sizeof(ret[i].k));

	return ret;
}

void db_col_pubkey(struct db_stmt *stmt,
		   const char *colname,
		   struct pubkey *dest)
{
	size_t col = db_query_colnum(stmt, colname);
	bool ok;
	assert(db_column_bytes(stmt, col) == PUBKEY_CMPR_LEN);
	ok = pubkey_from_der(db_column_blob(stmt, col), PUBKEY_CMPR_LEN, dest);
	assert(ok);
}

struct short_channel_id db_col_short_channel_id(struct db_stmt *stmt, const char *colname)
{
	struct short_channel_id scid;
	scid.u64 = db_col_u64(stmt, colname);
	return scid;
}

void *db_col_optional_(tal_t *dst,
		       struct db_stmt *stmt, const char *colname,
		       void (*colfn)(struct db_stmt *, const char *, void *))
{
	if (db_col_is_null(stmt, colname))
		return tal_free(dst);

	colfn(stmt, colname, dst);
	return dst;
}

struct short_channel_id *
db_col_short_channel_id_arr(const tal_t *ctx, struct db_stmt *stmt, const char *colname)
{
	size_t col = db_query_colnum(stmt, colname);
	const u8 *ser;
	size_t len;
	struct short_channel_id *ret;

	if (db_column_is_null(stmt, col))
		return NULL;

	ser = db_column_blob(stmt, col);
	len = db_column_bytes(stmt, col);
	ret = tal_arr(ctx, struct short_channel_id, 0);

	while (len != 0) {
		struct short_channel_id scid;
		scid = fromwire_short_channel_id(&ser, &len);
		tal_arr_expand(&ret, scid);
	}

	return ret;
}

bool db_col_signature(struct db_stmt *stmt, const char *colname,
			 secp256k1_ecdsa_signature *sig)
{
	size_t col = db_query_colnum(stmt, colname);
	assert(db_column_bytes(stmt, col) == 64);
	return secp256k1_ecdsa_signature_parse_compact(
		   secp256k1_ctx, sig, db_column_blob(stmt, col)) == 1;
}

struct timeabs db_col_timeabs(struct db_stmt *stmt, const char *colname)
{
	struct timeabs t;
	u64 timestamp = db_col_u64(stmt, colname);
	t.ts.tv_sec = timestamp / NSEC_IN_SEC;
	t.ts.tv_nsec = timestamp % NSEC_IN_SEC;
	return t;

}

struct bitcoin_tx *db_col_tx(const tal_t *ctx, struct db_stmt *stmt, const char *colname)
{
	size_t col = db_query_colnum(stmt, colname);
	const u8 *src = db_column_blob(stmt, col);
	size_t len = db_column_bytes(stmt, col);
	struct bitcoin_tx *tx;
	bool is_null;

	is_null = db_column_null_warn(stmt, colname, col);
	tx = pull_bitcoin_tx(ctx, &src, &len);

	if (is_null || tx) return tx;

	/* Column wasn't null, but we couldn't retrieve a valid wally_tx! */
	u8 *tx_dup = tal_dup_arr(stmt, u8, src, len, 0);

	db_fatal(stmt->db,
		 "db_col_tx: Invalid bitcoin transaction bytes retrieved: %s",
		 tal_hex(stmt, tx_dup));
	return NULL;
}

struct wally_psbt *db_col_psbt(const tal_t *ctx, struct db_stmt *stmt, const char *colname)
{
	struct wally_psbt *psbt;
	size_t col = db_query_colnum(stmt, colname);
	const u8 *src = db_column_blob(stmt, col);
	size_t len = db_column_bytes(stmt, col);

	db_column_null_warn(stmt, colname, col);
	psbt = psbt_from_bytes(ctx, src, len);
	psbt_set_version(psbt, 2);
	return psbt;
}

struct bitcoin_tx *db_col_psbt_to_tx(const tal_t *ctx, struct db_stmt *stmt, const char *colname)
{
	struct wally_psbt *psbt = db_col_psbt(ctx, stmt, colname);
	if (!psbt)
		return NULL;
	return bitcoin_tx_with_psbt(ctx, psbt);
}

struct channel_type *db_col_channel_type(const tal_t *ctx, struct db_stmt *stmt,
					 const char *colname)
{
	return channel_type_from(ctx, take(db_col_arr(NULL, stmt, colname, u8)));
}

void *db_col_arr_(const tal_t *ctx, struct db_stmt *stmt, const char *colname,
		  size_t bytes, const char *label, const char *caller)
{
	size_t col = db_query_colnum(stmt, colname);
	size_t sourcelen;
	void *p;

	if (db_column_is_null(stmt, col))
		return NULL;

	sourcelen = db_column_bytes(stmt, col);

	if (sourcelen % bytes != 0)
		db_fatal(stmt->db, "%s: %s/%zu column size for %zu not a multiple of %s (%zu)",
			 caller, colname, col, sourcelen, label, bytes);

	p = tal_arr_label(ctx, char, sourcelen, label);
	if (sourcelen != 0)
		memcpy(p, db_column_blob(stmt, col), sourcelen);
	return p;
}

void db_col_amount_msat_or_default(struct db_stmt *stmt,
				   const char *colname,
				   struct amount_msat *msat,
				   struct amount_msat def)
{
	size_t col = db_query_colnum(stmt, colname);

	if (db_column_is_null(stmt, col))
		*msat = def;
	else
		msat->millisatoshis = db_col_u64(stmt, colname); /* Raw: low level function */
}

struct amount_msat db_col_amount_msat(struct db_stmt *stmt, const char *colname)
{
	return amount_msat(db_col_u64(stmt, colname));
}

struct amount_sat db_col_amount_sat(struct db_stmt *stmt, const char *colname)
{
	return amount_sat(db_col_u64(stmt, colname));
}

struct json_escape *db_col_json_escape(const tal_t *ctx,
				       struct db_stmt *stmt, const char *colname)
{
	size_t col = db_query_colnum(stmt, colname);

	return json_escape_string_(ctx, db_column_blob(stmt, col),
				   db_column_bytes(stmt, col));
}

void db_col_sha256(struct db_stmt *stmt, const char *colname, struct sha256 *sha)
{
	size_t col = db_query_colnum(stmt, colname);
	const u8 *raw;
	size_t size = sizeof(struct sha256);
	assert(db_column_bytes(stmt, col) == size);
	raw = db_column_blob(stmt, col);
	memcpy(sha, raw, size);
}

void db_col_sha256d(struct db_stmt *stmt, const char *colname,
		       struct sha256_double *shad)
{
	size_t col = db_query_colnum(stmt, colname);
	const u8 *raw;
	size_t size = sizeof(struct sha256_double);
	assert(db_column_bytes(stmt, col) == size);
	raw = db_column_blob(stmt, col);
	memcpy(shad, raw, size);
}

void db_col_secret(struct db_stmt *stmt, const char *colname, struct secret *s)
{
	size_t col = db_query_colnum(stmt, colname);
	const u8 *raw;
	assert(db_column_bytes(stmt, col) == sizeof(struct secret));
	raw = db_column_blob(stmt, col);
	memcpy(s, raw, sizeof(struct secret));
}

struct secret *db_col_secret_arr(const tal_t *ctx,
				 struct db_stmt *stmt,
				 const char *colname)
{
	return db_col_arr(ctx, stmt, colname, struct secret);
}

struct wireaddr *db_col_wireaddr(const tal_t *ctx,
				 struct db_stmt *stmt,
				 const char *colname)
{
	struct wireaddr *waddr = tal(ctx, struct wireaddr);
	const u8 *wire = db_col_arr(tmpctx, stmt, colname, u8);
	size_t len = tal_bytelen(wire);
	if (!fromwire_wireaddr(&wire, &len, waddr))
		return tal_free(waddr);
	return waddr;
}

void db_col_txid(struct db_stmt *stmt, const char *colname, struct bitcoin_txid *t)
{
	db_col_sha256d(stmt, colname, &t->shad);
}

struct onionreply *db_col_onionreply(const tal_t *ctx,
					struct db_stmt *stmt, const char *colname)
{
	struct onionreply *r = tal(ctx, struct onionreply);
	r->contents = db_col_arr(ctx, stmt, colname, u8);
	return r;
}

void db_col_ignore(struct db_stmt *stmt, const char *colname)
{
	if (stmt->db->developer)
		db_query_colnum(stmt, colname);
}
