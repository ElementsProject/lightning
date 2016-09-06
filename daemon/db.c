#include "bitcoin/pullpush.h"
#include "commit_tx.h"
#include "db.h"
#include "feechange.h"
#include "htlc.h"
#include "invoice.h"
#include "lightningd.h"
#include "log.h"
#include "names.h"
#include "netaddr.h"
#include "pay.h"
#include "routing.h"
#include "secrets.h"
#include "utils.h"
#include "wallet.h"
#include <ccan/array_size/array_size.h>
#include <ccan/cast/cast.h>
#include <ccan/cppmagic/cppmagic.h>
#include <ccan/mem/mem.h>
#include <ccan/str/hex/hex.h>
#include <ccan/tal/str/str.h>
#include <inttypes.h>
#include <sqlite3.h>
#include <stdarg.h>
#include <unistd.h>

#define DB_FILE "lightning.sqlite3"

/* They don't use stdint types. */
#define PRIuSQLITE64 "llu"

struct db {
	bool in_transaction;
	const char *err;
	sqlite3 *sql;
};

static void close_db(struct db *db)
{
	sqlite3_close(db->sql);
}

/* We want a string, not an 'unsigned char *' thanks! */
static const char *sqlite3_column_str(sqlite3_stmt *stmt, int iCol)
{
	return cast_signed(const char *, sqlite3_column_text(stmt, iCol));
}

#define SQL_U64(var)		stringify(var)" BIGINT" /* Actually, an s64 */
#define SQL_U32(var)		stringify(var)" INT"
#define SQL_BOOL(var)		stringify(var)" BOOLEAN"
#define SQL_BLOB(var)		stringify(var)" BLOB"

#define SQL_PUBKEY(var)		stringify(var)" CHAR(33)"
#define SQL_PRIVKEY(var)	stringify(var)" CHAR(32)"
#define SQL_SIGNATURE(var)	stringify(var)" CHAR(64)"
#define SQL_TXID(var)		stringify(var)" CHAR(32)"
#define SQL_RHASH(var)		stringify(var)" CHAR(32)"
#define SQL_SHA256(var)		stringify(var)" CHAR(32)"
#define SQL_R(var)		stringify(var)" CHAR(32)"
/* STATE_OPEN_WAITING_THEIRANCHOR_THEYCOMPLETED == 44*/
#define SQL_STATENAME(var)	stringify(var)" VARCHAR(44)"
#define SQL_INVLABEL(var)	stringify(var)" VARCHAR("stringify(INVOICE_MAX_LABEL_LEN)")"

/* 8 + 4 + (8 + 32) * (64 + 1) */
#define SHACHAIN_SIZE	2612
#define SQL_SHACHAIN(var)	stringify(var)" CHAR("stringify(SHACHAIN_SIZE)")"

/* FIXME: Should be fixed size. */
#define SQL_ROUTING(var)	stringify(var)" BLOB"
#define SQL_FAIL(var)		stringify(var)" BLOB"

#define TABLE(tablename, ...)					\
	"CREATE TABLE " #tablename " (" CPPMAGIC_JOIN(", ", __VA_ARGS__) ");"

static const char *sql_bool(bool b)
{
	/* SQL2003 says TRUE and FALSE are binary literal keywords.
	 * sqlite3 barfs. */
	return (b) ? "1" : "0";
}

static bool PRINTF_FMT(3,4)
	db_exec(const char *caller,
		struct lightningd_state *dstate, const char *fmt, ...)
{
	va_list ap;
	char *cmd, *errmsg;
	int err;

	if (dstate->db->in_transaction && dstate->db->err)
		return false;

	va_start(ap, fmt);
	cmd = tal_vfmt(dstate->db, fmt, ap);
	va_end(ap);

	err = sqlite3_exec(dstate->db->sql, cmd, NULL, NULL, &errmsg);
	if (err != SQLITE_OK) {
		tal_free(dstate->db->err);
		dstate->db->err = tal_fmt(dstate->db, "%s:%s:%s:%s",
					  caller, sqlite3_errstr(err),
					  cmd, errmsg);
		sqlite3_free(errmsg);
		tal_free(cmd);
		log_broken(dstate->base_log, "%s", dstate->db->err);
		return false;
	}
	tal_free(cmd);
	return true;
}

static char *sql_hex_or_null(const tal_t *ctx, const void *buf, size_t len)
{
	char *r;

	if (!buf)
		return "NULL";
	r = tal_arr(ctx, char, 3 + hex_str_size(len));
	r[0] = 'x';
	r[1] = '\'';
	hex_encode(buf, len, r+2, hex_str_size(len));
	r[2+hex_str_size(len)-1] = '\'';
	r[2+hex_str_size(len)] = '\0';
	return r;
}

static void from_sql_blob(sqlite3_stmt *stmt, int idx, void *p, size_t n)
{
	if (sqlite3_column_bytes(stmt, idx) != n)
		fatal("db:wrong bytes %i not %zu",
		      sqlite3_column_bytes(stmt, idx), n);
	memcpy(p, sqlite3_column_blob(stmt, idx), n);
}

static u8 *tal_sql_blob(const tal_t *ctx, sqlite3_stmt *stmt, int idx)
{
	u8 *p;

	if (sqlite3_column_type(stmt, idx) == SQLITE_NULL)
		return NULL;

	p = tal_arr(ctx, u8, sqlite3_column_bytes(stmt, idx));
	from_sql_blob(stmt, idx, p, tal_count(p));
	return p;
}

static void pubkey_from_sql(secp256k1_context *secpctx,
			    sqlite3_stmt *stmt, int idx, struct pubkey *pk)
{
	if (!pubkey_from_der(secpctx, sqlite3_column_blob(stmt, idx),
			     sqlite3_column_bytes(stmt, idx), pk))
		fatal("db:bad pubkey length %i",
		      sqlite3_column_bytes(stmt, idx));
}

static void sha256_from_sql(sqlite3_stmt *stmt, int idx, struct sha256 *sha)
{
	from_sql_blob(stmt, idx, sha, sizeof(*sha));
}

static void sig_from_sql(secp256k1_context *secpctx,
			 sqlite3_stmt *stmt, int idx,
			 struct bitcoin_signature *sig)
{
	u8 compact[64];

	from_sql_blob(stmt, idx, compact, sizeof(compact));
	if (secp256k1_ecdsa_signature_parse_compact(secpctx, &sig->sig.sig,
						    compact) != 1)
		fatal("db:bad signature blob");
	sig->stype = SIGHASH_ALL;
}

static char *sig_to_sql(const tal_t *ctx,
			secp256k1_context *secpctx,
			const struct bitcoin_signature *sig)
{
	u8 compact[64];

	if (!sig)
		return sql_hex_or_null(ctx, NULL, 0);

	assert(sig->stype == SIGHASH_ALL);
	secp256k1_ecdsa_signature_serialize_compact(secpctx, compact,
						    &sig->sig.sig);
	return sql_hex_or_null(ctx, compact, sizeof(compact));
}

static void db_load_wallet(struct lightningd_state *dstate)
{
	int err;
	sqlite3_stmt *stmt;

	err = sqlite3_prepare_v2(dstate->db->sql, "SELECT * FROM wallet;", -1,
				 &stmt, NULL);

	if (err != SQLITE_OK)
		fatal("db_load_wallet:prepare gave %s:%s",
		      sqlite3_errstr(err), sqlite3_errmsg(dstate->db->sql));

	while ((err = sqlite3_step(stmt)) != SQLITE_DONE) {
		struct privkey privkey;
		if (err != SQLITE_ROW)
			fatal("db_load_wallet:step gave %s:%s",
			      sqlite3_errstr(err),
			      sqlite3_errmsg(dstate->db->sql));
		if (sqlite3_column_count(stmt) != 1)
			fatal("db_load_wallet:step gave %i cols, not 1",
			      sqlite3_column_count(stmt));
		from_sql_blob(stmt, 0, &privkey, sizeof(privkey));
		if (!restore_wallet_address(dstate, &privkey))
			fatal("db_load_wallet:bad privkey");
	}
	err = sqlite3_finalize(stmt);
	if (err != SQLITE_OK)
		fatal("db_load_wallet:finalize gave %s:%s",
		      sqlite3_errstr(err),
		      sqlite3_errmsg(dstate->db->sql));
}

void db_add_wallet_privkey(struct lightningd_state *dstate,
			   const struct privkey *privkey)
{
	char *ctx = tal(dstate, char);

	log_debug(dstate->base_log, "%s", __func__);
	if (!db_exec(__func__, dstate,
		      "INSERT INTO wallet VALUES (x'%s');",
		     tal_hexstr(ctx, privkey, sizeof(*privkey))))
		fatal("db_add_wallet_privkey failed");
}

static void load_peer_secrets(struct peer *peer)
{
	int err;
	sqlite3_stmt *stmt;
	sqlite3 *sql = peer->dstate->db->sql;
	char *ctx = tal(peer, char);
	const char *select;
	bool secrets_set = false;

	select = tal_fmt(ctx,
			 "SELECT * FROM peer_secrets WHERE peer = x'%s';",
			 pubkey_to_hexstr(ctx, peer->dstate->secpctx, peer->id));

	err = sqlite3_prepare_v2(sql, select, -1, &stmt, NULL);
	if (err != SQLITE_OK)
		fatal("load_peer_secrets:prepare gave %s:%s",
		      sqlite3_errstr(err), sqlite3_errmsg(sql));

	while ((err = sqlite3_step(stmt)) != SQLITE_DONE) {
		if (err != SQLITE_ROW)
			fatal("load_peer_secrets:step gave %s:%s",
			      sqlite3_errstr(err), sqlite3_errmsg(sql));
		if (secrets_set)
			fatal("load_peer_secrets: two secrets for '%s'",
			      select);
		peer_set_secrets_from_db(peer,
					 sqlite3_column_blob(stmt, 1),
					 sqlite3_column_bytes(stmt, 1),
					 sqlite3_column_blob(stmt, 2),
					 sqlite3_column_bytes(stmt, 2),
					 sqlite3_column_blob(stmt, 3),
					 sqlite3_column_bytes(stmt, 3));
		secrets_set = true;
	}

	if (!secrets_set)
		fatal("load_peer_secrets: no secrets for '%s'", select);
	tal_free(ctx);
}

static void load_peer_anchor(struct peer *peer)
{
	int err;
	sqlite3_stmt *stmt;
	sqlite3 *sql = peer->dstate->db->sql;
	char *ctx = tal(peer, char);
	const char *select;
	bool anchor_set = false;

	select = tal_fmt(ctx,
			 "SELECT * FROM anchors WHERE peer = x'%s';",
			 pubkey_to_hexstr(ctx, peer->dstate->secpctx, peer->id));

	err = sqlite3_prepare_v2(sql, select, -1, &stmt, NULL);
	if (err != SQLITE_OK)
		fatal("load_peer_anchor:prepare gave %s:%s",
		      sqlite3_errstr(err), sqlite3_errmsg(sql));

	while ((err = sqlite3_step(stmt)) != SQLITE_DONE) {
		if (err != SQLITE_ROW)
			fatal("load_peer_anchor:step gave %s:%s",
			      sqlite3_errstr(err), sqlite3_errmsg(sql));
		if (anchor_set)
			fatal("load_peer_anchor: two anchors for '%s'",
			      select);
		from_sql_blob(stmt, 1,
			      &peer->anchor.txid, sizeof(peer->anchor.txid));
		peer->anchor.index = sqlite3_column_int64(stmt, 2);
		peer->anchor.satoshis = sqlite3_column_int64(stmt, 3);
		peer->anchor.ours = sqlite3_column_int(stmt, 6);

		/* FIXME: Do timeout! */
		peer_watch_anchor(peer,
				  sqlite3_column_int(stmt, 4),
				  BITCOIN_ANCHOR_DEPTHOK, INPUT_NONE);
		peer->anchor.min_depth = sqlite3_column_int(stmt, 5);
		anchor_set = true;
	}

	if (!anchor_set)
		fatal("load_peer_anchor: no anchor for '%s'", select);
	tal_free(ctx);
}

static void load_peer_visible_state(struct peer *peer)
{
	int err;
	sqlite3_stmt *stmt;
	sqlite3 *sql = peer->dstate->db->sql;
	char *ctx = tal(peer, char);
	const char *select;
	bool visible_set = false;

	select = tal_fmt(ctx,
			 "SELECT * FROM their_visible_state WHERE peer = x'%s';",
			 pubkey_to_hexstr(ctx, peer->dstate->secpctx, peer->id));

	err = sqlite3_prepare_v2(sql, select, -1, &stmt, NULL);
	if (err != SQLITE_OK)
		fatal("load_peer_visible_state:prepare gave %s:%s",
		      sqlite3_errstr(err), sqlite3_errmsg(sql));

	while ((err = sqlite3_step(stmt)) != SQLITE_DONE) {
		if (err != SQLITE_ROW)
			fatal("load_peer_visible_state:step gave %s:%s",
			      sqlite3_errstr(err), sqlite3_errmsg(sql));

		if (sqlite3_column_count(stmt) != 8)
			fatal("load_peer_visible_state:step gave %i cols, not 8",
			      sqlite3_column_count(stmt));

		if (visible_set)
			fatal("load_peer_visible_state: two states for %s", select);
		visible_set = true;
		
		if (sqlite3_column_int64(stmt, 1))
			peer->remote.offer_anchor = CMD_OPEN_WITH_ANCHOR;
		else
			peer->remote.offer_anchor = CMD_OPEN_WITHOUT_ANCHOR;
		pubkey_from_sql(peer->dstate->secpctx, stmt, 2,
				&peer->remote.commitkey);
		pubkey_from_sql(peer->dstate->secpctx, stmt, 3,
				&peer->remote.finalkey);
		peer->remote.locktime.locktime = sqlite3_column_int(stmt, 4);
		peer->remote.mindepth = sqlite3_column_int(stmt, 5);
		peer->remote.commit_fee_rate = sqlite3_column_int64(stmt, 6);
		sha256_from_sql(stmt, 7, &peer->remote.next_revocation_hash);
		log_debug(peer->log, "%s:next_revocation_hash=%s",
			  __func__,
			  tal_hexstr(ctx, &peer->remote.next_revocation_hash,
				     sizeof(peer->remote.next_revocation_hash)));

		/* Now we can fill in anchor witnessscript. */
		peer->anchor.witnessscript
			= bitcoin_redeem_2of2(peer, peer->dstate->secpctx,
					      &peer->local.commitkey,
					      &peer->remote.commitkey);
	}

	if (!visible_set)
		fatal("load_peer_visible_state: no result '%s'", select);

	err = sqlite3_finalize(stmt);
	if (err != SQLITE_OK)
		fatal("load_peer_visible_state:finalize gave %s:%s",
		      sqlite3_errstr(err), sqlite3_errmsg(sql));
	tal_free(ctx);
}

static void load_peer_commit_info(struct peer *peer)
{
	int err;
	sqlite3_stmt *stmt;
	sqlite3 *sql = peer->dstate->db->sql;
	char *ctx = tal(peer, char);
	const char *select;

	select = tal_fmt(ctx,
			 "SELECT * FROM commit_info WHERE peer = x'%s';",
			 pubkey_to_hexstr(ctx, peer->dstate->secpctx, peer->id));

	err = sqlite3_prepare_v2(sql, select, -1, &stmt, NULL);
	if (err != SQLITE_OK)
		fatal("load_peer_commit_info:prepare gave %s:%s",
		      sqlite3_errstr(err), sqlite3_errmsg(sql));

	while ((err = sqlite3_step(stmt)) != SQLITE_DONE) {
		struct commit_info **cip, *ci;

		if (err != SQLITE_ROW)
			fatal("load_peer_commit_info:step gave %s:%s",
			      sqlite3_errstr(err), sqlite3_errmsg(sql));

		/* peer "SQL_PUBKEY", side TEXT, commit_num INT, revocation_hash "SQL_SHA256", sig "SQL_SIGNATURE", xmit_order INT, prev_revocation_hash "SQL_SHA256",  */
		if (sqlite3_column_count(stmt) != 7)
			fatal("load_peer_commit_info:step gave %i cols, not 7",
			      sqlite3_column_count(stmt));

		if (streq(sqlite3_column_str(stmt, 1), "LOCAL"))
			cip = &peer->local.commit;
		else {
			if (!streq(sqlite3_column_str(stmt, 1), "REMOTE"))
				fatal("load_peer_commit_info:bad side %s",
				      sqlite3_column_str(stmt, 1));
			cip = &peer->remote.commit;
			/* This is a hack where we temporarily store their
			 * previous revocation hash before we get their
			 * revocation. */
			if (sqlite3_column_type(stmt, 6) != SQLITE_NULL) {
				peer->their_prev_revocation_hash
					= tal(peer, struct sha256);
				sha256_from_sql(stmt, 6,
						peer->their_prev_revocation_hash);
			}
		}

		/* Do we already have this one? */
		if (*cip)
			fatal("load_peer_commit_info:duplicate side %s",
			      sqlite3_column_str(stmt, 1));

		*cip = ci = new_commit_info(peer, sqlite3_column_int64(stmt, 2));
		sha256_from_sql(stmt, 3, &ci->revocation_hash);
		ci->order = sqlite3_column_int64(stmt, 4);

		if (sqlite3_column_type(stmt, 5) == SQLITE_NULL)
			ci->sig = NULL;
		else {
			ci->sig = tal(ci, struct bitcoin_signature);
			sig_from_sql(peer->dstate->secpctx, stmt, 5, ci->sig);
		}

		/* Set once we have updated HTLCs. */
		ci->cstate = NULL;
		ci->tx = NULL;
	}

	err = sqlite3_finalize(stmt);
	if (err != SQLITE_OK)
		fatal("load_peer_commit_info:finalize gave %s:%s",
		      sqlite3_errstr(err), sqlite3_errmsg(sql));
	tal_free(ctx);

	if (!peer->local.commit)
		fatal("load_peer_commit_info:no local commit info found");
	if (!peer->remote.commit)
		fatal("load_peer_commit_info:no remote commit info found");
}

/* Because their HTLCs are not ordered wrt to ours, we can go negative
 * and do normally-impossible things in intermediate states.  So we
 * mangle cstate balances manually. */
static void apply_htlc(struct channel_state *cstate, const struct htlc *htlc,
		       enum side side)
{
	const char *sidestr = side_to_str(side);

	if (!htlc_has(htlc, HTLC_FLAG(side,HTLC_F_WAS_COMMITTED)))
		return;

	log_debug(htlc->peer->log, "  %s committed", sidestr);
	force_add_htlc(cstate, htlc);

	if (!htlc_has(htlc, HTLC_FLAG(side, HTLC_F_COMMITTED))) {
		log_debug(htlc->peer->log, "  %s %s",
			  sidestr, htlc->r ? "resolved" : "failed");
		if (htlc->r)
			force_fulfill_htlc(cstate, htlc);
		else
			force_fail_htlc(cstate, htlc);
	}
}

/* As we load the HTLCs, we apply them to get the final channel_state.
 * We also get the last used htlc id.
 * This is slow, but sure. */
static void load_peer_htlcs(struct peer *peer)
{
	int err;
	sqlite3_stmt *stmt;
	sqlite3 *sql = peer->dstate->db->sql;
	char *ctx = tal(peer, char);
	const char *select;
	bool to_them_only, to_us_only;

	select = tal_fmt(ctx,
			 "SELECT * FROM htlcs WHERE peer = x'%s' ORDER BY id;",
			 pubkey_to_hexstr(ctx, peer->dstate->secpctx, peer->id));

	err = sqlite3_prepare_v2(sql, select, -1, &stmt, NULL);
	if (err != SQLITE_OK)
		fatal("load_peer_htlcs:prepare gave %s:%s",
		      sqlite3_errstr(err), sqlite3_errmsg(sql));

	peer->local.commit->cstate = initial_cstate(peer,
						    peer->anchor.satoshis,
						    peer->local.commit_fee_rate,
						    peer->local.offer_anchor
						    == CMD_OPEN_WITH_ANCHOR ?
						    LOCAL : REMOTE);
	peer->remote.commit->cstate = initial_cstate(peer,
						     peer->anchor.satoshis,
						     peer->remote.commit_fee_rate,
						     peer->local.offer_anchor
						     == CMD_OPEN_WITH_ANCHOR ?
						     LOCAL : REMOTE);

	/* We rebuild cstate by running *every* HTLC through. */
	while ((err = sqlite3_step(stmt)) != SQLITE_DONE) {
		struct htlc *htlc;
		struct sha256 rhash;
		enum htlc_state hstate;

		if (err != SQLITE_ROW)
			fatal("load_peer_htlcs:step gave %s:%s",
			      sqlite3_errstr(err), sqlite3_errmsg(sql));

		if (sqlite3_column_count(stmt) != 11)
			fatal("load_peer_htlcs:step gave %i cols, not 11",
			      sqlite3_column_count(stmt));
		sha256_from_sql(stmt, 5, &rhash);

		hstate = htlc_state_from_name(sqlite3_column_str(stmt, 2));
		if (hstate == HTLC_STATE_INVALID)
			fatal("load_peer_htlcs:invalid state %s",
			      sqlite3_column_str(stmt, 2));
		htlc = peer_new_htlc(peer,
				     sqlite3_column_int64(stmt, 1),
				     sqlite3_column_int64(stmt, 3),
				     &rhash,
				     sqlite3_column_int64(stmt, 4),
				     sqlite3_column_blob(stmt, 7),
				     sqlite3_column_bytes(stmt, 7),
				     NULL,
				     hstate);

		if (sqlite3_column_type(stmt, 6) != SQLITE_NULL) {
			htlc->r = tal(htlc, struct rval);
			from_sql_blob(stmt, 6, htlc->r, sizeof(*htlc->r));
		}
		if (sqlite3_column_type(stmt, 10) != SQLITE_NULL) {
			htlc->fail = tal_sql_blob(htlc, stmt, 10);
		}

		if (htlc->r && htlc->fail)
			fatal("%s HTLC %"PRIu64" has failed and fulfilled?",
			      htlc_owner(htlc) == LOCAL ? "local" : "remote",
			      htlc->id);

		log_debug(peer->log, "Loaded %s HTLC %"PRIu64" (%s)",
			  htlc_owner(htlc) == LOCAL ? "local" : "remote",
			  htlc->id, htlc_state_name(htlc->state));

		if (htlc_owner(htlc) == LOCAL
		    && htlc->id >= peer->htlc_id_counter)
			peer->htlc_id_counter = htlc->id + 1;

		/* Update cstate with this HTLC. */
		apply_htlc(peer->local.commit->cstate, htlc, LOCAL);
		apply_htlc(peer->remote.commit->cstate, htlc, REMOTE);
	}

	err = sqlite3_finalize(stmt);
	if (err != SQLITE_OK)
		fatal("load_peer_htlcs:finalize gave %s:%s",
		      sqlite3_errstr(err), sqlite3_errmsg(sql));

	/* Now set any in-progress fee changes. */
	select = tal_fmt(ctx,
			 "SELECT * FROM feechanges WHERE peer = x'%s';",
			 pubkey_to_hexstr(ctx, peer->dstate->secpctx, peer->id));

	err = sqlite3_prepare_v2(sql, select, -1, &stmt, NULL);
	if (err != SQLITE_OK)
		fatal("load_peer_htlcs:prepare gave %s:%s",
		      sqlite3_errstr(err), sqlite3_errmsg(sql));

	while ((err = sqlite3_step(stmt)) != SQLITE_DONE) {
		enum feechange_state feechange_state;

		if (err != SQLITE_ROW)
			fatal("load_peer_htlcs:step gave %s:%s",
			      sqlite3_errstr(err), sqlite3_errmsg(sql));

		if (sqlite3_column_count(stmt) != 3)
			fatal("load_peer_htlcs:step gave %i cols, not 3",
			      sqlite3_column_count(stmt));

		feechange_state
			= feechange_state_from_name(sqlite3_column_str(stmt, 1));
		if (feechange_state == FEECHANGE_STATE_INVALID)
			fatal("load_peer_htlcs:invalid feechange state %s",
			      sqlite3_column_str(stmt, 1));
		if (peer->feechanges[feechange_state])
			fatal("load_peer_htlcs: second feechange in state %s",
			      sqlite3_column_str(stmt, 1));
		peer->feechanges[feechange_state]
			= new_feechange(peer, sqlite3_column_int64(stmt, 2),
					feechange_state);
	}
	err = sqlite3_finalize(stmt);
	if (err != SQLITE_OK)
		fatal("load_peer_htlcs:finalize gave %s:%s",
		      sqlite3_errstr(err), sqlite3_errmsg(sql));

	if (!balance_after_force(peer->local.commit->cstate)
	    || !balance_after_force(peer->remote.commit->cstate))
		fatal("load_peer_htlcs:channel didn't balance");

	/* Update commit->tx and commit->map */
	peer->local.commit->tx = create_commit_tx(peer->local.commit,
						  peer,
						  &peer->local.commit->revocation_hash,
						  peer->local.commit->cstate,
						  LOCAL, &to_them_only);
	bitcoin_txid(peer->local.commit->tx, &peer->local.commit->txid);

	peer->remote.commit->tx = create_commit_tx(peer->remote.commit,
						   peer,
						   &peer->remote.commit->revocation_hash,
						   peer->remote.commit->cstate,
						   REMOTE, &to_us_only);
	bitcoin_txid(peer->remote.commit->tx, &peer->remote.commit->txid);

	peer->remote.staging_cstate = copy_cstate(peer, peer->remote.commit->cstate);
	peer->local.staging_cstate = copy_cstate(peer, peer->local.commit->cstate);
	log_debug(peer->log, "Local staging: pay %u/%u fee %u/%u htlcs %u/%u",
		  peer->local.staging_cstate->side[LOCAL].pay_msat,
		  peer->local.staging_cstate->side[REMOTE].pay_msat,
		  peer->local.staging_cstate->side[LOCAL].fee_msat,
		  peer->local.staging_cstate->side[REMOTE].fee_msat,
		  peer->local.staging_cstate->side[LOCAL].num_htlcs,
		  peer->local.staging_cstate->side[REMOTE].num_htlcs);
	log_debug(peer->log, "Remote staging: pay %u/%u fee %u/%u htlcs %u/%u",
		  peer->remote.staging_cstate->side[LOCAL].pay_msat,
		  peer->remote.staging_cstate->side[REMOTE].pay_msat,
		  peer->remote.staging_cstate->side[LOCAL].fee_msat,
		  peer->remote.staging_cstate->side[REMOTE].fee_msat,
		  peer->remote.staging_cstate->side[LOCAL].num_htlcs,
		  peer->remote.staging_cstate->side[REMOTE].num_htlcs);
	
	tal_free(ctx);
}

/* FIXME: A real database person would do this in a single clause along
 * with loading the htlcs in the first place! */
static void connect_htlc_src(struct lightningd_state *dstate)
{
	sqlite3 *sql = dstate->db->sql;
	int err;
	sqlite3_stmt *stmt;
	char *ctx = tal(dstate, char);
	const char *select;

	select = tal_fmt(ctx,
			 "SELECT peer,id,state,src_peer,src_id FROM htlcs WHERE src_peer IS NOT NULL AND state <> 'RCVD_REMOVE_ACK_REVOCATION' AND state <> 'SENT_REMOVE_ACK_REVOCATION';");

	err = sqlite3_prepare_v2(sql, select, -1, &stmt, NULL);
	if (err != SQLITE_OK)
		fatal("connect_htlc_src:%s gave %s:%s",
		      select, sqlite3_errstr(err), sqlite3_errmsg(sql));

	while ((err = sqlite3_step(stmt)) != SQLITE_DONE) {
		struct pubkey id;
		struct peer *peer;
		struct htlc *htlc;
		enum htlc_state s;

		if (err != SQLITE_ROW)
			fatal("connect_htlc_src:step gave %s:%s",
			      sqlite3_errstr(err), sqlite3_errmsg(sql));

		pubkey_from_sql(dstate->secpctx, stmt, 0, &id);
		peer = find_peer(dstate, &id);
		if (!peer)
			continue;

		s = htlc_state_from_name(sqlite3_column_str(stmt, 2));
		if (s == HTLC_STATE_INVALID)
			fatal("connect_htlc_src:unknown state %s",
			      sqlite3_column_str(stmt, 2));

		htlc = htlc_get(&peer->htlcs, sqlite3_column_int64(stmt, 1),
				htlc_state_owner(s));
		if (!htlc)
			fatal("connect_htlc_src:unknown htlc %"PRIuSQLITE64" state %s",
			      sqlite3_column_int64(stmt, 1),
			      sqlite3_column_str(stmt, 2));

		pubkey_from_sql(dstate->secpctx, stmt, 4, &id);
		peer = find_peer(dstate, &id);
		if (!peer)
			fatal("connect_htlc_src:unknown src peer %s",
			      tal_hexstr(dstate, &id, sizeof(id)));

		/* Source must be a HTLC they offered. */
		htlc->src = htlc_get(&peer->htlcs,
				     sqlite3_column_int64(stmt, 4),
				     REMOTE);
		if (!htlc->src)
			fatal("connect_htlc_src:unknown src htlc");
	}

	err = sqlite3_finalize(stmt);
	if (err != SQLITE_OK)
		fatal("load_peer_htlcs:finalize gave %s:%s",
		      sqlite3_errstr(err),
		      sqlite3_errmsg(dstate->db->sql));
	tal_free(ctx);
}

static const char *linearize_shachain(const tal_t *ctx,
				      const struct shachain *shachain)
{
	size_t i;
	u8 *p = tal_arr(ctx, u8, 0);
	const char *str;

	push_le64(shachain->min_index, push, &p);
	push_le32(shachain->num_valid, push, &p);
	for (i = 0; i < shachain->num_valid; i++) {
		push_le64(shachain->known[i].index, push, &p);
		push(&shachain->known[i].hash, sizeof(shachain->known[i].hash),
		     &p);
	}
	for (i = shachain->num_valid; i < ARRAY_SIZE(shachain->known); i++) {
		static u8 zeroes[sizeof(shachain->known[0].hash)];
		push_le64(0, push, &p);
		push(zeroes, sizeof(zeroes), &p);
	}
		
	assert(tal_count(p) == SHACHAIN_SIZE);
	str = tal_hexstr(ctx, p, tal_count(p));
	tal_free(p);
	return str;
}

static bool delinearize_shachain(struct shachain *shachain,
				 const void *data, size_t len)
{
	size_t i;
	const u8 *p = data;

	shachain->min_index = pull_le64(&p, &len);
	shachain->num_valid = pull_le32(&p, &len);
	for (i = 0; i < ARRAY_SIZE(shachain->known); i++) {
		shachain->known[i].index = pull_le64(&p, &len);
		pull(&p, &len, &shachain->known[i].hash,
		     sizeof(shachain->known[i].hash));
	}
	return p && len == 0;
}

static void load_peer_shachain(struct peer *peer)
{
	int err;
	sqlite3_stmt *stmt;
	sqlite3 *sql = peer->dstate->db->sql;
	char *ctx = tal(peer, char);
	bool shachain_found = false;
	const char *select;

	select = tal_fmt(ctx,
			 "SELECT * FROM shachain WHERE peer = x'%s';",
			 pubkey_to_hexstr(ctx, peer->dstate->secpctx, peer->id));

	err = sqlite3_prepare_v2(sql, select, -1, &stmt, NULL);
	if (err != SQLITE_OK)
		fatal("load_peer_shachain:prepare gave %s:%s",
		      sqlite3_errstr(err), sqlite3_errmsg(sql));

	while ((err = sqlite3_step(stmt)) != SQLITE_DONE) {
		const char *hexstr;

		if (err != SQLITE_ROW)
			fatal("load_peer_shachain:step gave %s:%s",
			      sqlite3_errstr(err), sqlite3_errmsg(sql));

		/* shachain (peer "SQL_PUBKEY", shachain BINARY(%zu) */
		if (sqlite3_column_count(stmt) != 2)
			fatal("load_peer_shachain:step gave %i cols, not 2",
			      sqlite3_column_count(stmt));

		if (shachain_found)
			fatal("load_peer_shachain:multiple shachains?");

		hexstr = tal_hexstr(ctx, sqlite3_column_blob(stmt, 1),
				    sqlite3_column_bytes(stmt, 1));
		if (!delinearize_shachain(&peer->their_preimages,
					  sqlite3_column_blob(stmt, 1),
					  sqlite3_column_bytes(stmt, 1)))
			fatal("load_peer_shachain:invalid shachain %s",
			      hexstr);
		shachain_found = true;
	}

	if (!shachain_found)
		fatal("load_peer_shachain:no shachain");
	tal_free(ctx);
}

/* We may not have one, and that's OK. */
static void load_peer_closing(struct peer *peer)
{
	int err;
	sqlite3_stmt *stmt;
	sqlite3 *sql = peer->dstate->db->sql;
	char *ctx = tal(peer, char);
	bool closing_found = false;
	const char *select;

	select = tal_fmt(ctx,
			 "SELECT * FROM closing WHERE peer = x'%s';",
			 pubkey_to_hexstr(ctx, peer->dstate->secpctx, peer->id));

	err = sqlite3_prepare_v2(sql, select, -1, &stmt, NULL);
	if (err != SQLITE_OK)
		fatal("load_peer_closing:prepare gave %s:%s",
		      sqlite3_errstr(err), sqlite3_errmsg(sql));

	while ((err = sqlite3_step(stmt)) != SQLITE_DONE) {
		if (err != SQLITE_ROW)
			fatal("load_peer_closing:step gave %s:%s",
			      sqlite3_errstr(err), sqlite3_errmsg(sql));

		if (sqlite3_column_count(stmt) != 9)
			fatal("load_peer_closing:step gave %i cols, not 9",
			      sqlite3_column_count(stmt));

		if (closing_found)
			fatal("load_peer_closing:multiple closing?");

		peer->closing.our_fee = sqlite3_column_int64(stmt, 1);
		peer->closing.their_fee = sqlite3_column_int64(stmt, 2);
		if (sqlite3_column_type(stmt, 3) == SQLITE_NULL)
			peer->closing.their_sig = NULL;
		else {
			peer->closing.their_sig = tal(peer,
						      struct bitcoin_signature);
			sig_from_sql(peer->dstate->secpctx, stmt, 3,
				     peer->closing.their_sig);
		}
		peer->closing.our_script = tal_sql_blob(peer, stmt, 4);
		peer->closing.their_script = tal_sql_blob(peer, stmt, 5);
		peer->closing.shutdown_order = sqlite3_column_int64(stmt, 6);
		peer->closing.closing_order = sqlite3_column_int64(stmt, 7);
		peer->closing.sigs_in = sqlite3_column_int64(stmt, 8);
		closing_found = true;
	}
	tal_free(ctx);
}

/* FIXME: much of this is redundant. */
static void restore_peer_local_visible_state(struct peer *peer)
{
	if (peer->remote.offer_anchor == CMD_OPEN_WITH_ANCHOR)
		peer->local.offer_anchor = CMD_OPEN_WITHOUT_ANCHOR;
	else
		peer->local.offer_anchor = CMD_OPEN_WITH_ANCHOR;

	/* peer->local.commitkey and peer->local.finalkey set by
	 * peer_set_secrets_from_db(). */
	memcheck(&peer->local.commitkey, sizeof(peer->local.commitkey));
	memcheck(&peer->local.finalkey, sizeof(peer->local.finalkey));
	/* These set in new_peer */
	memcheck(&peer->local.locktime, sizeof(peer->local.locktime));
	memcheck(&peer->local.mindepth, sizeof(peer->local.mindepth));
	/* This set in db_load_peers */
	memcheck(&peer->local.commit_fee_rate,
		 sizeof(peer->local.commit_fee_rate));

	peer_get_revocation_hash(peer,
				 peer->local.commit->commit_num + 1,
				 &peer->local.next_revocation_hash);

	if (state_is_normal(peer->state))
		peer->nc = add_connection(peer->dstate,
					  &peer->dstate->id, peer->id,
					  peer->dstate->config.fee_base,
					  peer->dstate->config.fee_per_satoshi,
					  peer->dstate->config.min_htlc_expiry,
					  peer->dstate->config.min_htlc_expiry);

	peer->their_commitsigs = peer->local.commit->commit_num + 1;
	/* If they created anchor, they didn't send a sig for first commit */
	if (!peer->anchor.ours)
		peer->their_commitsigs--;

	peer->order_counter = 0;
	if (peer->local.commit->order + 1 > peer->order_counter)
		peer->order_counter = peer->local.commit->order + 1;
	if (peer->remote.commit->order + 1 > peer->order_counter)
		peer->order_counter = peer->remote.commit->order + 1;
	if (peer->closing.closing_order + 1 > peer->order_counter)
		peer->order_counter = peer->closing.closing_order + 1;
	if (peer->closing.shutdown_order + 1 > peer->order_counter)
		peer->order_counter = peer->closing.shutdown_order + 1;
}

static void db_load_peers(struct lightningd_state *dstate)
{
	int err;
	sqlite3_stmt *stmt;
	struct peer *peer;

	err = sqlite3_prepare_v2(dstate->db->sql, "SELECT * FROM peers;", -1,
				 &stmt, NULL);

	if (err != SQLITE_OK)
		fatal("db_load_peers:prepare gave %s:%s",
		      sqlite3_errstr(err), sqlite3_errmsg(dstate->db->sql));

	while ((err = sqlite3_step(stmt)) != SQLITE_DONE) {
		enum state state;
		struct log *l;
		struct pubkey id;
		const char *idstr;

		if (err != SQLITE_ROW)
			fatal("db_load_peers:step gave %s:%s",
			      sqlite3_errstr(err),
			      sqlite3_errmsg(dstate->db->sql));
		if (sqlite3_column_count(stmt) != 4)
			fatal("db_load_peers:step gave %i cols, not 4",
			      sqlite3_column_count(stmt));
		state = name_to_state(sqlite3_column_str(stmt, 1));
		if (state == STATE_MAX)
			fatal("db_load_peers:unknown state %s",
			      sqlite3_column_str(stmt, 1));
		pubkey_from_sql(dstate->secpctx, stmt, 0, &id);
		idstr = pubkey_to_hexstr(dstate, dstate->secpctx, &id);
		l = new_log(dstate, dstate->log_record, "%s:", idstr);
		tal_free(idstr);
		peer = new_peer(dstate, l, state, sqlite3_column_int(stmt, 2) ?
				CMD_OPEN_WITH_ANCHOR : CMD_OPEN_WITHOUT_ANCHOR);
		peer->htlc_id_counter = 0;
		peer->id = tal_dup(peer, struct pubkey, &id);
		peer->local.commit_fee_rate = sqlite3_column_int64(stmt, 3);
		log_debug(peer->log, "%s:%s",
			  __func__, state_name(peer->state));
	}
	err = sqlite3_finalize(stmt);
	if (err != SQLITE_OK)
		fatal("db_load_peers:finalize gave %s:%s",
		      sqlite3_errstr(err),
		      sqlite3_errmsg(dstate->db->sql));

	list_for_each(&dstate->peers, peer, list) {
		load_peer_secrets(peer);
		load_peer_closing(peer);
		peer->anchor.min_depth = 0;
		if (peer->state >= STATE_OPEN_WAITING_OURANCHOR
		    && !state_is_error(peer->state)) {
			load_peer_anchor(peer);
			load_peer_visible_state(peer);
			load_peer_shachain(peer);
			load_peer_commit_info(peer);
			load_peer_htlcs(peer);
			restore_peer_local_visible_state(peer);
		}
	}

	connect_htlc_src(dstate);
}


static const char *pubkeys_to_hex(const tal_t *ctx,
				  secp256k1_context *secpctx,
				  const struct pubkey *ids)
{
	u8 *ders = tal_arr(ctx, u8, PUBKEY_DER_LEN * tal_count(ids));
	size_t i;

	for (i = 0; i < tal_count(ids); i++)
		pubkey_to_der(secpctx, ders + i * PUBKEY_DER_LEN, &ids[i]);

	return tal_hexstr(ctx, ders, tal_count(ders));
}
static struct pubkey *pubkeys_from_arr(const tal_t *ctx,
				       secp256k1_context *secpctx,
				       const void *blob, size_t len)
{
	struct pubkey *ids;
	size_t i;

	if (len % PUBKEY_DER_LEN)
		fatal("ids array bad length %zu", len);

	ids = tal_arr(ctx, struct pubkey, len / PUBKEY_DER_LEN);
	for (i = 0; i < tal_count(ids); i++) {
		if (!pubkey_from_der(secpctx, blob, PUBKEY_DER_LEN, &ids[i]))
			fatal("ids array invalid %zu", i);
		blob = (const u8 *)blob + PUBKEY_DER_LEN;
	}
	return ids;
}

static void db_load_pay(struct lightningd_state *dstate)
{
	int err;
	sqlite3_stmt *stmt;
	char *ctx = tal(dstate, char);

	err = sqlite3_prepare_v2(dstate->db->sql, "SELECT * FROM pay;", -1,
				 &stmt, NULL);

	if (err != SQLITE_OK)
		fatal("db_load_pay:prepare gave %s:%s",
		      sqlite3_errstr(err), sqlite3_errmsg(dstate->db->sql));

	while ((err = sqlite3_step(stmt)) != SQLITE_DONE) {
		struct sha256 rhash;
		struct htlc *htlc;
		struct pubkey *peer_id;
		u64 htlc_id, msatoshi;
		struct pubkey *ids;
		struct rval *r;
		void *fail;

		if (err != SQLITE_ROW)
			fatal("db_load_pay:step gave %s:%s",
			      sqlite3_errstr(err),
			      sqlite3_errmsg(dstate->db->sql));
		if (sqlite3_column_count(stmt) != 7)
			fatal("db_load_pay:step gave %i cols, not 7",
			      sqlite3_column_count(stmt));

		sha256_from_sql(stmt, 0, &rhash);
		msatoshi = sqlite3_column_int64(stmt, 1);
		ids = pubkeys_from_arr(ctx, dstate->secpctx,
				       sqlite3_column_blob(stmt, 2),
				       sqlite3_column_bytes(stmt, 2));
		if (sqlite3_column_type(stmt, 3) == SQLITE_NULL)
			peer_id = NULL;
		else {
			peer_id = tal(ctx, struct pubkey);
			pubkey_from_sql(dstate->secpctx, stmt, 3, peer_id);
		}
		htlc_id = sqlite3_column_int64(stmt, 4);
		if (sqlite3_column_type(stmt, 5) == SQLITE_NULL)
			r = NULL;
		else {
			r = tal(ctx, struct rval);
			from_sql_blob(stmt, 5, r, sizeof(*r));
		}
		fail = tal_sql_blob(ctx, stmt, 6);
		/* Exactly one of these must be set. */
		if (!fail + !peer_id + !r != 2)
			fatal("db_load_pay: not exactly one set:"
			      " fail=%p peer_id=%p r=%p",
			      fail, peer_id, r);
		if (peer_id) {
			struct peer *peer = find_peer(dstate, peer_id);
			if (!peer)
				fatal("db_load_pay: unknown peer");
			htlc = htlc_get(&peer->htlcs, htlc_id, LOCAL);
			if (!htlc)
				fatal("db_load_pay: unknown htlc");
		} else
			htlc = NULL;

		if (!pay_add(dstate, &rhash, msatoshi, ids, htlc, fail, r))
			fatal("db_load_pay: could not add pay");
	}
	tal_free(ctx);
}

static void db_load_invoice(struct lightningd_state *dstate)
{
	int err;
	sqlite3_stmt *stmt;
	char *ctx = tal(dstate, char);

	err = sqlite3_prepare_v2(dstate->db->sql, "SELECT * FROM invoice;", -1,
				 &stmt, NULL);

	if (err != SQLITE_OK)
		fatal("db_load_invoice:prepare gave %s:%s",
		      sqlite3_errstr(err), sqlite3_errmsg(dstate->db->sql));

	while ((err = sqlite3_step(stmt)) != SQLITE_DONE) {
		struct rval r;
		u64 msatoshi, paid_num;
		const char *label;

		if (err != SQLITE_ROW)
			fatal("db_load_invoice:step gave %s:%s",
			      sqlite3_errstr(err),
			      sqlite3_errmsg(dstate->db->sql));
		if (sqlite3_column_count(stmt) != 4)
			fatal("db_load_invoice:step gave %i cols, not 4",
			      sqlite3_column_count(stmt));

		from_sql_blob(stmt, 0, &r, sizeof(r));
		msatoshi = sqlite3_column_int64(stmt, 1);
		label = (const char *)sqlite3_column_text(stmt, 2);
		paid_num = sqlite3_column_int64(stmt, 3);
		invoice_add(dstate, &r, msatoshi, label, paid_num);
	}
	tal_free(ctx);
}

static void db_load_addresses(struct lightningd_state *dstate)
{
	int err;
	sqlite3_stmt *stmt;
	sqlite3 *sql = dstate->db->sql;
	char *ctx = tal(dstate, char);
	const char *select;

	select = tal_fmt(ctx, "SELECT * FROM peer_address;");

	err = sqlite3_prepare_v2(sql, select, -1, &stmt, NULL);
	if (err != SQLITE_OK)
		fatal("load_peer_addresses:prepare gave %s:%s",
		      sqlite3_errstr(err), sqlite3_errmsg(sql));

	while ((err = sqlite3_step(stmt)) != SQLITE_DONE) {
		struct peer_address *addr;

		if (err != SQLITE_ROW)
			fatal("load_peer_addresses:step gave %s:%s",
			      sqlite3_errstr(err), sqlite3_errmsg(sql));
		addr = tal(dstate, struct peer_address);
		pubkey_from_sql(dstate->secpctx, stmt, 0, &addr->id);
		if (!netaddr_from_blob(sqlite3_column_blob(stmt, 1),
				       sqlite3_column_bytes(stmt, 1),
				       &addr->addr))
			fatal("load_peer_addresses: unparsable addresses for '%s'",
			      select);
		list_add_tail(&dstate->addresses, &addr->list);
		log_debug(dstate->base_log, "load_peer_addresses:%s",
			  pubkey_to_hexstr(ctx, dstate->secpctx, &addr->id));
	}
	tal_free(ctx);
}

static void db_load(struct lightningd_state *dstate)
{
	db_load_wallet(dstate);
	db_load_addresses(dstate);
	db_load_peers(dstate);
	db_load_pay(dstate);
	db_load_invoice(dstate);
}

void db_init(struct lightningd_state *dstate)
{
	int err;
	bool created = false;

	if (SQLITE_VERSION_NUMBER != sqlite3_libversion_number())
		fatal("SQLITE version mistmatch: compiled %u, now %u",
		      SQLITE_VERSION_NUMBER, sqlite3_libversion_number());

	dstate->db = tal(dstate, struct db);

	err = sqlite3_open_v2(DB_FILE, &dstate->db->sql,
			      SQLITE_OPEN_READWRITE, NULL);
	if (err != SQLITE_OK) {
		log_unusual(dstate->base_log,
			    "Error opening %s (%s), trying to create",
			    DB_FILE, sqlite3_errstr(err));
		err = sqlite3_open_v2(DB_FILE, &dstate->db->sql,
				      SQLITE_OPEN_READWRITE
				      | SQLITE_OPEN_CREATE, NULL);
		if (err != SQLITE_OK)
			fatal("failed creating %s: %s",
			      DB_FILE, sqlite3_errstr(err));
		created = true;
	}

	tal_add_destructor(dstate->db, close_db);
	dstate->db->in_transaction = false;
	dstate->db->err = NULL;

	if (!created) {
		db_load(dstate);
		return;
	}

	/* Set up tables. */
	if (!db_exec(__func__, dstate,
		     TABLE(wallet,
			   SQL_PRIVKEY(privkey))
		     TABLE(pay,
			   SQL_RHASH(rhash), SQL_U64(msatoshi),
			   SQL_BLOB(ids), SQL_PUBKEY(htlc_peer),
			   SQL_U64(htlc_id), SQL_R(r), SQL_FAIL(fail),
			   "PRIMARY KEY(rhash)")
		     TABLE(invoice,
			   SQL_R(r), SQL_U64(msatoshi), SQL_INVLABEL(label),
			   SQL_U64(paid_num),
			   "PRIMARY KEY(label)")
		     TABLE(anchors,
			   SQL_PUBKEY(peer),
			   SQL_TXID(txid), SQL_U32(idx), SQL_U64(amount),
			   SQL_U32(ok_depth), SQL_U32(min_depth),
			   SQL_BOOL(ours))
		     /* FIXME: state in key is overkill: just need side */
		     TABLE(htlcs,
			   SQL_PUBKEY(peer), SQL_U64(id),
			   SQL_STATENAME(state), SQL_U64(msatoshi),
			   SQL_U32(expiry), SQL_RHASH(rhash), SQL_R(r),
			   SQL_ROUTING(routing), SQL_PUBKEY(src_peer),
			   SQL_U64(src_id), SQL_BLOB(fail),
			   "PRIMARY KEY(peer, id, state)")
		     TABLE(feechanges,
			   SQL_PUBKEY(peer), SQL_STATENAME(state),
			   SQL_U32(fee_rate),
			   "PRIMARY KEY(peer,state)")
		     TABLE(commit_info,
			   SQL_PUBKEY(peer), SQL_U32(side),
			   SQL_U64(commit_num), SQL_SHA256(revocation_hash),
			   SQL_U64(xmit_order), SQL_SIGNATURE(sig),
			   SQL_SHA256(prev_revocation_hash),
			   "PRIMARY KEY(peer, side)")
		     TABLE(shachain,
			   SQL_PUBKEY(peer), SQL_SHACHAIN(shachain),
			   "PRIMARY KEY(peer)")
		     TABLE(their_visible_state,
			   SQL_PUBKEY(peer), SQL_BOOL(offered_anchor),
			   SQL_PUBKEY(commitkey), SQL_PUBKEY(finalkey),
			   SQL_U32(locktime), SQL_U32(mindepth),
			   SQL_U32(commit_fee_rate),
			   SQL_SHA256(next_revocation_hash),
			   "PRIMARY KEY(peer)")
		     TABLE(their_commitments,
			   SQL_PUBKEY(peer), SQL_SHA256(txid),
			   SQL_U64(commit_num),
			   "PRIMARY KEY(peer, txid)")
		     TABLE(peer_secrets,
			   SQL_PUBKEY(peer), SQL_PRIVKEY(commitkey),
			   SQL_PRIVKEY(finalkey),
			   SQL_SHA256(revocation_seed),
			   "PRIMARY KEY(peer)")
		     TABLE(peer_address,
			   SQL_PUBKEY(peer), SQL_BLOB(addr),
			   "PRIMARY KEY(peer)")
		     TABLE(closing,
			   SQL_PUBKEY(peer), SQL_U64(our_fee),
			   SQL_U64(their_fee), SQL_SIGNATURE(their_sig),
			   SQL_BLOB(our_script), SQL_BLOB(their_script),
			   SQL_U64(shutdown_order), SQL_U64(closing_order),
			   SQL_U64(sigs_in),
			   "PRIMARY KEY(peer)")
		     TABLE(peers,
			   SQL_PUBKEY(peer), SQL_STATENAME(state),
			   SQL_BOOL(offered_anchor), SQL_U32(our_feerate),
			   "PRIMARY KEY(peer)"))) {
		unlink(DB_FILE);
		fatal("%s", dstate->db->err);
	}
}

void db_set_anchor(struct peer *peer)
{
	const char *ctx = tal(peer, char);
	const char *peerid;

	assert(peer->dstate->db->in_transaction);
	peerid = pubkey_to_hexstr(ctx, peer->dstate->secpctx, peer->id);
	log_debug(peer->log, "%s(%s)", __func__, peerid);

	db_exec(__func__, peer->dstate, 
		"INSERT INTO anchors VALUES (x'%s', x'%s', %u, %"PRIu64", %i, %u, %s);",
		peerid,
		tal_hexstr(ctx, &peer->anchor.txid, sizeof(peer->anchor.txid)),
		peer->anchor.index,
		peer->anchor.satoshis,
		peer->anchor.ok_depth,
		peer->anchor.min_depth,
		sql_bool(peer->anchor.ours));

	db_exec(__func__, peer->dstate, 
		"INSERT INTO commit_info VALUES(x'%s', '%s', 0, x'%s', %"PRIi64", %s, NULL);",
		peerid,
		side_to_str(LOCAL),
		tal_hexstr(ctx, &peer->local.commit->revocation_hash,
			   sizeof(peer->local.commit->revocation_hash)),
		peer->local.commit->order,
		sig_to_sql(ctx, peer->dstate->secpctx,
			   peer->local.commit->sig));

	db_exec(__func__, peer->dstate, 
		"INSERT INTO commit_info VALUES(x'%s', '%s', 0, x'%s', %"PRIi64", %s, NULL);",
		peerid,
		side_to_str(REMOTE),
		tal_hexstr(ctx, &peer->remote.commit->revocation_hash,
			   sizeof(peer->remote.commit->revocation_hash)),
		peer->remote.commit->order,
		sig_to_sql(ctx, peer->dstate->secpctx,
			   peer->remote.commit->sig));

	db_exec(__func__, peer->dstate,
		"INSERT INTO shachain VALUES (x'%s', x'%s');",
		peerid,
		linearize_shachain(ctx, &peer->their_preimages));

	tal_free(ctx);
}

bool db_set_visible_state(struct peer *peer)
{
	const char *errmsg, *ctx = tal(peer, char);
	const char *peerid = pubkey_to_hexstr(ctx, peer->dstate->secpctx, peer->id);

	log_debug(peer->log, "%s(%s)", __func__, peerid);
	db_start_transaction(peer);

	db_exec(__func__, peer->dstate, 
		"INSERT INTO their_visible_state VALUES (x'%s', %s, x'%s', x'%s', %u, %u, %"PRIu64", x'%s');",
		peerid,
		sql_bool(peer->remote.offer_anchor == CMD_OPEN_WITH_ANCHOR),
		pubkey_to_hexstr(ctx, peer->dstate->secpctx,
				 &peer->remote.commitkey),
		pubkey_to_hexstr(ctx, peer->dstate->secpctx,
				 &peer->remote.finalkey),
		peer->remote.locktime.locktime,
		peer->remote.mindepth,
		peer->remote.commit_fee_rate,
		tal_hexstr(ctx, &peer->remote.next_revocation_hash,
			   sizeof(peer->remote.next_revocation_hash)));

	errmsg = db_commit_transaction(peer);

	tal_free(ctx);
	return !errmsg;
}

void db_update_next_revocation_hash(struct peer *peer)
{
	const char *ctx = tal(peer, char);
	const char *peerid = pubkey_to_hexstr(ctx, peer->dstate->secpctx, peer->id);

	log_debug(peer->log, "%s(%s):%s", __func__, peerid,
		tal_hexstr(ctx, &peer->remote.next_revocation_hash,
			   sizeof(peer->remote.next_revocation_hash)));
	assert(peer->dstate->db->in_transaction);
	db_exec(__func__, peer->dstate, 
		"UPDATE their_visible_state SET next_revocation_hash=x'%s' WHERE peer=x'%s';",
		tal_hexstr(ctx, &peer->remote.next_revocation_hash,
			   sizeof(peer->remote.next_revocation_hash)),
		peerid);
	tal_free(ctx);
}

bool db_create_peer(struct peer *peer)
{
	const char *errmsg, *ctx = tal(peer, char);
	const char *peerid = pubkey_to_hexstr(ctx, peer->dstate->secpctx, peer->id);

	log_debug(peer->log, "%s(%s)", __func__, peerid);
	db_start_transaction(peer);
	db_exec(__func__, peer->dstate, 
		"INSERT INTO peers VALUES (x'%s', '%s', %s, %"PRIi64");",
		peerid,
		state_name(peer->state),
		sql_bool(peer->local.offer_anchor == CMD_OPEN_WITH_ANCHOR),
		peer->local.commit_fee_rate);

	db_exec(__func__, peer->dstate, 
		"INSERT INTO peer_secrets VALUES (x'%s', %s);",
		peerid, peer_secrets_for_db(ctx, peer));

	errmsg = db_commit_transaction(peer);
	tal_free(ctx);
	return !errmsg;
}

void db_start_transaction(struct peer *peer)
{
	const char *ctx = tal(peer, char);
	const char *peerid = pubkey_to_hexstr(ctx, peer->dstate->secpctx, peer->id);

	log_debug(peer->log, "%s(%s)", __func__, peerid);
	assert(!peer->dstate->db->in_transaction);
	peer->dstate->db->in_transaction = true;
	peer->dstate->db->err = tal_free(peer->dstate->db->err);

	db_exec(__func__, peer->dstate, "BEGIN IMMEDIATE;");
	tal_free(ctx);
}

void db_abort_transaction(struct peer *peer)
{
	const char *ctx = tal(peer, char);
	const char *peerid = pubkey_to_hexstr(ctx, peer->dstate->secpctx, peer->id);

	log_debug(peer->log, "%s(%s)", __func__, peerid);
	assert(peer->dstate->db->in_transaction);
	peer->dstate->db->in_transaction = false;
	db_exec(__func__, peer->dstate, "ROLLBACK;");
	tal_free(ctx);
}

const char *db_commit_transaction(struct peer *peer)
{
	const char *ctx = tal(peer, char);
	const char *peerid = pubkey_to_hexstr(ctx, peer->dstate->secpctx, peer->id);

	log_debug(peer->log, "%s(%s)", __func__, peerid);
	assert(peer->dstate->db->in_transaction);
	if (!db_exec(__func__, peer->dstate, "COMMIT;"))
		db_abort_transaction(peer);
	else
		peer->dstate->db->in_transaction = false;
	tal_free(ctx);

	return peer->dstate->db->err;
}

void db_new_htlc(struct peer *peer, const struct htlc *htlc)
{
	const char *ctx = tal(peer, char);
	const char *peerid = pubkey_to_hexstr(ctx, peer->dstate->secpctx, peer->id);

	log_debug(peer->log, "%s(%s)", __func__, peerid);
	assert(peer->dstate->db->in_transaction);

	if (htlc->src) {
		db_exec(__func__, peer->dstate, 
			"INSERT INTO htlcs VALUES"
			" (x'%s', %"PRIu64", '%s', %"PRIu64", %u, x'%s', NULL, x'%s', x'%s', %"PRIu64", NULL);",
			pubkey_to_hexstr(ctx, peer->dstate->secpctx, peer->id),
			htlc->id,
			htlc_state_name(htlc->state),
			htlc->msatoshi,
			abs_locktime_to_blocks(&htlc->expiry),
			tal_hexstr(ctx, &htlc->rhash, sizeof(htlc->rhash)),
			tal_hexstr(ctx, htlc->routing, tal_count(htlc->routing)),
			peerid,
			htlc->src->id);
	} else {
		db_exec(__func__, peer->dstate, 
			"INSERT INTO htlcs VALUES"
			" (x'%s', %"PRIu64", '%s', %"PRIu64", %u, x'%s', NULL, x'%s', NULL, NULL, NULL);",
			peerid,
			htlc->id,
			htlc_state_name(htlc->state),
			htlc->msatoshi,
			abs_locktime_to_blocks(&htlc->expiry),
			tal_hexstr(ctx, &htlc->rhash, sizeof(htlc->rhash)),
			tal_hexstr(ctx, htlc->routing, tal_count(htlc->routing)));
	}

	tal_free(ctx);
}

void db_new_feechange(struct peer *peer, const struct feechange *feechange)
{
	const char *ctx = tal(peer, char);
	const char *peerid = pubkey_to_hexstr(ctx, peer->dstate->secpctx, peer->id);

	log_debug(peer->log, "%s(%s)", __func__, peerid);
	assert(peer->dstate->db->in_transaction);

	db_exec(__func__, peer->dstate, 
		"INSERT INTO feechanges VALUES"
		" (x'%s', '%s', %"PRIu64");",
		peerid,
		feechange_state_name(feechange->state),
		feechange->fee_rate);

	tal_free(ctx);
}

void db_update_htlc_state(struct peer *peer, const struct htlc *htlc,
			  enum htlc_state oldstate)
{
	const char *ctx = tal(peer, char);
	const char *peerid = pubkey_to_hexstr(ctx, peer->dstate->secpctx, peer->id);

	log_debug(peer->log, "%s(%s): %"PRIu64" %s->%s", __func__, peerid,
		  htlc->id, htlc_state_name(oldstate),
		  htlc_state_name(htlc->state));
	assert(peer->dstate->db->in_transaction);
	db_exec(__func__, peer->dstate, 
		"UPDATE htlcs SET state='%s' WHERE peer=x'%s' AND id=%"PRIu64" AND state='%s';",
		htlc_state_name(htlc->state), peerid,
		htlc->id, htlc_state_name(oldstate));

	tal_free(ctx);
}

void db_update_feechange_state(struct peer *peer,
			       const struct feechange *f,
			       enum htlc_state oldstate)
{
	const char *ctx = tal(peer, char);
	const char *peerid = pubkey_to_hexstr(ctx, peer->dstate->secpctx, peer->id);

	log_debug(peer->log, "%s(%s): %s->%s", __func__, peerid,
		  feechange_state_name(oldstate),
		  feechange_state_name(f->state));
	assert(peer->dstate->db->in_transaction);
	db_exec(__func__, peer->dstate, 
		"UPDATE feechanges SET state='%s' WHERE peer=x'%s' AND state='%s';",
		feechange_state_name(f->state), peerid,
		feechange_state_name(oldstate));

	tal_free(ctx);
}

void db_update_state(struct peer *peer)
{
	const char *ctx = tal(peer, char);
	const char *peerid = pubkey_to_hexstr(ctx, peer->dstate->secpctx, peer->id);

	log_debug(peer->log, "%s(%s)", __func__, peerid);

	assert(peer->dstate->db->in_transaction);
	db_exec(__func__, peer->dstate, 
		"UPDATE peers SET state='%s' WHERE peer=x'%s';",
		state_name(peer->state), peerid);
	tal_free(ctx);
}

void db_htlc_fulfilled(struct peer *peer, const struct htlc *htlc)
{
	const char *ctx = tal(peer, char);
	const char *peerid = pubkey_to_hexstr(ctx, peer->dstate->secpctx, peer->id);

	log_debug(peer->log, "%s(%s)", __func__, peerid);

	assert(peer->dstate->db->in_transaction);
	db_exec(__func__, peer->dstate, 
		"UPDATE htlcs SET r=x'%s' WHERE peer=x'%s' AND id=%"PRIu64" AND state='%s';",
		tal_hexstr(ctx, htlc->r, sizeof(*htlc->r)),
		peerid,
		htlc->id,
		htlc_state_name(htlc->state));

	tal_free(ctx);
}

void db_htlc_failed(struct peer *peer, const struct htlc *htlc)
{
	const char *ctx = tal(peer, char);
	const char *peerid = pubkey_to_hexstr(ctx, peer->dstate->secpctx, peer->id);

	log_debug(peer->log, "%s(%s)", __func__, peerid);

	assert(peer->dstate->db->in_transaction);
	db_exec(__func__, peer->dstate, 
		"UPDATE htlcs SET fail=x'%s' WHERE peer=x'%s' AND id=%"PRIu64" AND state='%s';",
		tal_hexstr(ctx, htlc->fail, sizeof(*htlc->fail)),
		peerid,
		htlc->id,
		htlc_state_name(htlc->state));

	tal_free(ctx);
}

void db_new_commit_info(struct peer *peer, enum side side,
			const struct sha256 *prev_rhash)
{
	struct commit_info *ci;
	const char *ctx = tal(peer, char);
	const char *peerid = pubkey_to_hexstr(ctx, peer->dstate->secpctx, peer->id);

	log_debug(peer->log, "%s(%s)", __func__, peerid);

	assert(peer->dstate->db->in_transaction);
	if (side == LOCAL) {
		ci = peer->local.commit;
	} else {
		ci = peer->remote.commit;
	}

	db_exec(__func__, peer->dstate, "UPDATE commit_info SET commit_num=%"PRIu64", revocation_hash=x'%s', sig=%s, xmit_order=%"PRIi64", prev_revocation_hash=%s WHERE peer=x'%s' AND side='%s';",
		ci->commit_num,
		tal_hexstr(ctx, &ci->revocation_hash,
			   sizeof(ci->revocation_hash)),
		sig_to_sql(ctx, peer->dstate->secpctx, ci->sig),
		ci->order,
		sql_hex_or_null(ctx, prev_rhash, sizeof(*prev_rhash)),
		peerid, side_to_str(side));
	tal_free(ctx);
}

/* FIXME: Is this strictly necessary? */
void db_remove_their_prev_revocation_hash(struct peer *peer)
{
	const char *ctx = tal(peer, char);
	const char *peerid = pubkey_to_hexstr(ctx, peer->dstate->secpctx, peer->id);

	log_debug(peer->log, "%s(%s)", __func__, peerid);

	assert(peer->dstate->db->in_transaction);

	db_exec(__func__, peer->dstate, "UPDATE commit_info SET prev_revocation_hash=NULL WHERE peer=x'%s' AND side='REMOTE' and prev_revocation_hash IS NOT NULL;",
			 peerid);
	tal_free(ctx);
}
	

void db_save_shachain(struct peer *peer)
{
	const char *ctx = tal(peer, char);
	const char *peerid = pubkey_to_hexstr(ctx, peer->dstate->secpctx, peer->id);

	log_debug(peer->log, "%s(%s)", __func__, peerid);

	assert(peer->dstate->db->in_transaction);
	db_exec(__func__, peer->dstate, "UPDATE shachain SET shachain=x'%s' WHERE peer=x'%s';",
		linearize_shachain(ctx, &peer->their_preimages),
		peerid);
	tal_free(ctx);
}

void db_add_commit_map(struct peer *peer,
		       const struct sha256_double *txid, u64 commit_num)
{
	const char *ctx = tal(peer, char);
	const char *peerid = pubkey_to_hexstr(ctx, peer->dstate->secpctx, peer->id);

	log_debug(peer->log, "%s(%s),commit_num=%"PRIu64, __func__, peerid,
		  commit_num);

	assert(peer->dstate->db->in_transaction);
	db_exec(__func__, peer->dstate,
		"INSERT INTO their_commitments VALUES (x'%s', x'%s', %"PRIu64");",
		peerid,
		tal_hexstr(ctx, txid, sizeof(*txid)),
		commit_num);
	tal_free(ctx);
}

/* FIXME: Clean out old ones! */
bool db_add_peer_address(struct lightningd_state *dstate,
			 const struct peer_address *addr)
{
	const char *ctx = tal(dstate, char);
	bool ok;

	log_debug(dstate->base_log, "%s", __func__);

	assert(!dstate->db->in_transaction);
	ok = db_exec(__func__, dstate,
		     "INSERT OR REPLACE INTO peer_address VALUES (x'%s', x'%s');",
		     pubkey_to_hexstr(ctx, dstate->secpctx, &addr->id),
		     netaddr_to_hex(ctx, &addr->addr));

	tal_free(ctx);
	return ok;
}

void db_forget_peer(struct peer *peer)
{
	const char *ctx = tal(peer, char);
	const char *peerid = pubkey_to_hexstr(ctx, peer->dstate->secpctx, peer->id);
	size_t i;
	const char *const tables[] = { "anchors", "htlcs", "commit_info", "shachain", "their_visible_state", "their_commitments", "peer_secrets", "closing", "peers" };
	log_debug(peer->log, "%s(%s)", __func__, peerid);

	assert(peer->state == STATE_CLOSED);

	db_start_transaction(peer);

	for (i = 0; i < ARRAY_SIZE(tables); i++) {
		db_exec(__func__, peer->dstate,
			"DELETE from %s WHERE peer=x'%s';",
			tables[i], peerid);
	}
	if (db_commit_transaction(peer) != NULL)
		fatal("%s:db_commi_transaction failed", __func__);

	tal_free(ctx);
}

void db_begin_shutdown(struct peer *peer)
{
	const char *ctx = tal(peer, char);
	const char *peerid = pubkey_to_hexstr(ctx, peer->dstate->secpctx, peer->id);

	log_debug(peer->log, "%s(%s)", __func__, peerid);

	assert(peer->dstate->db->in_transaction);
	db_exec(__func__, peer->dstate,
		"INSERT INTO closing VALUES (x'%s', 0, 0, NULL, NULL, NULL, 0, 0, 0);",
		peerid);
	tal_free(ctx);
}

void db_set_our_closing_script(struct peer *peer)
{
	const char *ctx = tal(peer, char);
	const char *peerid = pubkey_to_hexstr(ctx, peer->dstate->secpctx, peer->id);

	log_debug(peer->log, "%s(%s)", __func__, peerid);

	assert(peer->dstate->db->in_transaction);
	db_exec(__func__, peer->dstate, "UPDATE closing SET our_script=x'%s',shutdown_order=%"PRIu64" WHERE peer=x'%s';",
		tal_hexstr(ctx, peer->closing.our_script,
			   tal_count(peer->closing.our_script)),
		peer->closing.shutdown_order,
		peerid);
	tal_free(ctx);
}

bool db_set_their_closing_script(struct peer *peer)
{
	const char *ctx = tal(peer, char);
	bool ok;
	const char *peerid = pubkey_to_hexstr(ctx, peer->dstate->secpctx, peer->id);

	log_debug(peer->log, "%s(%s)", __func__, peerid);

	assert(!peer->dstate->db->in_transaction);
	ok = db_exec(__func__, peer->dstate,
		     "UPDATE closing SET their_script=x'%s' WHERE peer=x'%s';",
		     tal_hexstr(ctx, peer->closing.their_script,
				tal_count(peer->closing.their_script)),
		     peerid);
	tal_free(ctx);
	return ok;
}

/* For first time, we are in transaction to make it atomic with peer->state
 * update.  Later calls are not. */
/* FIXME: make caller wrap in transaction. */
bool db_update_our_closing(struct peer *peer)
{
	const char *ctx = tal(peer, char);
	bool ok;
	const char *peerid = pubkey_to_hexstr(ctx, peer->dstate->secpctx, peer->id);

	log_debug(peer->log, "%s(%s)", __func__, peerid);

	ok = db_exec(__func__, peer->dstate,
		     "UPDATE closing SET our_fee=%"PRIu64", closing_order=%"PRIi64" WHERE peer=x'%s';",
		     peer->closing.our_fee,
		     peer->closing.closing_order,
		     peerid);
	tal_free(ctx);
	return ok;
}

bool db_update_their_closing(struct peer *peer)
{
	const char *ctx = tal(peer, char);
	bool ok;
	const char *peerid = pubkey_to_hexstr(ctx, peer->dstate->secpctx, peer->id);

	log_debug(peer->log, "%s(%s)", __func__, peerid);

	assert(!peer->dstate->db->in_transaction);
	ok = db_exec(__func__, peer->dstate,
		     "UPDATE closing SET their_fee=%"PRIu64", their_sig=x'%s', sigs_in=%u WHERE peer=x'%s';",
		     peer->closing.their_fee,
		     tal_hexstr(ctx, peer->closing.their_sig,
				tal_count(peer->closing.their_sig)),
		     peer->closing.sigs_in,
		     peerid);
	tal_free(ctx);
	return ok;
}

bool db_new_pay_command(struct lightningd_state *dstate,
			const struct sha256 *rhash,
			const struct pubkey *ids,
			u64 msatoshi,
			const struct htlc *htlc)
{
	const char *ctx = tal(dstate, char);
	bool ok;

	log_debug(dstate->base_log, "%s", __func__);
	log_add_struct(dstate->base_log, "(%s)", struct sha256, rhash);

	assert(!dstate->db->in_transaction);
	ok = db_exec(__func__, dstate,
		     "INSERT INTO pay VALUES (x'%s', %"PRIu64", x'%s', x'%s', %"PRIu64", NULL, NULL);",
		     tal_hexstr(ctx, rhash, sizeof(*rhash)),
		     msatoshi,
		     pubkeys_to_hex(ctx, dstate->secpctx, ids),
		     pubkey_to_hexstr(ctx, dstate->secpctx, htlc->peer->id),
		     htlc->id);
	tal_free(ctx);
	return ok;
}

bool db_replace_pay_command(struct lightningd_state *dstate,
			    const struct sha256 *rhash,
			    const struct pubkey *ids,
			    u64 msatoshi,
			    const struct htlc *htlc)
{
	const char *ctx = tal(dstate, char);
	bool ok;

	log_debug(dstate->base_log, "%s", __func__);
	log_add_struct(dstate->base_log, "(%s)", struct sha256, rhash);

	assert(!dstate->db->in_transaction);
	ok = db_exec(__func__, dstate,
		     "UPDATE pay SET msatoshi=%"PRIu64", ids=x'%s', htlc_peer=x'%s', htlc_id=%"PRIu64", r=NULL, fail=NULL WHERE rhash=x'%s';",
		     msatoshi,
		     pubkeys_to_hex(ctx, dstate->secpctx, ids),
		     pubkey_to_hexstr(ctx, dstate->secpctx, htlc->peer->id),
		     htlc->id,
		     tal_hexstr(ctx, rhash, sizeof(*rhash)));
	tal_free(ctx);
	return ok;
}

void db_complete_pay_command(struct lightningd_state *dstate,
			     const struct htlc *htlc)
{
	const char *ctx = tal(dstate, char);

	log_debug(dstate->base_log, "%s", __func__);
	log_add_struct(dstate->base_log, "(%s)", struct sha256, &htlc->rhash);

	assert(dstate->db->in_transaction);
	if (htlc->r)
		db_exec(__func__, dstate,
			"UPDATE pay SET r=x'%s', htlc_peer=NULL WHERE rhash=x'%s';",
			tal_hexstr(ctx, htlc->r, sizeof(*htlc->r)),
			tal_hexstr(ctx, &htlc->rhash, sizeof(htlc->rhash)));
	else
		db_exec(__func__, dstate,
			"UPDATE pay SET fail=x'%s', htlc_peer=NULL WHERE rhash=x'%s';",
			tal_hexstr(ctx, htlc->fail, tal_count(htlc->fail)),
			tal_hexstr(ctx, &htlc->rhash, sizeof(htlc->rhash)));

	tal_free(ctx);
}

bool db_new_invoice(struct lightningd_state *dstate,
		    u64 msatoshi,
		    const char *label,
		    const struct rval *r)
{
	const char *ctx = tal(dstate, char);
	bool ok;
	
	log_debug(dstate->base_log, "%s", __func__);

	assert(!dstate->db->in_transaction);

	/* Insert label as hex; suspect injection attacks. */
	ok = db_exec(__func__, dstate,
		     "INSERT INTO invoice VALUES (x'%s', %"PRIu64", x'%s', %s);",
		     tal_hexstr(ctx, r, sizeof(*r)),
		     msatoshi,
		     tal_hexstr(ctx, label, strlen(label)),
		     sql_bool(false));
	tal_free(ctx);
	return ok;
}

void db_resolve_invoice(struct lightningd_state *dstate,
			const char *label, u64 paid_num)
{
	const char *ctx = tal(dstate, char);

	log_debug(dstate->base_log, "%s", __func__);

	assert(dstate->db->in_transaction);
	
	db_exec(__func__, dstate, "UPDATE invoice SET paid_num=%"PRIu64" WHERE label=x'%s';",
		paid_num, tal_hexstr(ctx, label, strlen(label)));
	tal_free(ctx);
}

bool db_remove_invoice(struct lightningd_state *dstate,
		       const char *label)
{
	const char *ctx = tal(dstate, char);
	bool ok;

	log_debug(dstate->base_log, "%s", __func__);

	assert(!dstate->db->in_transaction);
	
	ok = db_exec(__func__, dstate, "DELETE FROM invoice WHERE label=x'%s';",
			 tal_hexstr(ctx, label, strlen(label)));
	tal_free(ctx);
	return ok;
}
