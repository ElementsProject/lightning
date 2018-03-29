#include "nodestats.h"
#include <bitcoin/pubkey.h>
#include <ccan/tal/str/str.h>
#include <ccan/time/time.h>
#include <common/utils.h>
#include <lightningd/log.h>
#include <wallet/db.h>
#include <wallet/wallet.h>

struct nodestats {
	struct db *db;
	struct log *log;
};

struct nodestats *
nodestats_new(const tal_t *ctx,
	      struct db *db,
	      struct log *log)
{
	struct nodestats *nodestats = tal(ctx, struct nodestats);

	nodestats->db = db;
	nodestats->log = log;

	return nodestats;
}
/* FIXME: pruning of very old nodes */

/* Create an entry for the node if needed. */
static void
nodestats_create(struct nodestats *nodestats,
		 const struct pubkey *pubkey)
{
	sqlite3_stmt *stmt;
	u64 now = time_now().ts.tv_sec;

	stmt = db_prepare(nodestats->db,
			  "INSERT OR IGNORE INTO node_statistics"
			  "          ( nodeid"
			  "          , time_first_seen, time_last_seen"
			  "          )"
			  "   VALUES ( ?"
			  "          , ?, ?"
			  "          );");
	sqlite3_bind_pubkey(stmt, 1, pubkey);
	sqlite3_bind_int64(stmt, 2, now);
	sqlite3_bind_int64(stmt, 3, now);
	db_exec_prepared(nodestats->db, stmt);
}

/* Inform node statistics that we have seen this node. */
void
nodestats_mark_seen(struct nodestats *nodestats,
		    const struct pubkey *pubkey)
{
	sqlite3_stmt *stmt;
	u64 now;

	nodestats_create(nodestats, pubkey);

	now = time_now().ts.tv_sec;

	stmt = db_prepare(nodestats->db,
			  "UPDATE node_statistics"
			  "   SET time_last_seen = ?"
			  " WHERE nodeid = ?;");
	sqlite3_bind_int64(stmt, 1, now);
	sqlite3_bind_pubkey(stmt, 2, pubkey);
	db_exec_prepared(nodestats->db, stmt);
}

/* Increment counters. */
static void
nodestats_incr(struct nodestats *nodestats,
	       const struct pubkey *pubkey,
	       const char *counter)
{
	sqlite3_stmt *stmt;

	nodestats_create(nodestats, pubkey);

	stmt = db_prepare(nodestats->db,
			  tal_fmt(tmpctx,
				  "UPDATE node_statistics"
				  "   SET %s = %s + 1"
				  " WHERE nodeid = ?;",
				  counter, counter));
	sqlite3_bind_pubkey(stmt, 1, pubkey);
	db_exec_prepared(nodestats->db, stmt);
}
void
nodestats_incr_forwarding_failures(struct nodestats *ns, const struct pubkey *n)
{
	nodestats_incr(ns, n, "forwarding_failures");
}
void
nodestats_incr_connect_failures(struct nodestats *ns, const struct pubkey *n)
{
	nodestats_incr(ns, n, "connect_failures");
}
void
nodestats_incr_channel_failures(struct nodestats *ns, const struct pubkey *n)
{
	nodestats_incr(ns, n, "channel_failures");
}

u64
nodestats_iterate(struct nodestats *nodestats, u64 previndex)
{
	sqlite3_stmt *stmt;
	u64 index;

	stmt = db_prepare(nodestats->db,
			  "SELECT id"
			  "  FROM node_statistics"
			  " WHERE id > ?"
			  " ORDER BY id ASC LIMIT 1;");
	sqlite3_bind_int64(stmt, 1, previndex);

	if (sqlite3_step(stmt) == SQLITE_ROW)
		index = sqlite3_column_int64(stmt, 0);
	else
		index = 0;

	sqlite3_finalize(stmt);

	return index;
}

/* Get node statistics details */
#define nodestats_columns \
	"id, nodeid, time_first_seen, time_last_seen, " \
	"forwarding_failures, connect_failures, channel_failures"

static void
nodestats_stmt2detail(sqlite3_stmt *stmt, struct nodestats_detail *detail)
{
	detail->index = sqlite3_column_int64(stmt, 0);
	sqlite3_column_pubkey(stmt, 1, &detail->nodeid);
	detail->time_first_seen = sqlite3_column_int64(stmt, 2);
	detail->time_last_seen = sqlite3_column_int64(stmt, 3);
	detail->forwarding_failures = sqlite3_column_int(stmt, 4);
	detail->connect_failures = sqlite3_column_int(stmt, 5);
	detail->channel_failures = sqlite3_column_int(stmt, 6);
}

bool
nodestats_get_by_index(struct nodestats *nodestats,
		       struct nodestats_detail *detail,
		       u64 index)
{
	sqlite3_stmt *stmt;
	bool res;

	stmt = db_prepare(nodestats->db,
			  "SELECT " nodestats_columns
			  "  FROM node_statistics"
			  " WHERE id = ?;");
	sqlite3_bind_int64(stmt, 1, index);
	if (sqlite3_step(stmt) == SQLITE_ROW) {
		nodestats_stmt2detail(stmt, detail);
		res = true;
	} else
		res = false;

	sqlite3_finalize(stmt);

	return res;
}
bool
nodestats_get_by_pubkey(struct nodestats *nodestats,
		       struct nodestats_detail *detail,
		       const struct pubkey *pubkey)
{
	sqlite3_stmt *stmt;
	bool res;

	stmt = db_prepare(nodestats->db,
			  "SELECT " nodestats_columns
			  "  FROM node_statistics"
			  " WHERE nodeid = ?;");
	sqlite3_bind_pubkey(stmt, 1, pubkey);
	if (sqlite3_step(stmt) == SQLITE_ROW) {
		nodestats_stmt2detail(stmt, detail);
		res = true;
	} else
		res = false;

	sqlite3_finalize(stmt);

	return res;
}
