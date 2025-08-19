#include "config.h"

#include <ccan/htable/htable_type.h>
#include <ccan/str/str.h>
#include <ccan/tal/str/str.h>
#include <common/memleak.h>
#include <common/node_id.h>
#include <db/bindings.h>
#include <db/common.h>
#include <db/exec.h>
#include <db/utils.h>
#include <plugins/bkpr/account.h>
#include <plugins/bkpr/bookkeeper.h>
#include <plugins/bkpr/chain_event.h>
#include <plugins/bkpr/recorder.h>

static size_t hash_str(const char *str)
{
	return siphash24(siphash_seed(), str, strlen(str));
}

static const char *account_key(const struct account *account)
{
	return account->name;
}

static bool account_eq_name(const struct account *account,
			    const char *name)
{
	return streq(account->name, name);
}

HTABLE_DEFINE_NODUPS_TYPE(struct account,
			  account_key,
			  hash_str,
			  account_eq_name,
			  account_htable);

/* We keep accounts in memory, and for the moment, still in the db */
struct accounts {
	struct account_htable *htable;
};

static void destroy_account(struct account *a, struct accounts *accounts)
{
	account_htable_del(accounts->htable, a);
}

static struct account *new_account(struct accounts *accounts,
				   const char *name TAKES)
{
	struct account *a = tal(accounts, struct account);

	a->name = tal_strdup(a, name);
	a->peer_id = NULL;
	a->is_wallet = is_wallet_account(a->name);
	a->we_opened = false;
	a->leased = false;
	a->onchain_resolved_block = 0;
	a->open_event_db_id = NULL;
	a->closed_event_db_id = NULL;
	a->closed_count = 0;

	account_htable_add(accounts->htable, a);
	tal_add_destructor2(a, destroy_account, accounts);
	return a;
}

static struct account *stmt2account(struct accounts *accounts,
				    struct db_stmt *stmt)
{
	struct account *a;

	a = new_account(accounts, take(db_col_strdup(NULL, stmt, "name")));

	if (!db_col_is_null(stmt, "peer_id")) {
		a->peer_id = tal(a, struct node_id);
		db_col_node_id(stmt, "peer_id", a->peer_id);
	} else
		a->peer_id = NULL;
	a->is_wallet = db_col_int(stmt, "is_wallet") != 0;
	a->we_opened = db_col_int(stmt, "we_opened") != 0;
	a->leased = db_col_int(stmt, "leased") != 0;

	if (!db_col_is_null(stmt, "onchain_resolved_block")) {
		a->onchain_resolved_block = db_col_int(stmt, "onchain_resolved_block");
	} else
		a->onchain_resolved_block = 0;

	if (!db_col_is_null(stmt, "opened_event_id")) {
		a->open_event_db_id = tal(a, u64);
		*a->open_event_db_id = db_col_u64(stmt, "opened_event_id");
	} else
		a->open_event_db_id = NULL;

	if (!db_col_is_null(stmt, "closed_event_id")) {
		a->closed_event_db_id = tal(a, u64);
		*a->closed_event_db_id = db_col_u64(stmt, "closed_event_id");
	} else
		a->closed_event_db_id = NULL;

	a->closed_count = db_col_int(stmt, "closed_count");

	return a;
}

struct account **list_accounts(const tal_t *ctx, const struct bkpr *bkpr)
{
	struct account **results;
	struct account_htable_iter it;
	struct account *a;
	size_t i;

	results = tal_arr(ctx,
			  struct account *,
			  account_htable_count(bkpr->accounts->htable));
	for (i = 0, a = account_htable_first(bkpr->accounts->htable, &it);
	     a;
	     i++, a = account_htable_next(bkpr->accounts->htable, &it)) {
		results[i] = a;
	}

	return results;
}

static void account_db_add(struct db *db, struct account *acct)
{
	struct db_stmt *stmt;

	stmt = db_prepare_v2(db, SQL("INSERT INTO accounts"
				     " ("
				     "  name"
				     ", peer_id"
				     ", is_wallet"
				     ", we_opened"
				     ", leased"
				     ")"
				     " VALUES"
				     " (?, ?, ?, ?, ?);"));

	db_bind_text(stmt, acct->name);
	if (acct->peer_id)
		db_bind_node_id(stmt, acct->peer_id);
	else
		db_bind_null(stmt);
	db_bind_int(stmt, acct->is_wallet ? 1 : 0);
	db_bind_int(stmt, acct->we_opened ? 1 : 0);
	db_bind_int(stmt, acct->leased ? 1 : 0);

	db_exec_prepared_v2(take(stmt));
}

void maybe_update_account(struct bkpr *bkpr,
			  struct account *acct,
			  struct chain_event *e,
			  const enum mvt_tag *tags,
			  u32 closed_count,
			  struct node_id *peer_id)
{
	struct db_stmt *stmt;
	bool updated = false;

	for (size_t i = 0; i < tal_count(tags); i++) {
		switch (tags[i]) {
			case MVT_CHANNEL_PROPOSED:
			case MVT_CHANNEL_OPEN:
				if (!acct->open_event_db_id) {
					updated = true;
					acct->open_event_db_id = tal(acct, u64);
					*acct->open_event_db_id = e->db_id;
				}
				break;
			case MVT_CHANNEL_CLOSE:
				/* Splices dont count as closes */
				if (e->splice_close)
					break;
				updated = true;
				acct->closed_event_db_id = tal(acct, u64);
				*acct->closed_event_db_id = e->db_id;
				break;
			case MVT_LEASED:
				updated = true;
				acct->leased = true;
				break;
			case MVT_OPENER:
				updated = true;
				acct->we_opened = true;
				break;
			case MVT_DEPOSIT:
			case MVT_WITHDRAWAL:
			case MVT_PENALTY:
			case MVT_INVOICE:
			case MVT_ROUTED:
			case MVT_PUSHED:
			case MVT_CHANNEL_TO_US:
			case MVT_HTLC_TIMEOUT:
			case MVT_HTLC_FULFILL:
			case MVT_HTLC_TX:
			case MVT_TO_WALLET:
			case MVT_ANCHOR:
			case MVT_TO_THEM:
			case MVT_PENALIZED:
			case MVT_STOLEN:
			case MVT_TO_MINER:
			case MVT_LEASE_FEE:
			case MVT_STEALABLE:
			case MVT_SPLICE:
			case MVT_PENALTY_ADJ:
			case MVT_JOURNAL:
				/* Ignored */
				break;
		}
	}

	if (peer_id && !acct->peer_id) {
		updated = true;
		acct->peer_id = tal_dup(acct, struct node_id, peer_id);
	}

	if (!e->splice_close && closed_count > 0) {
		updated = true;
		acct->closed_count = closed_count;
	}

	/* Nothing new here */
	if (!updated)
		return;

	/* Otherwise, we update the account ! */
	stmt = db_prepare_v2(bkpr->db,
			     SQL("UPDATE accounts SET"
				 "  opened_event_id = ?"
				 ", closed_event_id = ?"
				 ", we_opened = ?"
				 ", leased = ?"
				 ", closed_count = ?"
				 ", peer_id = ?"
				 " WHERE"
				 " name = ?"));

	if (acct->open_event_db_id)
		db_bind_u64(stmt, *acct->open_event_db_id);
	else
		db_bind_null(stmt);

	if (acct->closed_event_db_id)
		db_bind_u64(stmt, *acct->closed_event_db_id);
	else
		db_bind_null(stmt);

	db_bind_int(stmt, acct->we_opened ? 1 : 0);
	db_bind_int(stmt, acct->leased ? 1 : 0);
	db_bind_int(stmt, acct->closed_count);
	if (acct->peer_id)
		db_bind_node_id(stmt, acct->peer_id);
	else
		db_bind_null(stmt);

	db_bind_text(stmt, acct->name);

	db_exec_prepared_v2(take(stmt));
}

void account_update_closeheight(struct bkpr *bkpr,
				struct account *acct,
				u64 close_height)
{
	struct db_stmt *stmt;

	assert(close_height);
	acct->onchain_resolved_block = close_height;

	/* Ok, now we update the account with this blockheight */
	stmt = db_prepare_v2(bkpr->db, SQL("UPDATE accounts SET"
					   "  onchain_resolved_block = ?"
					   " WHERE"
					   " name = ?"));
	db_bind_int(stmt, acct->onchain_resolved_block);
	db_bind_text(stmt, acct->name);
	db_exec_prepared_v2(take(stmt));
}

struct account *find_account(const struct bkpr *bkpr,
			     const char *name)
{
	return account_htable_get(bkpr->accounts->htable, name);
}

struct account *find_or_create_account(struct bkpr *bkpr,
				       const char *name)
{
	struct account *a = find_account(bkpr, name);

	if (a)
		return a;

	a = new_account(bkpr->accounts, name);
	account_db_add(bkpr->db, a);
	return a;
}

static void memleak_scan_accounts_htable(struct htable *memtable,
					 struct account_htable *ht)
{
	memleak_scan_htable(memtable, &ht->raw);
}

struct accounts *init_accounts(const tal_t *ctx, struct db *db)
{
	struct accounts *accounts = tal(ctx, struct accounts);
	struct db_stmt *stmt;

	accounts->htable = tal(accounts, struct account_htable);
	account_htable_init(accounts->htable);
	memleak_add_helper(accounts->htable, memleak_scan_accounts_htable);

	db_begin_transaction(db);
	stmt = db_prepare_v2(db,
			     SQL("SELECT"
				 " name"
				 ", peer_id"
				 ", opened_event_id"
				 ", closed_event_id"
				 ", onchain_resolved_block"
				 ", is_wallet"
				 ", we_opened"
				 ", leased"
				 ", closed_count"
				 " FROM accounts"));
	db_query_prepared(stmt);

	while (db_step(stmt))
		stmt2account(accounts, stmt);

	tal_free(stmt);
	db_commit_transaction(db);

	return accounts;
}
