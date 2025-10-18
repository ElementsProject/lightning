#include "config.h"

#include <ccan/htable/htable_type.h>
#include <ccan/json_out/json_out.h>
#include <ccan/str/str.h>
#include <ccan/tal/str/str.h>
#include <common/memleak.h>
#include <common/node_id.h>
#include <plugins/bkpr/account.h>
#include <plugins/bkpr/bookkeeper.h>
#include <plugins/bkpr/chain_event.h>
#include <plugins/bkpr/recorder.h>
#include <plugins/libplugin.h>
#include <wire/wire.h>

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

static void towire_account(u8 **pptr, const struct account *account)
{
	towire_wirestring(pptr, account->name);
	if (account->peer_id) {
		towire_bool(pptr, true);
		towire_node_id(pptr, account->peer_id);
	} else
		towire_bool(pptr, false);
	towire_bool(pptr, account->we_opened);
	towire_bool(pptr, account->leased);
	towire_u64(pptr, account->onchain_resolved_block);
	if (account->open_event_db_id) {
		towire_bool(pptr, true);
		towire_u64(pptr, *account->open_event_db_id);
	} else
		towire_bool(pptr, false);
	if (account->closed_event_db_id) {
		towire_bool(pptr, true);
		towire_u64(pptr, *account->closed_event_db_id);
	} else
		towire_bool(pptr, false);
	towire_u32(pptr, account->closed_count);
}

static struct account *fromwire_account(struct accounts *accounts,
					const u8 **pptr, size_t *max)
{
	const char *name;
	struct account *account;

	name = fromwire_wirestring(NULL, pptr, max);
	if (!name)
		return NULL;

	account = new_account(accounts, take(name));
	if (fromwire_bool(pptr, max)) {
		account->peer_id = tal(account, struct node_id);
		fromwire_node_id(pptr, max, account->peer_id);
	} else
		account->peer_id = NULL;
	account->we_opened = fromwire_bool(pptr, max);
	account->leased = fromwire_bool(pptr, max);
	account->onchain_resolved_block = fromwire_u64(pptr, max);
	if (fromwire_bool(pptr, max)) {
		account->open_event_db_id = tal(account, u64);
		*account->open_event_db_id = fromwire_u64(pptr, max);
	} else
		account->open_event_db_id = NULL;
	if (fromwire_bool(pptr, max)) {
		account->closed_event_db_id = tal(account, u64);
		*account->closed_event_db_id = fromwire_u64(pptr, max);
	} else
		account->closed_event_db_id = NULL;
	account->closed_count = fromwire_u32(pptr, max);

	if (!pptr)
		return tal_free(account);
	return account;
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

static const char *ds_path(const tal_t *ctx, const char *acctname)
{
	return tal_fmt(ctx, "bookkeeper/account/%s", acctname);
}

static void account_datastore_set(struct command *cmd,
				  const struct account *acct,
				  const char *mode)
{
	const char *path = ds_path(tmpctx, acct->name);
	u8 *data = tal_arr(tmpctx, u8, 0);

	towire_account(&data, acct);
	jsonrpc_set_datastore_binary(cmd, path, data, tal_bytelen(data), mode,
				     ignore_datastore_reply, NULL, NULL);
}

void maybe_update_account(struct command *cmd,
			  struct account *acct,
			  struct chain_event *e,
			  const enum mvt_tag *tags,
			  u32 closed_count,
			  struct node_id *peer_id)
{
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
			case MVT_FOREIGN:
			case MVT_IGNORED:
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
	account_datastore_set(cmd, acct, "must-replace");
}

void account_update_closeheight(struct command *cmd,
				struct account *acct,
				u64 close_height)
{
	assert(close_height);
	acct->onchain_resolved_block = close_height;

	/* Ok, now we update the account with this blockheight */
	account_datastore_set(cmd, acct, "must-replace");
}

struct account *find_account(const struct bkpr *bkpr,
			     const char *name)
{
	return account_htable_get(bkpr->accounts->htable, name);
}

struct account *find_or_create_account(struct command *cmd,
				       struct bkpr *bkpr,
				       const char *name)
{
	struct account *a = find_account(bkpr, name);

	if (a)
		return a;

	a = new_account(bkpr->accounts, name);
	account_datastore_set(cmd, a, "must-create");
	return a;
}

static void memleak_scan_accounts_htable(struct htable *memtable,
					 struct account_htable *ht)
{
	memleak_scan_htable(memtable, &ht->raw);
}

struct accounts *init_accounts(const tal_t *ctx, struct command *init_cmd)
{
	struct json_out *params = json_out_new(tmpctx);
	const jsmntok_t *result;
	const char *buf;
	const jsmntok_t *datastore, *t;
	size_t i;
	struct accounts *accounts = tal(ctx, struct accounts);

	accounts->htable = tal(accounts, struct account_htable);
	account_htable_init(accounts->htable);
	memleak_add_helper(accounts->htable, memleak_scan_accounts_htable);

	json_out_start(params, NULL, '{');
	json_out_start(params, "key", '[');
	json_out_addstr(params, NULL, "bookkeeper");
	json_out_addstr(params, NULL, "account");
	json_out_end(params, ']');
	json_out_end(params, '}');
	result = jsonrpc_request_sync(tmpctx, init_cmd,
				      "listdatastore",
				      params, &buf);

	datastore = json_get_member(buf, result, "datastore");
	json_for_each_arr(i, t, datastore) {
		size_t datalen;
		const jsmntok_t *key, *datatok;
		const u8 *data;

		/* Key is an array, first two elements are bookkeeper, account */
		key = json_get_member(buf, t, "key") + 3;
		datatok = json_get_member(buf, t, "hex");
		/* In case someone creates a subdir? */
		if (!datatok)
			continue;

		data = json_tok_bin_from_hex(tmpctx, buf, datatok);
		datalen = tal_bytelen(data);

		if (fromwire_account(accounts, &data, &datalen) == NULL) {
			plugin_err(init_cmd->plugin,
				   "Invalid account %.*s in datastore",
				   json_tok_full_len(key),
				   json_tok_full(buf, key));
		}
	}
	return accounts;
}
