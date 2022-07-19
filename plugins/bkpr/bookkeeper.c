#include "config.h"
#include <ccan/array_size/array_size.h>
#include <common/coin_mvt.h>
#include <common/json_param.h>
#include <common/memleak.h>
#include <common/node_id.h>
#include <common/type_to_string.h>
#include <plugins/bkpr/db.h>
#include <plugins/libplugin.h>

#define CHAIN_MOVE "chain_mvt"
#define CHANNEL_MOVE "channel_mvt"

/* The database that we store all the accounting data in */
static struct db *db ;

// FIXME: make relative to directory we're loaded into
static char *db_dsn = "sqlite3://accounts.sqlite3";

static struct command_result *json_list_balances(struct command *cmd,
						 const char *buf,
						 const jsmntok_t *params)
{
	struct json_stream *res;

	if (!param(cmd, buf, params, NULL))
		return command_param_failed();

	res = jsonrpc_stream_success(cmd);
	return command_finished(cmd, res);
}

struct account_snap {
	char *name;
	struct amount_msat amt;
	char *coin_type;
};

static struct command_result *json_balance_snapshot(struct command *cmd,
						    const char *buf,
						    const jsmntok_t *params)
{
	const char *err;
	size_t i;
	struct node_id node_id;
	u32 blockheight;
	u64 timestamp;
	struct account_snap *snaps;
	const jsmntok_t *accounts_tok, *acct_tok,
	      *snap_tok = json_get_member(buf, params, "balance_snapshot");

	if (snap_tok == NULL || snap_tok->type != JSMN_OBJECT)
		plugin_err(cmd->plugin,
			   "`balance_snapshot` payload did not scan %s: %.*s",
			   "no 'balance_snapshot'", json_tok_full_len(params),
			   json_tok_full(buf, params));

	err = json_scan(cmd, buf, snap_tok,
			"{node_id:%"
			",blockheight:%"
			",timestamp:%}",
			JSON_SCAN(json_to_node_id, &node_id),
			JSON_SCAN(json_to_number, &blockheight),
			JSON_SCAN(json_to_u64, &timestamp));

	if (err)
		plugin_err(cmd->plugin,
			   "`balance_snapshot` payload did not scan %s: %.*s",
			   err, json_tok_full_len(params),
			   json_tok_full(buf, params));

	plugin_log(cmd->plugin, LOG_DBG, "balances for node %s at %d"
		   " (%"PRIu64")",
		   type_to_string(tmpctx, struct node_id, &node_id),
		   blockheight, timestamp);

	accounts_tok = json_get_member(buf, snap_tok, "accounts");
	if (accounts_tok == NULL || accounts_tok->type != JSMN_ARRAY)
		plugin_err(cmd->plugin,
			   "`balance_snapshot` payload did not scan %s: %.*s",
			   "no 'balance_snapshot.accounts'",
			   json_tok_full_len(params),
			   json_tok_full(buf, params));

	snaps = tal_arr(cmd, struct account_snap, accounts_tok->size);
	json_for_each_arr(i, acct_tok, accounts_tok) {
		struct account_snap s = snaps[i];
		err = json_scan(cmd, buf, acct_tok,
				"{account_id:%"
				",balance_msat:%"
				",coin_type:%}",
				JSON_SCAN_TAL(tmpctx, json_strdup, &s.name),
				JSON_SCAN(json_to_msat, &s.amt),
				JSON_SCAN_TAL(tmpctx, json_strdup,
					      &s.coin_type));
		if (err)
			plugin_err(cmd->plugin,
				   "`balance_snapshot` payload did not"
				   " scan %s: %.*s",
				   err, json_tok_full_len(params),
				   json_tok_full(buf, params));

		plugin_log(cmd->plugin, LOG_DBG, "account %s has balance %s",
			   s.name,
			   type_to_string(tmpctx, struct amount_msat, &s.amt));
	}

	// FIXME: check balances are ok!

	return notification_handled(cmd);
}

static const char *parse_and_log_chain_move(struct command *cmd,
					    const char *buf,
					    const jsmntok_t *params,
					    const struct node_id *node_id,
					    const char *acct_name STEALS,
					    const struct amount_msat credit,
					    const struct amount_msat debit,
					    const char *coin_type STEALS,
					    const u32 timestamp,
					    const enum mvt_tag *tags)
{
	struct bitcoin_outpoint outpt;
	static struct amount_msat output_value;
	struct sha256 *payment_hash = tal(tmpctx, struct sha256);
	struct bitcoin_txid *spending_txid = tal(tmpctx, struct bitcoin_txid);
	u32 blockheight;
	const char *err;

	/* Fields we expect on *every* chain movement */
	err = json_scan(tmpctx, buf, params,
			"{coin_movement:"
			"{utxo_txid:%"
			",vout:%"
			",output_msat:%"
			",blockheight:%"
			"}}",
			JSON_SCAN(json_to_txid, &outpt.txid),
			JSON_SCAN(json_to_number, &outpt.n),
			JSON_SCAN(json_to_msat, &output_value),
			JSON_SCAN(json_to_number, &blockheight));

	if (err)
		return err;

	/* Now try to get out the optional parts */
	err = json_scan(tmpctx, buf, params,
			"{coin_movement:"
			"{txid:%"
			"}}",
			JSON_SCAN(json_to_txid, spending_txid));

	if (err)
		spending_txid = tal_free(spending_txid);

	/* Now try to get out the optional parts */
	err = json_scan(tmpctx, buf, params,
			"{coin_movement:"
			"{payment_hash:%"
			"}}",
			JSON_SCAN(json_to_sha256, payment_hash));

	if (err)
		payment_hash = tal_free(payment_hash);

	// FIXME: enter into database
	return NULL;
}

static const char *parse_and_log_channel_move(struct command *cmd,
					      const char *buf,
					      const jsmntok_t *params,
					      const struct node_id *node_id,
					      const char *acct_name STEALS,
					      const struct amount_msat credit,
					      const struct amount_msat debit,
					      const char *coin_type STEALS,
					      const u32 timestamp,
					      const enum mvt_tag *tags)
{
	struct sha256 payment_hash;
	u64 part_id;
	struct amount_msat fees;

	const char *err;

	err = json_scan(tmpctx, buf, params,
			"{coin_movement:"
			"{payment_hash:%"
			",fees:%"
			"}}",
			JSON_SCAN(json_to_sha256, &payment_hash),
			JSON_SCAN(json_to_msat, &fees));

	if (err)
		return err;

	err = json_scan(tmpctx, buf, params,
			"{coin_movement:"
			"{part_id:%}}",
			JSON_SCAN(json_to_u64, &part_id));
	if (err)
		part_id = 0;

	// FIXME: enter into database?

	return NULL;
}

static char *parse_tags(const tal_t *ctx,
			const char *buf,
			const jsmntok_t *tok,
			enum mvt_tag **tags)
{
	size_t i;
	const jsmntok_t *tag_tok,
	      *tags_tok = json_get_member(buf, tok, "tags");

	if (tags_tok == NULL || tags_tok->type != JSMN_ARRAY)
		return "Invalid/missing 'tags' field";

	*tags = tal_arr(ctx, enum mvt_tag, tags_tok->size);
	json_for_each_arr(i, tag_tok, tags_tok) {
		if (!json_to_coin_mvt_tag(buf, tag_tok, &(*tags)[i]))
			return "Unable to parse 'tags'";
	}

	return NULL;
}

static struct command_result * json_coin_moved(struct command *cmd,
					       const char *buf,
					       const jsmntok_t *params)
{
	const char *err, *mvt_type, *acct_name, *coin_type;
	struct node_id node_id;
	u32 version;
	u64 timestamp;
	struct amount_msat credit, debit;
	enum mvt_tag *tags;

	err = json_scan(tmpctx, buf, params,
			"{coin_movement:"
			"{version:%"
			",node_id:%"
			",type:%"
			",account_id:%"
			",credit_msat:%"
			",debit_msat:%"
			",coin_type:%"
			",timestamp:%"
			"}}",
			JSON_SCAN(json_to_number, &version),
			JSON_SCAN(json_to_node_id, &node_id),
			JSON_SCAN_TAL(tmpctx, json_strdup, &mvt_type),
			JSON_SCAN_TAL(tmpctx, json_strdup, &acct_name),
			JSON_SCAN(json_to_msat, &credit),
			JSON_SCAN(json_to_msat, &debit),
			JSON_SCAN_TAL(tmpctx, json_strdup, &coin_type),
			JSON_SCAN(json_to_u64, &timestamp));

	if (err)
		plugin_err(cmd->plugin,
			   "`coin_movement` payload did not scan %s: %.*s",
			   err, json_tok_full_len(params),
			   json_tok_full(buf, params));

	err = parse_tags(cmd, buf,
			 json_get_member(buf, params, "coin_movement"),
			 &tags);
	if (err)
		plugin_err(cmd->plugin,
			   "`coin_movement` payload did not scan %s: %.*s",
			   err, json_tok_full_len(params),
			   json_tok_full(buf, params));

	/* We expect version 2 of coin movements */
	assert(version == 2);

	plugin_log(cmd->plugin, LOG_DBG, "coin_move %d %s -%s %s %"PRIu64,
		   version,
		   type_to_string(tmpctx, struct amount_msat, &credit),
		   type_to_string(tmpctx, struct amount_msat, &debit),
		   mvt_type, timestamp);

	if (streq(mvt_type, CHAIN_MOVE))
		err = parse_and_log_chain_move(cmd, buf, params, &node_id,
					       acct_name, credit, debit,
					       coin_type, timestamp,
					       tags);
	else {
		assert(streq(mvt_type, CHANNEL_MOVE));
		err = parse_and_log_channel_move(cmd, buf, params, &node_id,
						 acct_name, credit, debit,
						 coin_type, timestamp,
						 tags);
	}

	if (err)
		plugin_err(cmd->plugin,
			   "`coin_movement` payload did not scan %s: %.*s",
			   err, json_tok_full_len(params),
			   json_tok_full(buf, params));

	return notification_handled(cmd);
}

const struct plugin_notification notifs[] = {
	{
		"coin_movement",
		json_coin_moved,
	},
	{
		"balance_snapshot",
		json_balance_snapshot,
	}
};

static const struct plugin_command commands[] = {
	{
		"listbalances",
		"bookkeeping",
		"List current account balances",
		"List of current accounts and their balances",
		json_list_balances
	},
};

static const char *init(struct plugin *p, const char *b, const jsmntok_t *t)
{
	// FIXME: pass in database DSN as an option??
	db = notleak(db_setup(p, p, db_dsn));

	return NULL;
}

int main(int argc, char *argv[])
{
	setup_locale();

	plugin_main(argv, init, PLUGIN_STATIC, true, NULL,
		    commands, ARRAY_SIZE(commands),
		    notifs, ARRAY_SIZE(notifs),
		    NULL, 0,
		    NULL, 0,
		    NULL);
	return 0;
}
