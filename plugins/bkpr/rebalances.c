#include "config.h"

#include <ccan/htable/htable_type.h>
#include <ccan/json_out/json_out.h>
#include <ccan/str/str.h>
#include <ccan/tal/str/str.h>
#include <common/coin_mvt.h>
#include <common/memleak.h>
#include <common/node_id.h>
#include <common/utils.h>
#include <plugins/bkpr/bookkeeper.h>
#include <plugins/bkpr/rebalances.h>
#include <plugins/libplugin.h>
#include <wire/wire.h>

/* Hash table contains a pair of these: [a, b] and [b, a] */
struct rebalance_pair {
	u64 pair[2];
};

static size_t rebalance_hash(u64 key)
{
	return siphash24(siphash_seed(), &key, sizeof(key));
}

static u64 rebalance_key(const struct rebalance_pair *p)
{
	return p->pair[0];
}

static bool rebalance_key_eq(const struct rebalance_pair *p, u64 key)
{
	return p->pair[0] == key;
}

HTABLE_DEFINE_NODUPS_TYPE(struct rebalance_pair,
			  rebalance_key,
			  rebalance_hash,
			  rebalance_key_eq,
			  rebalance_htable);

struct rebalances {
	struct rebalance_htable *pairs;
};

static void new_rebalance_pair(struct rebalances *r,
			       u64 created_index1, u64 created_index2)
{
	struct rebalance_pair *p1, *p2;

	p1 = tal(r->pairs, struct rebalance_pair);
	p1->pair[0] = created_index1;
	p1->pair[1] = created_index2;
	rebalance_htable_add(r->pairs, p1);

	p2 = tal(r->pairs, struct rebalance_pair);
	p2->pair[0] = created_index2;
	p2->pair[1] = created_index1;
	rebalance_htable_add(r->pairs, p2);
}

static const char *ds_rebalance_path(const tal_t *ctx, u64 id1, u64 id2)
{
	u64 lesser, greater;
	if (id1 < id2) {
		lesser = id1;
		greater = id2;
	} else {
		lesser = id2;
		greater = id1;
	}
	return tal_fmt(ctx, "bookkeeper/rebalances/%"PRIu64"-%"PRIu64,
		       lesser, greater);
}

void add_rebalance_pair(struct command *cmd,
			struct bkpr *bkpr,
			u64 created_index1, u64 created_index2)
{
	const char *path;
	new_rebalance_pair(bkpr->rebalances, created_index1, created_index2);

	path = ds_rebalance_path(tmpctx, created_index1, created_index2);
	/* Contents are ignored: key is the data */
	jsonrpc_set_datastore_string(cmd, path, "", "must-create",
				     ignore_datastore_reply, NULL, NULL);
}

const u64 *find_rebalance(const struct bkpr *bkpr, u64 created_index)
{
	const struct rebalance_pair *p;

	p = rebalance_htable_get(bkpr->rebalances->pairs, created_index);
	return p ? &p->pair[1] : NULL;
}

static void memleak_scan_rebalance_htable(struct htable *memtable,
					  struct rebalance_htable *ht)
{
	memleak_scan_htable(memtable, &ht->raw);
}

struct rebalances *init_rebalances(const tal_t *ctx,
				   struct command *init_cmd)
{
	struct json_out *params = json_out_new(tmpctx);
	const jsmntok_t *result;
	const char *buf;
	const jsmntok_t *datastore, *t;
	size_t i;

	struct rebalances *r = tal(ctx, struct rebalances);
	r->pairs = tal(r, struct rebalance_htable);
	rebalance_htable_init(r->pairs);
	memleak_add_helper(r->pairs, memleak_scan_rebalance_htable);

	/* Query all keys under bookkeeper/rebalances */
	json_out_start(params, NULL, '{');
	json_out_start(params, "key", '[');
	json_out_addstr(params, NULL, "bookkeeper");
	json_out_addstr(params, NULL, "rebalances");
	json_out_end(params, ']');
	json_out_end(params, '}');

	result = jsonrpc_request_sync(tmpctx, init_cmd,
				      "listdatastore", params, &buf);

	datastore = json_get_member(buf, result, "datastore");
	json_for_each_arr(i, t, datastore) {
		const jsmntok_t *keytok = json_get_member(buf, t, "key");
		jsmntok_t lessertok, greatertok;
		u64 lesser, greater;

		if (keytok->size != 3)
			goto weird;

		/* key = ["bookkeeper", "rebalances", "<lesser>-<greater>"] */
		if (!split_tok(buf, keytok + 3, '-', &lessertok, &greatertok))
			goto weird;

		if (!json_to_u64(buf, &lessertok, &lesser)
		    || !json_to_u64(buf, &greatertok, &greater))
			goto weird;

		new_rebalance_pair(r, lesser, greater);
		continue;

	weird:
		plugin_log(init_cmd->plugin, LOG_BROKEN, "Unparsable datastore %.*s",
			   json_tok_full_len(keytok),
			   json_tok_full(buf, keytok));
	}

	return r;
}
