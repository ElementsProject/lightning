#include "config.h"

#include <ccan/htable/htable_type.h>
#include <ccan/json_out/json_out.h>
#include <ccan/str/hex/hex.h>
#include <ccan/str/str.h>
#include <ccan/tal/str/str.h>
#include <common/memleak.h>
#include <common/utils.h>
#include <inttypes.h>
#include <plugins/bkpr/blockheights.h>
#include <plugins/bkpr/bookkeeper.h>
#include <plugins/libplugin.h>

struct blockheight_entry {
	struct bitcoin_txid txid;
	u32 height;
};

static size_t hash_txid(const struct bitcoin_txid *txid)
{
	return siphash24(siphash_seed(), txid->shad.sha.u.u8,
			 sizeof(txid->shad.sha.u.u8));
}

static const struct bitcoin_txid *
blockheight_key(const struct blockheight_entry *e)
{
	return &e->txid;
}

static bool blockheight_key_eq(const struct blockheight_entry *e,
                               const struct bitcoin_txid *k)
{
	return bitcoin_txid_eq(&e->txid, k);
}

HTABLE_DEFINE_NODUPS_TYPE(struct blockheight_entry,
			  blockheight_key,
			  hash_txid,
			  blockheight_key_eq,
			  blockheight_htable);

struct blockheights {
	struct blockheight_htable *map;
};

static void memleak_scan_blockheight_htable(struct htable *memtable,
					    struct blockheight_htable *ht)
{
	memleak_scan_htable(memtable, &ht->raw);
}

static const char *ds_blockheight_path(const tal_t *ctx,
				       const struct bitcoin_txid *txid)
{
	/* Keys like: bookkeeper/blockheights/<txid> */
	return tal_fmt(ctx, "bookkeeper/blockheights/%s",
		       fmt_bitcoin_txid(tmpctx, txid));
}

void add_blockheight(struct command *cmd,
		     struct bkpr *bkpr,
		     const struct bitcoin_txid *txid,
		     u32 blockheight)
{
	struct blockheights *bh = bkpr->blockheights;
	struct blockheight_entry *e;
	be32 be_blockheight;
	const char *path = ds_blockheight_path(tmpctx, txid);

	/* Update in-memory map (replace or insert) */
	e = blockheight_htable_get(bh->map, txid);
	if (e) {
		e->height = blockheight;
	} else {
		e = tal(bh->map, struct blockheight_entry);
		e->txid = *txid;
		e->height = blockheight;
		blockheight_htable_add(bh->map, e);
	}

	be_blockheight = cpu_to_be32(blockheight);
	jsonrpc_set_datastore_binary(cmd, path,
				     &be_blockheight, sizeof(be_blockheight),
				     "create-or-replace",
				     ignore_datastore_reply, NULL, NULL);
}

u32 find_blockheight(const struct bkpr *bkpr,
		     const struct bitcoin_txid *txid)
{
	const struct blockheight_entry *e;

	e = blockheight_htable_get(bkpr->blockheights->map, txid);
	return e ? e->height : 0;
}

static bool json_hex_to_be32(const char *buffer, const jsmntok_t *tok,
			     be32 *val)
{
	return hex_decode(buffer + tok->start, tok->end - tok->start,
			  val, sizeof(*val));
}

struct blockheights *init_blockheights(const tal_t *ctx,
				       struct command *init_cmd)
{
	struct json_out *params = json_out_new(tmpctx);
	const jsmntok_t *result;
	const char *buf;
	const jsmntok_t *datastore, *t;
	size_t i;

	struct blockheights *bh = tal(ctx, struct blockheights);
	bh->map = tal(bh, struct blockheight_htable);
	blockheight_htable_init(bh->map);
	memleak_add_helper(bh->map, memleak_scan_blockheight_htable);

	/* Query all keys under bookkeeper/blockheights */
	json_out_start(params, NULL, '{');
	json_out_start(params, "key", '[');
	json_out_addstr(params, NULL, "bookkeeper");
	json_out_addstr(params, NULL, "blockheights");
	json_out_end(params, ']');
	json_out_end(params, '}');

	result = jsonrpc_request_sync(tmpctx, init_cmd,
	                              "listdatastore", params, &buf);

	datastore = json_get_member(buf, result, "datastore");
	json_for_each_arr(i, t, datastore) {
		const jsmntok_t *keytok = json_get_member(buf, t, "key");
		const jsmntok_t *hextok = json_get_member(buf, t, "hex");
		struct blockheight_entry *e;
		struct bitcoin_txid txid;
		be32 be_blockheight;

		/* Expect: ["bookkeeper","blockheights","<txid>"] */
		if (keytok->size != 3)
			goto weird;

		if (!json_to_txid(buf, keytok + 2, &txid))
			goto weird;
		if (!json_hex_to_be32(buf, hextok, &be_blockheight))
			goto weird;

		/* Insert into map */
		e = tal(bh->map, struct blockheight_entry);
		e->txid = txid;
		e->height = be32_to_cpu(be_blockheight);
		blockheight_htable_add(bh->map, e);
		continue;

weird:
		plugin_log(init_cmd->plugin, LOG_BROKEN,
		           "Unparsable blockheight datastore entry: %.*s",
		           json_tok_full_len(t), json_tok_full(buf, t));
	}

	return bh;
}
