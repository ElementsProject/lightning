#include "config.h"
#include <ccan/crypto/siphash24/siphash24.h>
#include <ccan/mem/mem.h>
#include <plugins/bwatch/bwatch_store.h>

const struct scriptpubkey *scriptpubkey_watch_keyof(const struct watch *w)
{
	assert(w->type == WATCH_SCRIPTPUBKEY);
	return &w->key.scriptpubkey;
}

size_t scriptpubkey_hash(const struct scriptpubkey *scriptpubkey)
{
	return siphash24(siphash_seed(), scriptpubkey->script, scriptpubkey->len);
}

bool scriptpubkey_watch_eq(const struct watch *w, const struct scriptpubkey *scriptpubkey)
{
	return w->key.scriptpubkey.len == scriptpubkey->len &&
	       memeq(w->key.scriptpubkey.script, scriptpubkey->len,
		     scriptpubkey->script, scriptpubkey->len);
}

const struct bitcoin_outpoint *outpoint_watch_keyof(const struct watch *w)
{
	assert(w->type == WATCH_OUTPOINT);
	return &w->key.outpoint;
}

size_t outpoint_hash(const struct bitcoin_outpoint *outpoint)
{
	size_t h1 = siphash24(siphash_seed(), &outpoint->txid, sizeof(outpoint->txid));
	size_t h2 = siphash24(siphash_seed(), &outpoint->n, sizeof(outpoint->n));
	return h1 ^ h2;
}

bool outpoint_watch_eq(const struct watch *w, const struct bitcoin_outpoint *outpoint)
{
	return bitcoin_outpoint_eq(&w->key.outpoint, outpoint);
}

const struct short_channel_id *scid_watch_keyof(const struct watch *w)
{
	assert(w->type == WATCH_SCID);
	return &w->key.scid;
}

size_t scid_hash(const struct short_channel_id *scid)
{
	return siphash24(siphash_seed(), scid, sizeof(*scid));
}

bool scid_watch_eq(const struct watch *w, const struct short_channel_id *scid)
{
	return short_channel_id_eq(w->key.scid, *scid);
}

const u32 *blockdepth_watch_keyof(const struct watch *w)
{
	assert(w->type == WATCH_BLOCKDEPTH);
	return &w->start_block;
}

size_t u32_hash(const u32 *height)
{
	return siphash24(siphash_seed(), height, sizeof(*height));
}

bool blockdepth_watch_eq(const struct watch *w, const u32 *height)
{
	return w->start_block == *height;
}

const char *bwatch_get_watch_type_name(enum watch_type type)
{
	switch (type) {
	case WATCH_SCRIPTPUBKEY:
		return "scriptpubkey";
	case WATCH_OUTPOINT:
		return "outpoint";
	case WATCH_SCID:
		return "scid";
	case WATCH_BLOCKDEPTH:
		return "blockdepth";
	}
	abort();
}

void bwatch_add_watch_to_hash(struct bwatch *bwatch, struct watch *w)
{
	switch (w->type) {
	case WATCH_SCRIPTPUBKEY:
		scriptpubkey_watches_add(bwatch->scriptpubkey_watches, w);
		return;
	case WATCH_OUTPOINT:
		outpoint_watches_add(bwatch->outpoint_watches, w);
		return;
	case WATCH_SCID:
		scid_watches_add(bwatch->scid_watches, w);
		return;
	case WATCH_BLOCKDEPTH:
		blockdepth_watches_add(bwatch->blockdepth_watches, w);
		return;
	}
	abort();
}

struct watch *bwatch_get_watch(struct bwatch *bwatch,
			       enum watch_type type,
			       const struct bitcoin_outpoint *outpoint,
			       const u8 *scriptpubkey,
			       const struct short_channel_id *scid,
			       const u32 *confirm_height)
{
	switch (type) {
	case WATCH_SCRIPTPUBKEY: {
		struct scriptpubkey k = {
			.script = scriptpubkey,
			.len = tal_bytelen(scriptpubkey),
		};
		return scriptpubkey_watches_get(bwatch->scriptpubkey_watches, &k);
	}
	case WATCH_OUTPOINT:
		return outpoint_watches_get(bwatch->outpoint_watches, outpoint);
	case WATCH_SCID:
		return scid_watches_get(bwatch->scid_watches, scid);
	case WATCH_BLOCKDEPTH:
		return blockdepth_watches_get(bwatch->blockdepth_watches, confirm_height);
	}
	abort();
}

void bwatch_remove_watch_from_hash(struct bwatch *bwatch, struct watch *w)
{
	switch (w->type) {
	case WATCH_SCRIPTPUBKEY:
		scriptpubkey_watches_del(bwatch->scriptpubkey_watches, w);
		return;
	case WATCH_OUTPOINT:
		outpoint_watches_del(bwatch->outpoint_watches, w);
		return;
	case WATCH_SCID:
		scid_watches_del(bwatch->scid_watches, w);
		return;
	case WATCH_BLOCKDEPTH:
		blockdepth_watches_del(bwatch->blockdepth_watches, w);
		return;
	}
	abort();
}
