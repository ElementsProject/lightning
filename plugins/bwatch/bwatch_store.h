#ifndef LIGHTNING_PLUGINS_BWATCH_BWATCH_STORE_H
#define LIGHTNING_PLUGINS_BWATCH_BWATCH_STORE_H

#include "config.h"
#include <ccan/htable/htable_type.h>
#include <plugins/bwatch/bwatch.h>

/*
 * Per-watch-type key/hash/eq triplets so HTABLE_DEFINE_NODUPS_TYPE can
 * generate a typed hash table for each watch type.  Lookups then take
 * the natural key (raw script bytes, bitcoin_outpoint, short_channel_id,
 * or u32 confirm height) instead of dispatching on type at every call.
 */

const struct scriptpubkey *scriptpubkey_watch_keyof(const struct watch *w);
size_t scriptpubkey_hash(const struct scriptpubkey *scriptpubkey);
bool scriptpubkey_watch_eq(const struct watch *w, const struct scriptpubkey *scriptpubkey);

const struct bitcoin_outpoint *outpoint_watch_keyof(const struct watch *w);
size_t outpoint_hash(const struct bitcoin_outpoint *outpoint);
bool outpoint_watch_eq(const struct watch *w, const struct bitcoin_outpoint *outpoint);

const struct short_channel_id *scid_watch_keyof(const struct watch *w);
size_t scid_hash(const struct short_channel_id *scid);
bool scid_watch_eq(const struct watch *w, const struct short_channel_id *scid);

const u32 *blockdepth_watch_keyof(const struct watch *w);
size_t u32_hash(const u32 *height);
bool blockdepth_watch_eq(const struct watch *w, const u32 *height);

HTABLE_DEFINE_NODUPS_TYPE(struct watch, scriptpubkey_watch_keyof,
			  scriptpubkey_hash, scriptpubkey_watch_eq,
			  scriptpubkey_watches);

HTABLE_DEFINE_NODUPS_TYPE(struct watch, outpoint_watch_keyof,
			  outpoint_hash, outpoint_watch_eq,
			  outpoint_watches);

HTABLE_DEFINE_NODUPS_TYPE(struct watch, scid_watch_keyof,
			  scid_hash, scid_watch_eq,
			  scid_watches);

HTABLE_DEFINE_NODUPS_TYPE(struct watch, blockdepth_watch_keyof,
			  u32_hash, blockdepth_watch_eq,
			  blockdepth_watches);

/* Human-readable name of a watch type, used as the second datastore key
 * component (e.g. ["bwatch", "scriptpubkey", <hex>]) once persistence
 * lands in a follow-up commit. */
const char *bwatch_get_watch_type_name(enum watch_type type);

/* Watch hash table operations: dispatch on watch->type. */
void bwatch_add_watch_to_hash(struct bwatch *bwatch, struct watch *w);
struct watch *bwatch_get_watch(struct bwatch *bwatch,
			       enum watch_type type,
			       const struct bitcoin_outpoint *outpoint,
			       const u8 *scriptpubkey,
			       const struct short_channel_id *scid,
			       const u32 *confirm_height);
void bwatch_remove_watch_from_hash(struct bwatch *bwatch, struct watch *w);

#endif /* LIGHTNING_PLUGINS_BWATCH_BWATCH_STORE_H */
