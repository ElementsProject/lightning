#ifndef LIGHTNING_PLUGINS_BWATCH_BWATCH_STORE_H
#define LIGHTNING_PLUGINS_BWATCH_BWATCH_STORE_H

#include "config.h"
#include "bwatch.h"
#include <ccan/htable/htable_type.h>
#include <common/amount.h>

/*
 * ============================================================================
 * HASH TABLE DEFINITIONS (implementation details)
 * ============================================================================
 */

/* Hash table key functions (needed for HTABLE_DEFINE macros) */
const struct scriptpubkey *scriptpubkey_watch_keyof(const struct watch *w);
size_t scriptpubkey_hash(const struct scriptpubkey *scriptpubkey);
bool scriptpubkey_watch_eq(const struct watch *w, const struct scriptpubkey *scriptpubkey);

const struct bitcoin_outpoint *outpoint_watch_keyof(const struct watch *w);
size_t outpoint_hash(const struct bitcoin_outpoint *outpoint);
bool outpoint_watch_eq(const struct watch *w, const struct bitcoin_outpoint *outpoint);

const struct bitcoin_txid *txid_watch_keyof(const struct watch *w);
size_t txid_hash(const struct bitcoin_txid *txid);
bool txid_watch_eq(const struct watch *w, const struct bitcoin_txid *txid);

/* Define hash table types */
HTABLE_DEFINE_NODUPS_TYPE(struct watch, scriptpubkey_watch_keyof,
			  scriptpubkey_hash, scriptpubkey_watch_eq,
			  scriptpubkey_watches);

HTABLE_DEFINE_NODUPS_TYPE(struct watch, outpoint_watch_keyof,
			  outpoint_hash, outpoint_watch_eq,
			  outpoint_watches);

HTABLE_DEFINE_NODUPS_TYPE(struct watch, txid_watch_keyof,
			  txid_hash, txid_watch_eq,
			  txid_watches);

/*
 * ============================================================================
 * PUBLIC API
 * ============================================================================
 */

/* Get watch type name as string */
const char *bwatch_get_watch_type_name(enum watch_type type);

/* Block operations */
void bwatch_add_block_to_datastore(struct command *cmd, const struct block_record_wire *br);
void bwatch_add_block_to_history(struct bwatch *bwatch, u32 height,
				  const struct bitcoin_blkid *hash,
				  const struct bitcoin_blkid *prev_hash);
void bwatch_delete_block_from_datastore(struct command *cmd, u32 height);
void bwatch_load_block_history(struct command *cmd, struct bwatch *bwatch);

/* Watch hash table operations */
void bwatch_add_watch_to_hash(struct bwatch *bwatch, struct watch *w);
struct watch *bwatch_get_watch(struct bwatch *bwatch,
			       enum watch_type type,
			       const struct bitcoin_outpoint *outpoint,
			       const u8 *scriptpubkey,
			       const struct bitcoin_txid *txid);
void bwatch_remove_watch_from_hash(struct bwatch *bwatch, struct watch *w);

/* Watch datastore operations */
void bwatch_save_watch_to_datastore(struct command *cmd, const struct watch *w);
void bwatch_delete_watch_from_datastore(struct command *cmd, const struct watch *w);
void bwatch_load_watches_from_datastore(struct command *cmd, struct bwatch *bwatch);

/* Watch management (add/remove logic) */
struct watch *bwatch_add_watch(struct command *cmd,
			       struct bwatch *bwatch,
			       enum watch_type type,
			       const struct bitcoin_outpoint *outpoint,
			       const u8 *scriptpubkey,
			       const struct bitcoin_txid *txid,
			       u32 start_block,
			       const char *owner_id);

void bwatch_del_watch(struct command *cmd,
		      struct bwatch *bwatch,
		      enum watch_type type,
		      const struct bitcoin_outpoint *outpoint,
		      const u8 *scriptpubkey,
		      const struct bitcoin_txid *txid,
		      const char *owner_id);

/* Utxoset (replaces wallet utxoset table) */
void bwatch_utxoset_add(struct command *cmd,
		       const struct bitcoin_outpoint *outpoint,
		       u32 blockheight, u32 txindex,
		       const u8 *scriptpubkey, size_t scriptpubkey_len,
		       struct amount_sat satoshis);
void bwatch_utxoset_spend(struct command *cmd,
			 const struct bitcoin_outpoint *outpoint,
			 u32 spendheight);

/* Transactions (replaces wallet transactions table) */
void bwatch_transaction_add(struct command *cmd,
			    const struct bitcoin_tx *tx,
			    u32 blockheight, u32 txindex);

/* Look up a stored transaction entry by txid. Returns the entry JSON token
 * (with blockheight + hex fields) into *buf_out, or NULL if not found. */
const jsmntok_t *bwatch_get_transaction(const tal_t *ctx,
					struct command *cmd,
					const struct bitcoin_txid *txid,
					const char **buf_out);

#endif /* LIGHTNING_PLUGINS_BWATCH_BWATCH_STORE_H */
