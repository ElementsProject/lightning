#ifndef LIGHTNING_LIGHTNINGD_BROADCAST_H
#define LIGHTNING_LIGHTNINGD_BROADCAST_H
#include "config.h"
#include <bitcoin/tx.h>
#include <ccan/htable/htable_type.h>

struct lightningd;

/* Off ld->outgoing_txs */
struct outgoing_tx {
	struct channel *channel;
	const struct bitcoin_tx *tx;
	struct bitcoin_txid txid;
	u32 minblock;
	bool allowhighfees;
	const char *cmd_id;
	bool (*finished)(struct channel *channel, const struct bitcoin_tx *,
			 bool success, const char *err, void *arg);
	bool (*refresh)(struct channel *, const struct bitcoin_tx **, void *arg);
	void *cbarg;
};

static inline const struct bitcoin_txid *keyof_outgoing_tx_map(const struct outgoing_tx *t)
{
	return &t->txid;
}

static inline size_t outgoing_tx_hash_sha(const struct bitcoin_txid *key)
{
	size_t ret;
	memcpy(&ret, key, sizeof(ret));
	return ret;
}

static inline bool outgoing_tx_eq(const struct outgoing_tx *b, const struct bitcoin_txid *key)
{
	return bitcoin_txid_eq(&b->txid, key);
}
HTABLE_DEFINE_DUPS_TYPE(struct outgoing_tx, keyof_outgoing_tx_map,
			outgoing_tx_hash_sha, outgoing_tx_eq,
			outgoing_tx_map);

/**
 * broadcast_tx - Broadcast a single tx, and rebroadcast as reqd (copies tx).
 * @ctx: context: when this is freed, callback/retransmission don't happen.
 * @ld: lightningd
 * @channel: the channel responsible for this (stop broadcasting if freed).
 * @tx: the transaction
 * @cmd_id: the JSON command id which triggered this (or NULL).
 * @allowhighfees: set to true to override the high-fee checks in the backend.
 * @minblock: minimum block we can send it at (or 0).
 * @finished: if non-NULL, call every time sendrawtransaction returns; if it returns true, don't rebroadcast.
 * @refresh: if non-NULL, callback before re-broadcasting (can replace tx):
 *           if returns false, delete.
 * @cbarg: argument for @finished and @refresh
 */
#define broadcast_tx(ctx, ld, channel, tx, cmd_id, allowhighfees,	\
		     minblock, finished, refresh, cbarg)		\
	broadcast_tx_((ctx), (ld), (channel), (tx), (cmd_id), (allowhighfees), \
		      (minblock),					\
		      typesafe_cb_preargs(bool, void *,			\
					  (finished), (cbarg),		\
					  struct channel *,		\
					  const struct bitcoin_tx *,	\
					  bool, const char *),		\
		      typesafe_cb_preargs(bool, void *,			\
					  (refresh), (cbarg),		\
					  struct channel *,		\
					  const struct bitcoin_tx **),	\
		      (cbarg))

void broadcast_tx_(const tal_t *ctx,
		   struct lightningd *ld,
		   struct channel *channel,
		   const struct bitcoin_tx *tx TAKES,
		   const char *cmd_id, bool allowhighfees, u32 minblock,
		   bool (*finished)(struct channel *,
				    const struct bitcoin_tx *,
				    bool success,
				    const char *err,
				    void *),
		   bool (*refresh)(struct channel *, const struct bitcoin_tx **, void *),
		   void *cbarg TAKES);

/* Rebroadcast unconfirmed txs. Called when a new block is processed. */
void rebroadcast_txs(struct lightningd *ld);

/* True iff there's a pending outgoing tx with this txid. */
bool we_broadcast(const struct lightningd *ld,
		  const struct bitcoin_txid *txid);

/* Drain all pending outgoing txs at shutdown, before channels (and their
 * outgoing_tx destructors) are freed. */
void broadcast_shutdown(struct lightningd *ld);

#endif /* LIGHTNING_LIGHTNINGD_BROADCAST_H */
