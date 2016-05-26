#ifndef LIGHTNING_COMMIT_TX_H
#define LIGHTNING_COMMIT_TX_H
#include "config.h"
#include "funding.h"

struct channel_state;
struct sha256_double;
struct sha256;
struct pubkey;
struct rel_locktime;

/* Create commitment tx to spend the anchor tx output; doesn't fill in
 * input scriptsig. */
struct bitcoin_tx *create_commit_tx(const tal_t *ctx,
				    const struct pubkey *our_final,
				    const struct pubkey *their_final,
				    const struct rel_locktime *our_locktime,
				    const struct rel_locktime *their_locktime,
				    const struct sha256_double *anchor_txid,
				    unsigned int anchor_index,
				    u64 anchor_satoshis,
				    const struct sha256 *rhash,
				    const struct channel_state *cstate,
				    enum channel_side side,
				    int **map);
#endif
