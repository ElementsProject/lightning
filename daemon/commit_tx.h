#ifndef LIGHTNING_COMMIT_TX_H
#define LIGHTNING_COMMIT_TX_H
#include "config.h"
#include "htlc.h"

struct channel_state;
struct sha256;
struct pubkey;
struct peer;

u8 *wscript_for_htlc(const tal_t *ctx,
		     const struct peer *peer,
		     const struct htlc *h,
		     const struct sha256 *rhash,
		     enum htlc_side side);

/* Create commitment tx to spend the anchor tx output; doesn't fill in
 * input scriptsig. */
struct bitcoin_tx *create_commit_tx(const tal_t *ctx,
				    struct peer *peer,
				    const struct sha256 *rhash,
				    const struct channel_state *cstate,
				    enum htlc_side side,
				    int **map);
#endif
