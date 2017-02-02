#ifndef LIGHTNING_COMMIT_TX_H
#define LIGHTNING_COMMIT_TX_H
#include "config.h"
#include "htlc.h"
#include <ccan/tal/tal.h>

struct channel_state;
struct sha256;
struct pubkey;
struct peer;

u8 *wscript_for_htlc(const tal_t *ctx,
		     const struct peer *peer,
		     const struct htlc *h,
		     const struct sha256 *rhash,
		     enum side side);

/* Returns scriptpubkey: *wscript is NULL if it's a direct p2wpkh. */
u8 *commit_output_to_us(const tal_t *ctx,
			const struct peer *peer,
			const struct sha256 *rhash,
			enum side side,
			u8 **wscript);

/* Returns scriptpubkey: *wscript is NULL if it's a direct p2wpkh. */
u8 *commit_output_to_them(const tal_t *ctx,
			  const struct peer *peer,
			  const struct sha256 *rhash,
			  enum side side,
			  u8 **wscript);

/* Create commitment tx to spend the anchor tx output; doesn't fill in
 * input scriptsig. */
struct bitcoin_tx *create_commit_tx(const tal_t *ctx,
				    struct peer *peer,
				    const struct sha256 *rhash,
				    const struct channel_state *cstate,
				    enum side side,
				    bool *otherside_only);
#endif
