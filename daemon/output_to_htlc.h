#ifndef LIGHTNING_DAEMON_OUTPUT_TO_HTLC_H
#define LIGHTNING_DAEMON_OUTPUT_TO_HTLC_H
#include "config.h"
#include "htlc.h"

struct peer;
struct sha256;

/* Get a map of HTLCs (including at least those at the given commit_num). */
struct htlc_output_map *get_htlc_output_map(const tal_t *ctx,
					    const struct peer *peer,
					    const struct sha256 *rhash,
					    enum side side,
					    unsigned int commit_num);

/* If this scriptPubkey pays to a HTLC, get the full wscript */
struct htlc *txout_get_htlc(struct htlc_output_map *omap,
			    const u8 *script, const u8 **wscript);

#endif /* LIGHTNING_DAEMON_OUTPUT_TO_HTLC_H */
