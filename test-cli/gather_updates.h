#ifndef GATHER_UPDATES_H
#define GATHER_UPDATES_H
#include <ccan/tal/tal.h>
#include "lightning.pb-c.h"

struct signature;
struct sha256;
struct channel_state;

struct channel_state *gather_updates(const tal_t *ctx,
			const OpenChannel *o1, const OpenChannel *o2,
			const OpenAnchor *oa, uint64_t fee,
			char **argv,
			size_t *num_updates,
			struct sha256 *our_rhash,
			struct sha256 *their_rhash,
			struct signature *their_commit_sig);

/**
 * is_funder: helper to tell you if this is offering to fund channel.
 * @o: the openchannel packet.
 */
static inline bool is_funder(const OpenChannel *o)
{
	return o->anch == OPEN_CHANNEL__ANCHOR_OFFER__WILL_CREATE_ANCHOR;
}
#endif /* GATHER_UPDATES_H */
