#ifndef LIGHTNING_COMMON_ZEROCONF_H
#define LIGHTNING_COMMON_ZEROCONF_H
#include "config.h"
#include <common/node_id.h>

/* Helper struct to hand options around various daemons. */
struct zeroconf_options {
       bool allow_all;
       /* List of nodes we allow zeroconf from/to */
       struct node_id *allowlist;
};

struct zeroconf_options *zeroconf_options_new(const tal_t *ctx);

bool fromwire_zeroconf_options(const u8 **cursor, size_t *max,
                              struct zeroconf_options *opts);
void towire_zeroconf_options(u8 **pptr, const struct zeroconf_options *opts);

/**
 * Check if a given node should be allowed for zeroconf.
 *
 * Determines whether we'd be happy to open or accept a zeroconf
 * channel with this peers. It is used to selectively apply the
 * `option_zeroconf` to the `init` message we'll send to the peer when
 * a connection is established. This is sticky, as in it applies to
 * all channels we'll open or accept on this connection. Notice that
 * this does not differentiate between opening of accepting a channel,
 * and that's because the accepter doesn't get a say in the channel
 * negotiation.
 */
bool zeroconf_allow_peer(const struct zeroconf_options *zopts,
			 const struct node_id *node_id);

#endif /* LIGHTNING_COMMON_ZEROCONF_H */
