#ifndef LIGHTNING_COMMON_BLINDEDPATH_H
#define LIGHTNING_COMMON_BLINDEDPATH_H
#include "config.h"
#include <ccan/tal/tal.h>

#if EXPERIMENTAL_FEATURES
struct route_info;
struct pubkey;

/* Fills in *initial_blinding and *final_blinding and returns
 * onionmsg_path array for this route */
struct onionmsg_path **make_blindedpath(const tal_t *ctx,
					const struct pubkey *route,
					struct pubkey *initial_blinding,
					struct pubkey *final_blinding);
#endif /* EXPERIMENTAL_FEATURES */
#endif /* LIGHTNING_COMMON_BLINDEDPATH_H */
