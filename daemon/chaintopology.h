#ifndef LIGHTNING_DAEMON_CHAINTOPOLOGY_H
#define LIGHTNING_DAEMON_CHAINTOPOLOGY_H
#include "config.h"
#include <stddef.h>

struct lightningd_state;
struct txwatch;

size_t get_tx_depth(struct lightningd_state *dstate, const struct txwatch *w,
		    struct sha256_double *blkid);
void setup_topology(struct lightningd_state *dstate);

#endif /* LIGHTNING_DAEMON_CRYPTOPKT_H */
