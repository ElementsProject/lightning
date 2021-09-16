#ifndef LIGHTNING_LIGHTNINGD_HSM_CONTROL_H
#define LIGHTNING_LIGHTNINGD_HSM_CONTROL_H
#include "config.h"
#include <ccan/short_types/short_types.h>

struct lightningd;
struct node_id;
struct ext_key;

/* Ask HSM for a new fd for a subdaemon to use. */
int hsm_get_client_fd(struct lightningd *ld,
		      const struct node_id *id,
		      u64 dbid,
		      int capabilities);

/* Ask HSM for an fd for a global subdaemon to use (gossipd, connectd) */
int hsm_get_global_fd(struct lightningd *ld, int capabilities);

struct ext_key *hsm_init(struct lightningd *ld);
#endif /* LIGHTNING_LIGHTNINGD_HSM_CONTROL_H */
