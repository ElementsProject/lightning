#ifndef LIGHTNING_LIGHTNINGD_HSM_CONTROL_H
#define LIGHTNING_LIGHTNINGD_HSM_CONTROL_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <hsmd/capabilities.h>
#include <stdbool.h>

struct lightningd;
struct pubkey;

/* Ask HSM for a new fd for a subdaemon to use. */
int hsm_get_client_fd(struct lightningd *ld,
		      const struct pubkey *id,
		      u64 dbid,
		      int capabilities);

void hsm_init(struct lightningd *ld);
#endif /* LIGHTNING_LIGHTNINGD_HSM_CONTROL_H */
