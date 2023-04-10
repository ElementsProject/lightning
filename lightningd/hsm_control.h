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

/* Is this capability supported by the HSM? (So far, always a message
 * number) */
bool hsm_capable(struct lightningd *ld, u32 msgtype);

struct ext_key *hsm_init(struct lightningd *ld);

/* Send request to hsmd, get response. */
const u8 *hsm_sync_req(const tal_t *ctx,
		       struct lightningd *ld,
		       const u8 *msg TAKES);

/* Get (and check!) a bip32 derived pubkey */
void bip32_pubkey(struct lightningd *ld, struct pubkey *pubkey, u32 index);

#endif /* LIGHTNING_LIGHTNINGD_HSM_CONTROL_H */
