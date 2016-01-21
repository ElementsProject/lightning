#ifndef LIGHTNING_DAEMON_SECRETS_H
#define LIGHTNING_DAEMON_SECRETS_H
/* Routines to handle private keys. */
#include "config.h"
#include <ccan/short_types/short_types.h>

struct peer;
struct lightningd_state;
struct signature;
struct sha256;

void privkey_sign(struct peer *peer, const void *src, size_t len,
		  struct signature *sig);

void peer_secrets_init(struct peer *peer);

void peer_get_revocation_hash(const struct peer *peer, u64 index,
			      struct sha256 *rhash);
void peer_get_revocation_preimage(const struct peer *peer, u64 index,
				  struct sha256 *preimage);

void secrets_init(struct lightningd_state *dstate);

#endif /* LIGHTNING_DAEMON_SECRETS_H */
