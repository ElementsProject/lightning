#ifndef LIGHTNING_DAEMON_SECRETS_H
#define LIGHTNING_DAEMON_SECRETS_H
/* Routines to handle private keys. */
#include "config.h"

struct peer;
struct lightningd_state;
struct signature;

void privkey_sign(struct peer *peer, const void *src, size_t len,
		  struct signature *sig);

void secrets_init(struct lightningd_state *state);

#endif /* LIGHTNING_DAEMON_SECRETS_H */
