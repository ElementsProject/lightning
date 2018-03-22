/* API to ask the HSM for things. */
#ifndef LIGHTNING_HSMD_CLIENT_H
#define LIGHTNING_HSMD_CLIENT_H
#include "config.h"
#include <ccan/endian/endian.h>
#include <ccan/short_types/short_types.h>
#include <stdbool.h>

struct pubkey;
struct secret;

/* Setup communication to the HSM */
void hsm_setup(int fd);

/* Do ECDH using this node id secret. */
bool hsm_do_ecdh(struct secret *ss, const struct pubkey *point);
#endif /* LIGHTNING_HSMD_CLIENT_H */
