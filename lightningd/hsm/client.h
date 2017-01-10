/* API to ask the HSM for things. */
#ifndef LIGHTNING_LIGHTNINGD_HSM_H
#define LIGHTNING_LIGHTNINGD_HSM_H
#include "config.h"
#include <ccan/endian/endian.h>
#include <ccan/short_types/short_types.h>
#include <stdbool.h>

struct pubkey;
struct sha256;

/* Setup communication to the HSM */
void hsm_setup(int fd);

/* Do ECDH using this node id secret. */
bool hsm_do_ecdh(struct sha256 *ss, const struct pubkey *point);
#endif /* LIGHTNING_LIGHTNINGD_HSM_H */
