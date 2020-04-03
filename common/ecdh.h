#ifndef LIGHTNING_COMMON_ECDH_H
#define LIGHTNING_COMMON_ECDH_H
#include "config.h"

struct pubkey;
struct secret;

/* This function is implemented differently in various daemons and tools:
 * subdaemons need to talk to the HSM via hsm_fd, lightningd needs to use
 * its HSM interface, and tools can implement this directly. */
void ecdh(const struct pubkey *point, struct secret *ss);

#endif /* LIGHTNING_COMMON_ECDH_H */
