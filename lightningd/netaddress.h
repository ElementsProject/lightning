#ifndef LIGHTNING_LIGHTNINGD_NETADDRESS_H
#define LIGHTNING_LIGHTNINGD_NETADDRESS_H
#include "config.h"
#include <ccan/short_types/short_types.h>

struct lightningd;

void guess_addresses(struct lightningd *ld);


#endif /* LIGHTNING_LIGHTNINGD_NETADDRESS_H */
