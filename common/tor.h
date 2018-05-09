#ifndef LIGHTNING_COMMON_TOR_H
#define LIGHTNING_COMMON_TOR_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <lightningd/lightningd.h>
#include <stdbool.h>
#include <stdlib.h>

bool check_return_from_service_call(void);
bool parse_tor_wireaddr(const char *arg,u8 *ip_ld,u16 *port_ld);
bool create_tor_hidden_service_conn(struct lightningd *);
bool do_we_use_tor_addr(const struct wireaddr *wireaddrs);
#endif /* LIGHTNING_COMMON_TOR_H */
