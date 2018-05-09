#ifndef LIGHTNING_LIGHTNINGD_TOR_H
#define LIGHTNING_LIGHTNINGD_TOR_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <lightningd/lightningd.h>
#include <stdbool.h>
#include <stdlib.h>

bool check_return_from_service_call(void);
bool create_tor_hidden_service_conn(struct lightningd *ld);
#endif /* LIGHTNING_LIGHTNINGD_TOR_H */
