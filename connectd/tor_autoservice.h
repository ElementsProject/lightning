#ifndef LIGHTNING_CONNECTD_TOR_AUTOSERVICE_H
#define LIGHTNING_CONNECTD_TOR_AUTOSERVICE_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <stdbool.h>
#include <stdlib.h>

struct wireaddr *tor_autoservice(const tal_t *ctx,
				 const struct wireaddr *tor_serviceaddr,
				 const char *tor_password,
				 const struct wireaddr_internal *bindings);

#endif /* LIGHTNING_CONNECTD_TOR_AUTOSERVICE_H */
