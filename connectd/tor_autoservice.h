#ifndef LIGHTNING_CONNECTD_TOR_AUTOSERVICE_H
#define LIGHTNING_CONNECTD_TOR_AUTOSERVICE_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <stdbool.h>
#include <stdlib.h>

struct wireaddr *tor_autoservice(const tal_t *ctx,
				 const struct wireaddr_internal *tor_serviceaddr,
				 const char *tor_password,
				 const struct wireaddr *localaddr,
				 const bool use_v3_autotor);

struct wireaddr *tor_fixed_service(const tal_t *ctx,
				 const struct wireaddr_internal *tor_serviceaddr,
				 const char *tor_password,
				 const char *blob,
				 const struct wireaddr *bind,
				 const u8 index);

#endif /* LIGHTNING_CONNECTD_TOR_AUTOSERVICE_H */
