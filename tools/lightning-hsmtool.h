#ifndef LIGHTNING_TOOLS_LIGHTNING_HSMTOOL_H
#define LIGHTNING_TOOLS_LIGHTNING_HSMTOOL_H
#include "config.h"
#include <ccan/tal/tal.h>

struct hsm_secret;

#define ERROR_USAGE 2
#define ERROR_KEYDERIV 5

struct hsm_secret *hsmtool_load_hsm_secret(const tal_t *ctx,
					   const char *hsm_secret_path);

#endif /* LIGHTNING_TOOLS_LIGHTNING_HSMTOOL_H */
