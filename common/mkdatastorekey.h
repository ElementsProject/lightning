#ifndef LIGHTNING_COMMON_MKDATASTOREKEY_H
#define LIGHTNING_COMMON_MKDATASTOREKEY_H
#include "config.h"
#include <ccan/compiler/compiler.h>
#include <ccan/tal/tal.h>

/* Generate an array of strings from these values: great for making
 * keys for datastore operations */
#define mkdatastorekey(ctx, ...) \
	mkdatastorekey_(ctx, __VA_ARGS__, NULL)

LAST_ARG_NULL
const char **mkdatastorekey_(const tal_t *ctx, ...);

#endif /* LIGHTNING_COMMON_MKDATASTOREKEY_H */
