#ifndef LIGHTNING_LIGHTNINGD_GRAPHQLRPC_H
#define LIGHTNING_LIGHTNINGD_GRAPHQLRPC_H
#include "config.h"

struct json_stream;

void graphqlrpc_add_warning(struct json_stream *js, const char *fmt, ...)
        PRINTF_FMT(2, 3);

#endif /* LIGHTNING_LIGHTNINGD_GRAPHQLRPC_H */
