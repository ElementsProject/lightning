#ifndef LIGHTNING_COMMON_WIRE_ERROR_H
#define LIGHTNING_COMMON_WIRE_ERROR_H
#include "config.h"
#include <ccan/compiler/compiler.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <stdarg.h>

struct channel_id;

/**
 * towire_errorfmt - helper to turn string into WIRE_ERROR.
 *
 * @ctx: context to allocate from
 * @channel: specific channel to complain about, or NULL for all.
 * @fmt: format for error.
 */
u8 *towire_errorfmt(const tal_t *ctx,
		    const struct channel_id *channel,
		    const char *fmt, ...) PRINTF_FMT(3,4);

/**
 * towire_errorfmtv - helper to turn string into WIRE_ERROR.
 *
 * @ctx: context to allocate from
 * @channel: specific channel to complain about, or NULL for all.
 * @fmt: format for error.
 * @ap: accumulated varargs.
 */
u8 *towire_errorfmtv(const tal_t *ctx,
		     const struct channel_id *channel,
		     const char *fmt,
		     va_list ap);

/* BOLT #1:
 *
 * The channel is referred to by `channel_id`, unless `channel_id` is 0
 * (i.e. all bytes are 0), in which case it refers to all channels.
 */
/**
 * channel_id_is_all - True if channel_id is all zeroes.
 */
bool channel_id_is_all(const struct channel_id *channel_id);

/**
 * sanitize_error - extract and sanitize contents of WIRE_ERROR.
 *
 * @ctx: context to allocate from
 * @errmsg: the wire_error
 * @channel: (out) channel it's referring to, or NULL if don't care.
 */
char *sanitize_error(const tal_t *ctx, const u8 *errmsg,
		     struct channel_id *channel_id);

#endif /* LIGHTNING_COMMON_WIRE_ERROR_H */
