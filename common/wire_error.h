#ifndef LIGHTNING_COMMON_WIRE_ERROR_H
#define LIGHTNING_COMMON_WIRE_ERROR_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

struct channel_id;

/**
 * towire_errorfmt - helper to turn string into WIRE_ERROR.
 *
 * @ctx: context to allocate from
 * @channel: specific channel to complain about
 * @fmt: format for error.
 */
u8 *towire_errorfmt(const tal_t *ctx,
		    const struct channel_id *channel,
		    const char *fmt, ...) PRINTF_FMT(3,4) NON_NULL_ARGS(2);

/**
 * towire_errorfmtv - helper to turn string into WIRE_ERROR.
 *
 * @ctx: context to allocate from
 * @channel: specific channel to complain about
 * @fmt: format for error.
 * @ap: accumulated varargs.
 */
u8 *towire_errorfmtv(const tal_t *ctx,
		     const struct channel_id *channel,
		     const char *fmt,
		     va_list ap) NON_NULL_ARGS(2);

/**
 * towire_warningfmt - helper to turn string into WIRE_WARNING.
 *
 * @ctx: context to allocate from
 * @channel: specific channel to complain about, or NULL for all.
 * @fmt: format for warning.
 */
u8 *towire_warningfmt(const tal_t *ctx,
		      const struct channel_id *channel,
		      const char *fmt, ...) PRINTF_FMT(3,4);

/**
 * towire_warningfmtv - helper to turn string into WIRE_WARNING.
 *
 * @ctx: context to allocate from
 * @channel: specific channel to complain about, or NULL for all.
 * @fmt: format for warning.
 * @ap: accumulated varargs.
 */
u8 *towire_warningfmtv(const tal_t *ctx,
		       const struct channel_id *channel,
		       const char *fmt,
		       va_list ap);

/**
 * towire_abortfmt - helper to turn string into WIRE_TX_ABORT.
 *
 * @ctx: context to allocate from
 * @channel: specific channel to complain about, or NULL for all.
 * @fmt: format for warning.
 */
u8 *towire_abortfmt(const tal_t *ctx,
		    const struct channel_id *channel,
		    const char *fmt, ...) PRINTF_FMT(3,4);

/**
 * towire_abortfmtv - helper to turn string into WIRE_TX_ABORT.
 *
 * @ctx: context to allocate from
 * @channel: specific channel to complain about, or NULL for all.
 * @fmt: format for warning.
 * @ap: accumulated varargs.
 */
u8 *towire_abortfmtv(const tal_t *ctx,
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
 * sanitize_error - extract and sanitize contents of WIRE_ERROR/WIRE_WARNING.
 *
 * @ctx: context to allocate from
 * @errmsg: the wire_error or wire_warning
 * @channel: (out) channel it's referring to, or NULL if don't care.
 */
char *sanitize_error(const tal_t *ctx, const u8 *errmsg,
		     struct channel_id *channel_id);

/**
 * is_peer_error - if it's an error, describe it.
 * @ctx: context to allocate return from.
 * @msg: the peer message.
 *
 * If this returns non-NULL, it's usually passed to
 * peer_failed_received_errmsg().
 */
const char *is_peer_error(const tal_t *ctx, const u8 *msg);

/**
 * is_peer_warning - if it's a warning, describe it.
 * @ctx: context to allocate return from.
 * @msg: the peer message.
 *
 * If this returns non-NULL, it's usually logged.
 */
const char *is_peer_warning(const tal_t *ctx, const u8 *msg);

#endif /* LIGHTNING_COMMON_WIRE_ERROR_H */
