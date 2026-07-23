/* Internal types for libbolt12 -- not part of the public API.
 *
 * Self-sufficient: pulls in common/bolt12.h (which pulls in
 * wire/bolt12_wiregen.h) so struct tlv_offer / struct tlv_invoice
 * are fully defined for the opaque wrappers below.
 */
#ifndef LIGHTNING_CONTRIB_LIBBOLT12_BOLT12_INTERNAL_H
#define LIGHTNING_CONTRIB_LIBBOLT12_BOLT12_INTERNAL_H
#include "config.h"

#include "contrib/libbolt12/bolt12.h"
#include <common/bolt12.h>
#include <stdarg.h>
#include <stdio.h>

/* Opaque wrapper for a decoded BOLT12 offer.
 * Holds a tal context owning all internal allocations.
 * Requires wire/bolt12_wiregen.h for struct tlv_offer. */
struct bolt12_offer {
	tal_t *ctx;		  /* Root of the tal tree */
	struct tlv_offer *tlv;	  /* Parsed TLV, allocated under ctx */
};

/* Opaque wrapper for a decoded BOLT12 invoice.
 * Holds a tal context owning all internal allocations.
 * Requires wire/bolt12_wiregen.h for struct tlv_invoice. */
struct bolt12_invoice {
	tal_t *ctx;		    /* Root of the tal tree */
	struct tlv_invoice *tlv;    /* Parsed TLV, allocated under ctx */
};

/* Set a bolt12_error_t if non-NULL. */
static inline void set_error(bolt12_error_t *err, int code, const char *fmt, ...)
	__attribute__((format(printf, 3, 4)));

static inline void set_error(bolt12_error_t *err, int code, const char *fmt, ...)
{
	if (!err)
		return;
	err->code = code;
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(err->message, sizeof(err->message), fmt, ap);
	va_end(ap);
}

#endif /* LIGHTNING_CONTRIB_LIBBOLT12_BOLT12_INTERNAL_H */
