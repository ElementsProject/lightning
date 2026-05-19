#ifndef LIGHTNING_COMMON_ISO4217_H
#define LIGHTNING_COMMON_ISO4217_H
#include "config.h"
#include <wire/wire.h>

/* BOLT #12:
 *
 * - MUST specify `offer_currency` `iso4217` as an ISO 4217 three-letter code.
 * - MUST specify `offer_amount` in the currency unit adjusted by the ISO 4217
 * exponent (e.g. USD cents).
 */
struct iso4217_name_and_divisor {
	const char *name;
	unsigned int minor_unit;
};

#define ISO4217_NAMELEN 3

const struct iso4217_name_and_divisor *find_iso4217(const utf8 *prefix,
						    size_t len);

/**
 * parse_currency_amount - convert msat amount, any, or currency amount.
 *
 * Returns error message or NULL.  On success:
 * if *iso4217 == NULL: currency is BTC.  If *amount == NULL, "any".
 * if *iso4217 != NULL: *amount is amount in cents in that currency, never NULL.
 */
const char *parse_currency_amount(const tal_t *ctx,
				  const char *buf,
				  size_t buflen,
				  const struct iso4217_name_and_divisor **iso4217,
				  u64 **amount);
#endif /* LIGHTNING_COMMON_ISO4217_H */
