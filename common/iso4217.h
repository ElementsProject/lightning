#ifndef LIGHTNING_COMMON_ISO4217_H
#define LIGHTNING_COMMON_ISO4217_H
#include "config.h"
#include <wire/wire.h>

/* BOLT-offers #12:
 *
 * - MUST specify `iso4217` as an ISO 4712 three-letter code.
 * - MUST specify `amount` in the currency unit adjusted by the ISO 4712
 * exponent (e.g. USD cents).
 */
struct iso4217_name_and_divisor {
	const char *name;
	unsigned int minor_unit;
};

#define ISO4217_NAMELEN 3

const struct iso4217_name_and_divisor *find_iso4217(const utf8 *prefix,
						    size_t len);
#endif /* LIGHTNING_COMMON_ISO4217_H */
