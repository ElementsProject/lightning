#include "config.h"
#include <ccan/array_size/array_size.h>
#include <ccan/mem/mem.h>
#include <ccan/tal/str/str.h>
#include <common/amount.h>
#include <common/iso4217.h>
#include <common/overflows.h>
#include <common/utils.h>

/* Wikipedia leads me to: https://www.currency-iso.org/en/home/tables/table-a1.html

   "List one: Currency, fund and precious metal codes",,,,,
   Published:,,,,,
   "August 29, 2018", ,,,,
   ENTITY,Currency,Alphabetic Code,Numeric Code,Minor unit,Fund
*/
static const struct iso4217_name_and_divisor iso4217[] = {
	{ "AED", 2 },
	{ "AFN", 2 },
	{ "ALL", 2 },
	{ "AMD", 2 },
	{ "ANG", 2 },
	{ "AOA", 2 },
	{ "ARS", 2 },
	{ "AUD", 2 },
	{ "AWG", 2 },
	{ "AZN", 2 },
	{ "BAM", 2 },
	{ "BBD", 2 },
	{ "BDT", 2 },
	{ "BGN", 2 },
	{ "BHD", 3 },
	{ "BIF", 0 },
	{ "BMD", 2 },
	{ "BND", 2 },
	{ "BOB", 2 },
	{ "BOV", 2 },
	{ "BRL", 2 },
	{ "BSD", 2 },
	{ "BTN", 2 },
	{ "BWP", 2 },
	{ "BYN", 2 },
	{ "BZD", 2 },
	{ "CAD", 2 },
	{ "CDF", 2 },
	{ "CHE", 2 },
	{ "CHF", 2 },
	{ "CHW", 2 },
	{ "CLF", 4 },
	{ "CLP", 0 },
	{ "CNY", 2 },
	{ "COP", 2 },
	{ "COU", 2 },
	{ "CRC", 2 },
	{ "CUC", 2 },
	{ "CUP", 2 },
	{ "CVE", 2 },
	{ "CZK", 2 },
	{ "DJF", 0 },
	{ "DKK", 2 },
	{ "DOP", 2 },
	{ "DZD", 2 },
	{ "EGP", 2 },
	{ "ERN", 2 },
	{ "ETB", 2 },
	{ "EUR", 2 },
	{ "FJD", 2 },
	{ "FKP", 2 },
	{ "GBP", 2 },
	{ "GEL", 2 },
	{ "GHS", 2 },
	{ "GIP", 2 },
	{ "GMD", 2 },
	{ "GNF", 0 },
	{ "GTQ", 2 },
	{ "GYD", 2 },
	{ "HKD", 2 },
	{ "HNL", 2 },
	{ "HRK", 2 },
	{ "HTG", 2 },
	{ "HUF", 2 },
	{ "IDR", 2 },
	{ "ILS", 2 },
	{ "INR", 2 },
	{ "IQD", 3 },
	{ "IRR", 2 },
	{ "ISK", 0 },
	{ "JMD", 2 },
	{ "JOD", 3 },
	{ "JPY", 0 },
	{ "KES", 2 },
	{ "KGS", 2 },
	{ "KHR", 2 },
	{ "KMF", 0 },
	{ "KPW", 2 },
	{ "KRW", 0 },
	{ "KWD", 3 },
	{ "KYD", 2 },
	{ "KZT", 2 },
	{ "LAK", 2 },
	{ "LBP", 2 },
	{ "LKR", 2 },
	{ "LRD", 2 },
	{ "LSL", 2 },
	{ "LYD", 3 },
	{ "MAD", 2 },
	{ "MDL", 2 },
	{ "MGA", 2 },
	{ "MKD", 2 },
	{ "MMK", 2 },
	{ "MNT", 2 },
	{ "MOP", 2 },
	{ "MRU", 2 },
	{ "MUR", 2 },
	{ "MVR", 2 },
	{ "MWK", 2 },
	{ "MXN", 2 },
	{ "MXV", 2 },
	{ "MYR", 2 },
	{ "MZN", 2 },
	{ "NAD", 2 },
	{ "NGN", 2 },
	{ "NIO", 2 },
	{ "NOK", 2 },
	{ "NPR", 2 },
	{ "NZD", 2 },
	{ "OMR", 3 },
	{ "PAB", 2 },
	{ "PEN", 2 },
	{ "PGK", 2 },
	{ "PHP", 2 },
	{ "PKR", 2 },
	{ "PLN", 2 },
	{ "PYG", 0 },
	{ "QAR", 2 },
	{ "RON", 2 },
	{ "RSD", 2 },
	{ "RUB", 2 },
	{ "RWF", 0 },
	{ "SAR", 2 },
	{ "SBD", 2 },
	{ "SCR", 2 },
	{ "SDG", 2 },
	{ "SEK", 2 },
	{ "SGD", 2 },
	{ "SHP", 2 },
	{ "SLL", 2 },
	{ "SOS", 2 },
	{ "SRD", 2 },
	{ "SSP", 2 },
	{ "STN", 2 },
	{ "SVC", 2 },
	{ "SYP", 2 },
	{ "SZL", 2 },
	{ "THB", 2 },
	{ "TJS", 2 },
	{ "TMT", 2 },
	{ "TND", 3 },
	{ "TOP", 2 },
	{ "TRY", 2 },
	{ "TTD", 2 },
	{ "TWD", 2 },
	{ "TZS", 2 },
	{ "UAH", 2 },
	{ "UGX", 0 },
	{ "USD", 2 },
	{ "USN", 2 },
	{ "UYI", 0 },
	{ "UYU", 2 },
	{ "UYW", 4 },
	{ "UZS", 2 },
	{ "VES", 2 },
	{ "VND", 0 },
	{ "VUV", 0 },
	{ "WST", 2 },
	{ "XAF", 0 },
	{ "XAG", 0 },
	{ "XAU", 0 },
	{ "XBA", 0 },
	{ "XBB", 0 },
	{ "XBC", 0 },
	{ "XBD", 0 },
	{ "XCD", 2 },
	{ "XDR", 0 },
	{ "XOF", 0 },
	{ "XPD", 0 },
	{ "XPF", 0 },
	{ "XPT", 0 },
	{ "XSU", 0 },
	{ "XTS", 0 },
	{ "XUA", 0 },
	{ "XXX", 0 },
	{ "YER", 2 },
	{ "ZAR", 2 },
	{ "ZMW", 2 },
	{ "ZWL", 2 },
};

const struct iso4217_name_and_divisor *find_iso4217(const utf8 *prefix,
						    size_t len)
{
	for (size_t i = 0; i < ARRAY_SIZE(iso4217); i++) {
		if (memeq(iso4217[i].name, strlen(iso4217[i].name),
			  prefix, len))
			return &iso4217[i];
	}
	return NULL;
}

static bool msat_or_any(const tal_t *ctx,
			const char *buf,
			size_t buflen,
			u64 **amount)
{
	struct amount_msat msat;

	if (memeqstr(buf, buflen, "any")) {
		*amount = NULL;
		return true;
	}

	if (!parse_amount_msat(&msat, buf, buflen))
		return false;

	*amount = tal_dup(ctx, u64, &msat.millisatoshis); /* Raw: parsing */
	return true;
}

const char *parse_currency_amount(const tal_t *ctx,
				  const char *buf,
				  size_t buflen,
				  const struct iso4217_name_and_divisor **isocode,
				  u64 **amount)
{
	const char *dot;
	size_t wholelen;
	u64 cents;
	u64 total;

	if (msat_or_any(ctx, buf, buflen, amount)) {
		*isocode = NULL;
		return NULL;
	}

	/* BOLT #12:
	 *
	 * - MUST specify `offer_currency` `iso4217` as an ISO 4217 three-letter code.
	 * - MUST specify `offer_amount` in the currency unit adjusted by the ISO 4217
	 *   exponent (e.g. USD cents).
	 */
	if (buflen < ISO4217_NAMELEN)
		return tal_fmt(ctx, "Not a number, and too short for currency");

 	*isocode = find_iso4217(buf + buflen - ISO4217_NAMELEN, ISO4217_NAMELEN);
	if (!*isocode)
		return tal_fmt(ctx, "Unknown currency suffix %.*s",
			       ISO4217_NAMELEN,
			       buf + buflen - ISO4217_NAMELEN);

	buflen -= ISO4217_NAMELEN;
	dot = memchr(buf, '.', buflen);
	if (!dot) {
		wholelen = buflen;
		cents = 0;
	} else {
		const char *afterdot = dot + 1;
		size_t partlen = buf + buflen - afterdot;
		wholelen = dot - buf;
		if (partlen != (*isocode)->minor_unit)
			return tal_fmt(ctx, "Currency %s requires %u minor units",
				       (*isocode)->name, (*isocode)->minor_unit);
		if (!str_to_u64(afterdot, partlen, &cents))
			return tal_fmt(ctx, "Bad minor units number");
	}

	if (!str_to_u64(buf, wholelen, &total))
		return tal_fmt(ctx, "Not a valid number");

	for (size_t i = 0; i < (*isocode)->minor_unit; i++) {
		if (mul_overflows_u64(total, 10))
			return tal_fmt(ctx, "excessively large value");
		total *= 10;
	}

	if (add_overflows_u64(total, cents))
		return tal_fmt(ctx, "excessively large value");

	total += cents;
	*amount = tal_dup(ctx, u64, &total);
	return NULL;
}
