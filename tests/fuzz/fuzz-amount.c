#include "config.h"
#include <assert.h>
#include <tests/fuzz/libfuzz.h>

#include <common/amount.h>

void init(int *argc, char ***argv)
{
}

void run(const uint8_t *data, size_t size)
{
	struct amount_msat msat;
	struct amount_sat sat;
	char *string;
	uint8_t *buf;
	const char *fmt_msat, *fmt_msatbtc, *fmt_sat, *fmt_satbtc;


	/* We should not crash when parsing any string. */

	string = to_string(NULL, data, size);
	parse_amount_msat(&msat, string, tal_count(string));
	parse_amount_sat(&sat, string, tal_count(string));
	tal_free(string);


	/* Same with the wire primitives. */

	buf = tal_arr(NULL, uint8_t, 8);

	msat = fromwire_amount_msat(&data, &size);
	towire_amount_msat(&buf, msat);
	sat = fromwire_amount_sat(&data, &size);
	towire_amount_sat(&buf, sat);

	tal_free(buf);


	/* Format should inconditionally produce valid amount strings according to our
	 * parser */

	fmt_msat = fmt_amount_msat(NULL, msat);
	fmt_msatbtc = fmt_amount_msat_btc(NULL, msat, true);
	assert(parse_amount_msat(&msat, fmt_msat, tal_count(fmt_msat)));
	assert(parse_amount_msat(&msat, fmt_msatbtc, tal_count(fmt_msatbtc)));
	tal_free(fmt_msat);
	tal_free(fmt_msatbtc);

	fmt_sat = fmt_amount_sat(NULL, sat);
	fmt_satbtc = fmt_amount_sat_btc(NULL, sat, true);
	assert(parse_amount_sat(&sat, fmt_sat, tal_count(fmt_sat)));
	assert(parse_amount_sat(&sat, fmt_satbtc, tal_count(fmt_satbtc)));
	tal_free(fmt_sat);
	tal_free(fmt_satbtc);
}
