#include "../amount.c"
#include <common/utils.h>

#define FAIL_MSAT(msatp, str) \
	assert(!parse_amount_msat((msatp), (str), strlen(str)))
#define PASS_MSAT(msatp, str, val)					\
	do {								\
		assert(parse_amount_msat((msatp), (str), strlen(str))); \
		assert((msatp)->millisatoshis == val);			\
	} while (0)

#define FAIL_SAT(satp, str) \
	assert(!parse_amount_sat((satp), (str), strlen(str)))
#define PASS_SAT(satp, str, val)					\
	do {								\
		assert(parse_amount_sat((satp), (str), strlen(str)));	\
		assert((satp)->satoshis == val);			\
	} while (0)

int main(void)
{
	struct amount_msat msat;
	struct amount_sat sat;

	setup_locale();
	setup_tmpctx();

	/* Grossly malformed */
	FAIL_MSAT(&msat, "x");
	FAIL_MSAT(&msat, "x100");

	PASS_MSAT(&msat, "0", 0);
	PASS_MSAT(&msat, "1", 1);
	PASS_MSAT(&msat, "2100000000000000000", 2100000000000000000ULL);
	FAIL_MSAT(&msat, "0.0");
	FAIL_MSAT(&msat, "0.00000000");
	FAIL_MSAT(&msat, "0.00000000000");
	FAIL_MSAT(&msat, "0.00000000msat");
	FAIL_MSAT(&msat, "-1");

	PASS_MSAT(&msat, "0msat", 0);
	PASS_MSAT(&msat, "1msat", 1);
	PASS_MSAT(&msat, "2100000000000000000msat", 2100000000000000000ULL);
	FAIL_MSAT(&msat, "-1msat");

	PASS_MSAT(&msat, "0sat", 0);
	PASS_MSAT(&msat, "1sat", 1000);
	PASS_MSAT(&msat, "2100000000000000sat", 2100000000000000000ULL);
	FAIL_MSAT(&msat, "-1sat");

	PASS_MSAT(&msat, "0.00000000btc", 0);
	PASS_MSAT(&msat, "0.00000000000btc", 0);
	PASS_MSAT(&msat, "0.00000001btc", 1000);
	PASS_MSAT(&msat, "0.00000000001btc", 1);
	PASS_MSAT(&msat, "1.2btc", 120000000000);
	PASS_MSAT(&msat, "1.23btc", 123000000000);
	PASS_MSAT(&msat, "1.234btc", 123400000000);
	PASS_MSAT(&msat, "1.2345btc", 123450000000);
	PASS_MSAT(&msat, "1.23456btc", 123456000000);
	PASS_MSAT(&msat, "1.234567btc", 123456700000);
	PASS_MSAT(&msat, "1.2345678btc", 123456780000);
	PASS_MSAT(&msat, "1.23456789btc", 123456789000);
	PASS_MSAT(&msat, "1.234567890btc", 123456789000);
	PASS_MSAT(&msat, "1.2345678901btc", 123456789010);
	PASS_MSAT(&msat, "1.23456789012btc", 123456789012);
	FAIL_MSAT(&msat, "1btc");
	FAIL_MSAT(&msat, "1.000000000000btc");
	FAIL_MSAT(&msat, "-1.23456789btc");
	FAIL_MSAT(&msat, "-1.23456789012btc");

	/* Overflowingly big. */
	FAIL_MSAT(&msat, "21000000000000000000000000.00000000btc");

	/* Grossly malformed */
	FAIL_SAT(&sat, "x");
	FAIL_SAT(&sat, "x100");

	PASS_SAT(&sat, "0", 0);
	PASS_SAT(&sat, "1", 1);
	PASS_SAT(&sat, "2100000000000000", 2100000000000000ULL);
	FAIL_SAT(&sat, "0.0");
	FAIL_SAT(&sat, "0.00000000");
	FAIL_SAT(&sat, "0.00000000000");
	FAIL_SAT(&sat, "0.00000000sat");
	FAIL_SAT(&sat, "0.00000000000msat");
	FAIL_SAT(&sat, "-1");

	PASS_SAT(&sat, "0sat", 0);
	PASS_SAT(&sat, "1sat", 1);
	PASS_SAT(&sat, "2100000000000000sat", 2100000000000000ULL);
	FAIL_SAT(&sat, "-1sat");

	PASS_SAT(&sat, "1000msat", 1);
	PASS_SAT(&sat, "1000000msat", 1000);
	PASS_SAT(&sat, "2100000000000000000msat", 2100000000000000ULL);
	FAIL_SAT(&sat, "0msat");
	FAIL_SAT(&sat, "100msat");
	FAIL_SAT(&sat, "2000000000000000999msat");
	FAIL_SAT(&sat, "-1000msat");

	PASS_SAT(&sat, "0.00000000btc", 0);
	FAIL_SAT(&sat, "0.00000000000btc");
	PASS_SAT(&sat, "0.00000001btc", 1);
	FAIL_SAT(&sat, "0.00000000001btc");
	PASS_SAT(&sat, "1.23456789btc", 123456789);
	PASS_SAT(&sat, "1.2btc", 120000000);
	PASS_SAT(&sat, "1.23btc", 123000000);
	PASS_SAT(&sat, "1.234btc", 123400000);
	PASS_SAT(&sat, "1.2345btc", 123450000);
	PASS_SAT(&sat, "1.23456btc", 123456000);
	PASS_SAT(&sat, "1.234567btc", 123456700);
	PASS_SAT(&sat, "1.2345678btc", 123456780);
	PASS_SAT(&sat, "1.23456789btc", 123456789);
	FAIL_SAT(&sat, "1.234567890btc");
	FAIL_SAT(&sat, "1btc");
	FAIL_SAT(&sat, "-1.23456789btc");

	/* Overflowingly big. */
	FAIL_SAT(&sat, "21000000000000000000000000.00000000btc");

	/* Test fmt_amount_msat_btc, fmt_amount_msat */
	for (u64 i = 0; i <= UINT64_MAX / 10; i = i ? i * 10 : 1) {
		const char *with, *without;

		msat.millisatoshis = i;
		with = fmt_amount_msat_btc(tmpctx, &msat, true);
		without = fmt_amount_msat_btc(tmpctx, &msat, false);
		assert(strends(with, "btc"));
		assert(strlen(with) == strlen(without) + 3);
		assert(strncmp(with, without, strlen(without)) == 0);
		/* Make sure it overwrites. */
		msat.millisatoshis++;
		assert(parse_amount_msat(&msat, with, strlen(with)));
		assert(msat.millisatoshis == i);

		with = fmt_amount_msat(tmpctx, &msat);
		without = tal_fmt(tmpctx, "%"PRIu64, msat.millisatoshis);
		assert(strends(with, "msat"));
		assert(strlen(with) == strlen(without) + 4);
		assert(strncmp(with, without, strlen(without)) == 0);
		/* Make sure it overwrites. */
		msat.millisatoshis++;
		assert(parse_amount_msat(&msat, with, strlen(with)));
		assert(msat.millisatoshis == i);
	}

	/* Test fmt_amount_sat_btc, fmt_amount_sat */
	for (u64 i = 0; i <= UINT64_MAX / 10; i = i ? i * 10 : 1) {
		const char *with, *without;

		sat.satoshis = i;
		with = fmt_amount_sat_btc(tmpctx, &sat, true);
		without = fmt_amount_sat_btc(tmpctx, &sat, false);
		assert(strends(with, "btc"));
		assert(strlen(with) == strlen(without) + 3);
		assert(strncmp(with, without, strlen(without)) == 0);
		/* Make sure it overwrites. */
		sat.satoshis++;
		assert(parse_amount_sat(&sat, with, strlen(with)));
		assert(sat.satoshis == i);

		with = fmt_amount_sat(tmpctx, &sat);
		without = tal_fmt(tmpctx, "%"PRIu64, sat.satoshis);
		assert(strends(with, "sat"));
		assert(strlen(with) == strlen(without) + 3);
		assert(strncmp(with, without, strlen(without)) == 0);
		/* Make sure it overwrites. */
		sat.satoshis++;
		assert(parse_amount_sat(&sat, with, strlen(with)));
		assert(sat.satoshis == i);
	}

	tal_free(tmpctx);
}
