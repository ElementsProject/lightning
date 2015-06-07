#include "opt_bits.h"

char *opt_set_bits(const char *arg, u64 *satoshi)
{
	unsigned long long ll;
	char *ret = opt_set_ulonglongval_si(arg, &ll);
	if (ret)
		return ret;
	*satoshi = ll * 100;
	if (*satoshi / 100 != ll)
		return "Invalid number of bits";
	return NULL;
}

void opt_show_bits(char buf[OPT_SHOW_LEN], const u64 *bits)
{
	unsigned long long ll = *bits / 100;
	opt_show_ulonglongval_si(buf, &ll);
}

