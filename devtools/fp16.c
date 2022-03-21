/* Simple tool to convert to/from our internal fp16 representation */
#include "config.h"
#include <ccan/err/err.h>
#include <ccan/opt/opt.h>
#include <common/fp16.h>
#include <common/setup.h>
#include <common/type_to_string.h>
#include <inttypes.h>
#include <stdio.h>

int main(int argc, char *argv[])
{
	fp16_t fp16val;
	u64 u64min, u64max;
	char *endp;

	common_setup(argv[0]);

	opt_register_noarg("-h|--help", opt_usage_and_exit,
			   "[fp16:val|value]\n"
			   "Converts to/from fp16, indicates ranges",
			   "Get usage information");
	opt_parse(&argc, argv, opt_log_stderr_exit);
	if (argc != 2)
		opt_usage_exit_fail("Expect 1 argument");

	if (strstarts(argv[1], "fp16:"))
		fp16val = strtoul(argv[1] + 5, &endp, 0);
	else
		fp16val = u64_to_fp16(strtoul(argv[1], &endp, 0), false);

	if (*endp)
		opt_usage_exit_fail("Expect valid number");

	u64min = u64max = fp16_to_u64(fp16val);
	while (u64_to_fp16(u64min-1, false) == fp16val)
		u64min--;
	while (u64_to_fp16(u64max+1, false) == fp16val)
		u64max++;
	printf("fp16:0x%x\n"
	       "min %"PRIu64"\n"
	       "max %"PRIu64"\n",
	       fp16val, u64min, u64max);
	common_shutdown();
}
