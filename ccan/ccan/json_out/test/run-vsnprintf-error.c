/* Regression test (auditor-added, temporary): json_out_addv() stores the
 * vsnprintf() return (an int, -1 on error) in a size_t
 * (ccan/json_out/json_out.c:218,239), so a failing conversion yields
 * fmtlen == SIZE_MAX.  With quote=true that reaches
 * json_escape_len(NULL, dst, SIZE_MAX) whose len*6+1 sizing overflows
 * and aborts in tal ("allocation size overflow"); with quote=false it
 * reaches membuf_added(outbuf, SIZE_MAX), corrupting the buffer (or
 * hitting its assertion).
 *
 * glibc vsnprintf returns -1 (EILSEQ) for "%lc" with an invalid wchar;
 * the probe skips the test on platforms where it does not.
 *
 * Currently fails (abort); must pass (return false) after repair.
 */
#include "config.h"

#include <stdio.h>
#include <unistd.h>
#include <wchar.h>

#include <ccan/json_out/json_out.c>
#include <ccan/tap/tap.h>

int main(void)
{
	struct json_out *jout;
	char probe[8];
	int r;

	alarm(10);
	plan_tests(2);

	r = snprintf(probe, sizeof(probe), "%lc", (wint_t)0xD800);
	if (r >= 0) {
		ok1(true); /* SKIP: platform vsnprintf does not fail here */
		ok1(true); /* SKIP */
		return exit_status();
	}

	/* quote=true path. */
	jout = json_out_new(NULL);
	json_out_start(jout, NULL, '{');
	ok1(!json_out_add(jout, "f", true, "%lc", (wint_t)0xD800));
	tal_free(jout);

	/* quote=false path. */
	jout = json_out_new(NULL);
	json_out_start(jout, NULL, '{');
	ok1(!json_out_add(jout, "f", false, "%lc", (wint_t)0xD800));
	tal_free(jout);

	return exit_status();
}
