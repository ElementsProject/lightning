#include <ccan/short_types/short_types.h>
#include <ccan/tap/tap.h>
#include <stdlib.h>
#include <err.h>

int main(void)
{
	plan_tests(16);

	ok1(sizeof(u64) == 8);
	ok1(sizeof(s64) == 8);
	ok1(sizeof(u32) == 4);
	ok1(sizeof(s32) == 4);
	ok1(sizeof(u16) == 2);
	ok1(sizeof(s16) == 2);
	ok1(sizeof(u8) == 1);
	ok1(sizeof(s8) == 1);

	/* Signedness tests. */
	ok1((u64)-1 > 0);
	ok1((u32)-1 > 0);
	ok1((u16)-1 > 0);
	ok1((u8)-1 > 0);
	ok1((s64)-1 < 0);
	ok1((s32)-1 < 0);
	ok1((s16)-1 < 0);
	ok1((s8)-1 < 0);

	return exit_status();
}
