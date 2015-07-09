#include <limits.h>

#include <ccan/array_size/array_size.h>

#include <ccan/ptrint/ptrint.h>
#include <ccan/tap/tap.h>

static ptrdiff_t testvals[] = {
	-INT_MAX, -1, 0, 1, 2, 17, INT_MAX,
};

int main(void)
{
	int i;

	/* This is how many tests you plan to run */
	plan_tests(2 * ARRAY_SIZE(testvals));

	for (i = 0; i < ARRAY_SIZE(testvals); i++) {
		ptrdiff_t val = testvals[i];
		void *ptr = int2ptr(val);

		ok1(ptr2int(ptr) == val);
		ok1(!val == !ptr);
	}

	/* This exits depending on whether all tests passed */
	return exit_status();
}
