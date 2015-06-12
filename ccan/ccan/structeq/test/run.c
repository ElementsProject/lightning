#include <ccan/structeq/structeq.h>
#include <ccan/tap/tap.h>

struct mydata {
	int start, end;
};

int main(void)
{
	struct mydata a, b;

	/* This is how many tests you plan to run */
	plan_tests(3);

	a.start = 0;
	a.end = 100;
	ok1(structeq(&a, &a));

	b = a;
	ok1(structeq(&a, &b));

	b.end++;
	ok1(!structeq(&a, &b));

	/* This exits depending on whether all tests passed */
	return exit_status();
}
