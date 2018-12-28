#include <ccan/structeq/structeq.h>
#include <ccan/tap/tap.h>

/* In theory, this could be generated without padding, if alignof(int) were 0,
 * and test would fail.  Call me when that happens. */
struct mydata {
	char start;
	int end;
};

STRUCTEQ_DEF(mydata, -3, start, end);

struct mydata2 {
	char start;
	int end;
};

STRUCTEQ_DEF(mydata2, -4, start, end);

int main(void)
{
	struct mydata a, b;

	/* This is how many tests you plan to run */
	plan_tests(3);

	a.start = 0;
	a.end = 100;
	ok1(mydata_eq(&a, &a));

	b = a;
	ok1(mydata_eq(&a, &b));

	b.end++;
	ok1(!mydata_eq(&a, &b));

	/* This exits depending on whether all tests passed */
	return exit_status();
}
