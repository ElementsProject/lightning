#include <ccan/container_of/container_of.h>
#include <ccan/tap/tap.h>

struct outer {
	int first;
	char pad[3];
	struct inner {
		long x;
		char c;
	} second;
};

int main(void)
{
	struct outer o = { 0 }, *p;

	plan_tests(6);

	/* NULL member pointer, member at offset 0 and at non-zero offset. */
	ok1(container_of_or_null((int *)NULL, struct outer, first) == NULL);
	ok1(container_of_or_null((struct inner *)NULL, struct outer,
				 second) == NULL);

	/* Non-NULL member pointer, member at offset 0 and non-zero offset. */
	p = container_of_or_null(&o.first, struct outer, first);
	ok1(p == &o);
	p = container_of_or_null(&o.second, struct outer, second);
	ok1(p == &o);

	/* container_of on the same members for contrast. */
	ok1(container_of(&o.first, struct outer, first) == &o);
	ok1(container_of(&o.second, struct outer, second) == &o);

	return exit_status();
}
