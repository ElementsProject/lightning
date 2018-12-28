#include <ccan/alignof/alignof.h>
#include <stdlib.h>
#include <stddef.h>
#include <ccan/tap/tap.h>

/* Alignment is remarkably difficult to test.  The rules may be more
 * complex than ALIGNOF() can know: eg. on i386 __alignof__(double) == 8, but
 * __alignof__(struct containing double) == 4.
 *
 * Technically, we can only test that we give *at least* the alignment which
 * naturally occurs, and that accesses work.
 *
 * For the moment, we work around double. */
struct lots_of_types
{
	char c;
	short s;
	char c2;
	int i;
	char c3;
	float f;
	char c4;
	double d;
	char c5;
};

int main(void)
{
	struct lots_of_types lots_of_types, *lp = malloc(sizeof(*lp));
	char c;
	short s;
	char c2;
	int i;
	char c3;
	float f;
	char c4;
	double d;

	/* Make sure we use all the variables. */
	c = c2 = c3 = c4 = 0;

	plan_tests(15);
	ok1((unsigned long)&c % ALIGNOF(char) == 0);
	ok1((unsigned long)&s % ALIGNOF(short) == 0);
	ok1((unsigned long)&i % ALIGNOF(int) == 0);
	ok1((unsigned long)&f % ALIGNOF(float) == 0);
	ok1((unsigned long)&d % ALIGNOF(double) == 0);

	ok1((unsigned long)&lots_of_types.c % ALIGNOF(char) == 0);
	ok1((unsigned long)&lots_of_types.s % ALIGNOF(short) == 0);
	ok1((unsigned long)&lots_of_types.i % ALIGNOF(int) == 0);
	ok1((unsigned long)&lots_of_types.f % ALIGNOF(float) == 0);
	ok1(offsetof(struct lots_of_types, d) % ALIGNOF(double) == 0);

	ok1((unsigned long)&lp->c % ALIGNOF(char) == 0);
	ok1((unsigned long)&lp->s % ALIGNOF(short) == 0);
	ok1((unsigned long)&lp->i % ALIGNOF(int) == 0);
	ok1((unsigned long)&lp->f % ALIGNOF(float) == 0);
	ok1((unsigned long)&lp->d % ALIGNOF(double) == 0);
	exit(exit_status());
}
