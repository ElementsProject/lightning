#include <ccan/container_of/container_of.h>
#include <stdlib.h>

struct foo {
	int a;
	char b;
};

int main(int argc, char *argv[])
{
	struct foo foo = { .a = 1, .b = 2 }, *foop;
	int *intp = &foo.a;

#ifdef FAIL
	/* b is a char, but intp is an int * */
	foop = container_of_var(intp, foop, b);
#if !HAVE_TYPEOF
#error "Unfortunately we don't fail if we don't have typeof."
#endif
#else
	foop = NULL;
#endif
	(void) foop; /* Suppress unused-but-set-variable warning. */
	return intp == NULL;
}
