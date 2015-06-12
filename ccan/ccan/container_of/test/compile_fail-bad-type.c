#include <ccan/container_of/container_of.h>
#include <stdlib.h>

struct foo {
	int a;
	char b;
};

int main(int argc, char *argv[])
{
	struct foo foo = { .a = 1, .b = 2 };
	int *intp = &foo.a;
	char *p;

#ifdef FAIL
	/* p is a char *, but this gives a struct foo * */
	p = container_of(intp, struct foo, a);
#else
	p = (char *)intp;
#endif
	return p == NULL;
}
