#include <ccan/container_of/container_of.h>
#include <ccan/tap/tap.h>

struct foo {
	int a;
	char b;
};

int main(void)
{
	struct foo foo = { .a = 1, .b = 2 };
	int *intp = &foo.a;
	char *charp = &foo.b;

	plan_tests(12);
	ok1(container_of(intp, struct foo, a) == &foo);
	ok1(container_of(charp, struct foo, b) == &foo);
	ok1(container_of_or_null(intp, struct foo, a) == &foo);
	ok1(container_of_or_null(charp, struct foo, b) == &foo);
	ok1(container_of_or_null((int *)NULL, struct foo, a) == NULL);
	ok1(container_of_or_null((char *)NULL, struct foo, b) == NULL);
	ok1(container_of_var(intp, &foo, a) == &foo);
	ok1(container_of_var(charp, &foo, b) == &foo);

	ok1(container_off(struct foo, a) == 0);
	ok1(container_off(struct foo, b) == offsetof(struct foo, b));
	ok1(container_off_var(&foo, a) == 0);
	ok1(container_off_var(&foo, b) == offsetof(struct foo, b));
	return exit_status();
}
