#include <ccan/tal/path/path.h>
#include <ccan/tal/path/path.c>
#include <ccan/tap/tap.h>

int main(void)
{
	plan_tests(9);

	ok1(path_ext_off("foo") == 3);
	ok1(path_ext_off(".foo") == 4);
	ok1(path_ext_off("bar.foo") == 3);
	ok1(path_ext_off("bar/foo") == 7);
	ok1(path_ext_off("bar/.foo") == 8);
	ok1(path_ext_off(".bar/foo") == 8);
	ok1(path_ext_off("foo.bar/foo") == 11);
	ok1(path_ext_off("foo.bar/foo.") == 11);
	ok1(path_ext_off("foo.bar/foo..") == 12);
	return exit_status();
}
