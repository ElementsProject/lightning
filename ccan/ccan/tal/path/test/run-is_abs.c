#include <ccan/tal/path/path.h>
#include <ccan/tal/path/path.c>
#include <ccan/tap/tap.h>

int main(void)
{
	plan_tests(5);

	ok1(path_is_abs(PATH_SEP_STR "foo"));
	ok1(!path_is_abs("foo"));
	ok1(!path_is_abs("foo" PATH_SEP_STR));

	ok1(path_is_abs(PATH_SEP_STR "foo" PATH_SEP_STR));
	ok1(path_is_abs(PATH_SEP_STR "."));
	return exit_status();
}
