#include <ccan/check_type/check_type.h>
#include <ccan/tap/tap.h>

int main(int argc, char *argv[])
{
	int x = 0, y = 0;

	plan_tests(9);

	ok1(check_type(argc, int) == 0);
	ok1(check_type(&argc, int *) == 0);
	ok1(check_types_match(argc, argc) == 0);
	ok1(check_types_match(argc, x) == 0);
	ok1(check_types_match(&argc, &x) == 0);

	ok1(check_type(x++, int) == 0);
	ok(x == 0, "check_type does not evaluate expression");
	ok1(check_types_match(x++, y++) == 0);
	ok(x == 0 && y == 0, "check_types_match does not evaluate expressions");

	return exit_status();
}
