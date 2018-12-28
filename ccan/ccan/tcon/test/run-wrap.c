#include <ccan/tcon/tcon.h>
#include <ccan/tap/tap.h>
#include <stdlib.h>

typedef TCON_WRAP(int, char *canary) canaried_int;

int main(void)
{
	canaried_int ci = TCON_WRAP_INIT(0);

	plan_tests(2);

	ok1(*tcon_unwrap(&ci) == 0);
	*tcon_unwrap(&ci) = 17;
	ok1(*tcon_unwrap(&ci) == 17);

	return exit_status();
}
