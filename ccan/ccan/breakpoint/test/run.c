#include <ccan/breakpoint/breakpoint.h>
#include <ccan/breakpoint/breakpoint.c>
#include <ccan/tap/tap.h>

int main(void)
{
	/* This is how many tests you plan to run */
	plan_tests(2);

	breakpoint();

	ok1(breakpoint_initialized);
	ok1(!breakpoint_under_debug);

	/* This exits depending on whether all tests passed */
	return exit_status();
}
