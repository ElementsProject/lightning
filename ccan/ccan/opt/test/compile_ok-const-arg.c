#include <ccan/opt/opt.h>
#include <ccan/opt/opt.c>
#include <ccan/opt/helpers.c>
#include <ccan/opt/parse.c>
#include <ccan/opt/usage.c>

int main(void)
{
	opt_register_noarg("-v", opt_version_and_exit,
			   (const char *)"1.2.3",
			   (const char *)"Print version");
	return 0;
}
