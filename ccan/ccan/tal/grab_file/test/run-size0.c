#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/tal/grab_file/grab_file.c>
#include <ccan/tap/tap.h>
#include <string.h>
#include <unistd.h>

/* /proc (and /sys) files are S_ISREG with st_size == 0, yet have
 * content: grab_file must not return an empty buffer for them. */
int main(void)
{
	char *s;

	plan_tests(2);
	if (access("/proc/self/status", R_OK) != 0)
		skip(2, "no /proc/self/status");
	else {
		s = grab_file_str(NULL, "/proc/self/status");
		ok1(s != NULL);
		ok1(s && strlen(s) > 0);
		tal_free(s);
	}

	tal_cleanup();
	return exit_status();
}
