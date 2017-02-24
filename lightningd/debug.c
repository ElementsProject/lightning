#include <ccan/str/str.h>
#include <lightningd/debug.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

void subdaemon_debug(int argc, char *argv[])
{
	int i;
	bool printed = false;

	/* From debugger, tell gdb "return". */
	for (i = 1; i < argc; i++) {
		while (streq(argv[i], "--debugger")) {
			if (!printed)
				fprintf(stderr, "gdb -ex 'attach %u' %s\n",
					getpid(), argv[0]);
			printed = true;
		}
	}
}
