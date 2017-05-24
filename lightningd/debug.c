#include <ccan/str/str.h>
#include <lightningd/debug.h>
#include <lightningd/dev_disconnect.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

void subdaemon_debug(int argc, char *argv[])
{
	int i;
	bool printed = false;

	for (i = 1; i < argc; i++) {
		if (strstarts(argv[i], "--dev-disconnect=")) {
			dev_disconnect_init(atoi(argv[i]
						 + strlen("--dev-disconnect=")));
		}
	}

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
