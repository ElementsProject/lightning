#include "config.h"
#include <stdio.h>
#include <string.h>

/**
 * daemonize - routine to turn a process into a well-behaved daemon.
 *
 * Daemons should detach themselves thoroughly from the process which launched
 * them, and not prevent any filesystems from being unmounted.  daemonize()
 * helps with the process.
 *
 * Example:
 *	#include <ccan/daemonize/daemonize.h>
 *	#include <ccan/str/str.h>
 *	#include <err.h>
 *	#include <unistd.h>
 *	#include <stdlib.h>
 *	
 *	static void usage(const char *name)
 *	{
 *		errx(1, "Usage: %s [--daemonize]\n", name);
 *	}
 *	
 *	// Wait for a minute, possibly as a daemon.
 *	int main(int argc, char *argv[])
 *	{
 *		if (argc != 1) {
 *			if (argc == 2 && streq(argv[1], "--daemonize")) {
 *				if (!daemonize())
 *					err(1, "Failed to become daemon");
 *			} else
 *				usage(argv[1]);
 *		}
 *		sleep(60);
 *		exit(0);
 *	}
 *
 * License: BSD-MIT
 */
int main(int argc, char *argv[])
{
	if (argc != 2)
		return 1;

	if (strcmp(argv[1], "depends") == 0) {
		return 0;
	}

	if (strcmp(argv[1], "libs") == 0) {
		return 0;
	}

	return 1;
}
