#include "config.h"
#include <stdio.h>
#include <string.h>

/**
 * noerr - routines for cleaning up without blatting errno
 *
 * It is a good idea to follow the standard C convention of setting errno in
 * your own helper functions.  Unfortunately, care must be taken in the error
 * paths as most standard functions can (and do) overwrite errno, even if they
 * succeed.
 *
 * Example:
 *	#include <sys/types.h>
 *	#include <sys/stat.h>
 *	#include <fcntl.h>
 *	#include <stdbool.h>
 *	#include <string.h>
 *	#include <errno.h>
 *	#include <ccan/noerr/noerr.h>
 *
 *	static bool write_string_to_file(const char *file, const char *string)
 *	{
 *		int ret, fd = open(file, O_WRONLY|O_CREAT|O_EXCL, 0600);
 *		if (fd < 0)
 *			return false;
 *		ret = write(fd, string, strlen(string));
 *		if (ret < 0) {
 *			// Preserve errno from write above.
 *			close_noerr(fd);
 *			unlink_noerr(file);
 *			return false;
 *		}
 *		if (close(fd) != 0) {
 *			// Again, preserve errno.
 *			unlink_noerr(file);
 *			return false;
 *		}
 *		// A short write means out of space.
 *		if (ret < (int)strlen(string)) {
 *			unlink(file);
 *			errno = ENOSPC;
 *			return false;
 *		}
 *		return true;
 *	}
 *
 * License: CC0 (Public domain)
 * Author: Rusty Russell <rusty@rustcorp.com.au>
 */
int main(int argc, char *argv[])
{
	if (argc != 2)
		return 1;

	if (strcmp(argv[1], "depends") == 0)
		/* Nothing. */
		return 0;

	return 1;
}
