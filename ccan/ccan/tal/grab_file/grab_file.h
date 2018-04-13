/* Licensed under LGPLv2+ - see LICENSE file for details */
#ifndef CCAN_TAL_GRAB_FILE_H
#define CCAN_TAL_GRAB_FILE_H
#include <stdio.h> // For size_t

/**
 * grab_fd - read all of a file descriptor into memory
 * @ctx: the context to tallocate from (often NULL)
 * @fd: the file descriptor to read from
 *
 * This function reads from the given file descriptor until no more
 * input is available.  The content is talloced off @ctx, and the
 * tal_count() is the size in bytes plus one: for convenience, the
 * byte after the end of the content will always be NUL.
 *
 * Note that this does *not* currently exit on EINTR, but continues
 * reading.
 *
 * Example:
 *	#include <ccan/tal/str/str.h>
 *	#include <ccan/tal/tal.h>
 *	...
 *	// Return all of standard input, as lines.
 *	static char **read_stdin_as_lines(void)
 *	{
 *		char **lines, *all;
 *
 *		all = grab_fd(NULL, 0);
 *		if (!all)
 *			return NULL;
 *		lines = tal_strsplit(NULL, all, "\n", STR_EMPTY_OK);
 *		tal_free(all);
 *		return lines;
 *	}
 */
void *grab_fd(const void *ctx, int fd);

/**
 * grab_file - read all of a file (or stdin) into memory
 * @ctx: the context to tallocate from (often NULL)
 * @filename: the file to read (NULL for stdin)
 *
 * This function reads from the given file until no more input is
 * available.  The content is talloced off @ctx, and the tal_count()
 * is the size in bytes plus one: for convenience, the byte after the
 * end of the content will always be NUL.
 *
 * Example:
 *	// Return all of a given file, as lines.
 *	static char **read_file_as_lines(const char *filename)
 *	{
 *		char **lines, *all;
 *
 *		all = grab_file(NULL, filename);
 *		if (!all)
 *			return NULL;
 *		lines = tal_strsplit(NULL, all, "\n", STR_EMPTY_OK);
 *		tal_free(all);
 *		return lines;
 *	}
 */
void *grab_file(const void *ctx, const char *filename);
#endif /* CCAN_TAL_GRAB_FILE_H */
