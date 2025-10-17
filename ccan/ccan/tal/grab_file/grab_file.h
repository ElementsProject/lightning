/* Licensed under LGPLv2+ - see LICENSE file for details */
#ifndef CCAN_TAL_GRAB_FILE_H
#define CCAN_TAL_GRAB_FILE_H
#include <stdio.h> // For size_t
#include <ccan/compiler/compiler.h>

/**
 * grab_fd_raw - read all of a file descriptor into memory WITHOUT adding a nul.
 * @ctx: the context to tallocate from (often NULL)
 * @fd: the file descriptor to read from
 * @size: the (optional) size of the file
 *
 * This function reads from the given file descriptor until no more
 * input is available.  The content is talloced off @ctx, and the
 * tal_count() is the size in bytes.
 *
 * Note that this does *not* currently exit on EINTR, but continues
 * reading. *
 * Example:
 *	// Return the first line.
 *	static char *read_stdin_all(void)
 *	{
 *		return grab_fd_raw(NULL, 0);
 *	}
 */
void *grab_fd_raw(const void *ctx, int fd);

/**
 * grab_fd_str - read all of a file descriptor into memory with a NUL terminator.
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
 *		all = grab_fd_str(NULL, 0);
 *		if (!all)
 *			return NULL;
 *		lines = tal_strsplit(NULL, all, "\n", STR_EMPTY_OK);
 *		tal_free(all);
 *		return lines;
 *	}
 */
void *grab_fd_str(const void *ctx, int fd);

/* Deprecated synonym for grab_fd_str */
static inline void *grab_fd(const void *ctx, int fd)
	WARN_DEPRECATED;
static inline void *grab_fd(const void *ctx, int fd)
{
	return grab_fd_str(ctx, fd);
}

/**
 * grab_file_str - read all of a file (or stdin) into memory with a NUL terminator
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
 *		all = grab_file_str(NULL, filename);
 *		if (!all)
 *			return NULL;
 *		lines = tal_strsplit(NULL, all, "\n", STR_EMPTY_OK);
 *		tal_free(all);
 *		return lines;
 *	}
 */
void *grab_file_str(const void *ctx, const char *filename);

/**
 * grab_file_raw - read all of a file (or stdin) into memory WITHOUT a NUL terminator
 * @ctx: the context to tallocate from (often NULL)
 * @filename: the file to read (NULL for stdin)
 * @size: the (optional) size of the file
 *
 * This function reads from the given file until no more input is
 * available.  The content is talloced off @ctx, and the tal_count()
 * is the size in bytes.
 *
 * Example:
 *	static char *read_file_all(const char *filename)
 *	{
 *		return grab_file_raw(NULL, filename);
 *	}
 */
void *grab_file_raw(const void *ctx, const char *filename);

/* Deprecated synonym for grab_file_str */
static inline void *grab_file(const void *ctx, const char *filename)
	WARN_DEPRECATED;
static inline void *grab_file(const void *ctx, const char *filename)
{
	return grab_file_str(ctx, filename);
}

#endif /* CCAN_TAL_GRAB_FILE_H */
