/* CC0 (Public domain) - see LICENSE file for details */
#ifndef CCAN_ERR_H
#define CCAN_ERR_H
#include "config.h"

#if HAVE_ERR_H
#include <err.h>

/* This is unnecessary with a real err.h.  See below */
#define err_set_progname(name) ((void)name)

#else
#include <ccan/compiler/compiler.h>

/**
 * err_set_progname - set the program name
 * @name: the name to use for err, errx, warn and warnx
 *
 * The BSD err.h calls know the program name, unfortunately there's no
 * portable way for the CCAN replacements to do that on other systems.
 *
 * If you don't call this with argv[0], it will be "unknown program".
 *
 * Example:
 *	err_set_progname(argv[0]);
 */
void err_set_progname(const char *name);

/**
 * err - exit(eval) with message based on format and errno.
 * @eval: the exit code
 * @fmt: the printf-style format string
 *
 * The format string is printed to stderr like so:
 *	<executable name>: <format>: <strerror(errno)>\n
 *
 * Example:
 *	char *p = strdup("hello");
 *	if (!p)
 *		err(1, "Failed to strdup 'hello'");
 */
void NORETURN err(int eval, const char *fmt, ...);

/**
 * errx - exit(eval) with message based on format.
 * @eval: the exit code
 * @fmt: the printf-style format string
 *
 * The format string is printed to stderr like so:
 *	<executable name>: <format>\n
 *
 * Example:
 *	if (argc != 1)
 *		errx(1, "I don't expect any arguments");
 */
void NORETURN errx(int eval, const char *fmt, ...);

/**
 * warn - print a message to stderr based on format and errno.
 * @eval: the exit code
 * @fmt: the printf-style format string
 *
 * The format string is printed to stderr like so:
 *	<executable name>: <format>: <strerror(errno)>\n
 *
 * Example:
 *	char *p = strdup("hello");
 *	if (!p)
 *		warn("Failed to strdup 'hello'");
 */
void warn(const char *fmt, ...);

/**
 * warnx - print a message to stderr based on format.
 * @eval: the exit code
 * @fmt: the printf-style format string
 *
 * The format string is printed to stderr like so:
 *	<executable name>: <format>\n
 *
 * Example:
 *	if (argc != 1)
 *		warnx("I don't expect any arguments (ignoring)");
 */
void warnx(const char *fmt, ...);
#endif

#endif /* CCAN_ERR_H */
