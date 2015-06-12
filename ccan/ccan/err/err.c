/* CC0 (Public domain) - see LICENSE file for details */
#include "err.h"

#if !HAVE_ERR_H
#include <stdarg.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

static const char *progname = "unknown program";

void err_set_progname(const char *name)
{
	progname = name;
}

void NORETURN err(int eval, const char *fmt, ...)
{
	int err_errno = errno;
	va_list ap;

	fprintf(stderr, "%s: ", progname);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, ": %s\n", strerror(err_errno));
	exit(eval);
}

void NORETURN errx(int eval, const char *fmt, ...)
{
	va_list ap;

	fprintf(stderr, "%s: ", progname);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
	exit(eval);
}

void warn(const char *fmt, ...)
{
	int err_errno = errno;
	va_list ap;

	fprintf(stderr, "%s: ", progname);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, ": %s\n", strerror(err_errno));
}

void warnx(const char *fmt, ...)
{
	va_list ap;

	fprintf(stderr, "%s: ", progname);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}
#endif
