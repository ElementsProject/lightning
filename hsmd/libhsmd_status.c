/* When running as a subdaemon controlled by lightningd the hsmd will
 * report logging, debugging information and crash reports to
 * lightningd via the status socket, using the wire protocol used in
 * LN more generally. This is done so lightningd can print add the
 * messages to its own logs, presenting a unified view of what is
 * happening.
 *
 * When using libhsmd not as a subdaemon controlled by lightningd we
 * cannot make use of the communication primitives we used in that
 * context. For this reason libhsmd defers the selection of actual
 * primitives to link time, and here we provide simple ones that just
 * print to stdout, as alternatives to the status wire protocol ones.
 */
#include "config.h"
#include <hsmd/libhsmd.h>
#include <stdio.h>
u8 *hsmd_status_bad_request(struct hsmd_client *client, const u8 *msg, const char *error)
{
	fprintf(stderr, "%s\n", error);
	return NULL;
}

void hsmd_status_fmt(enum log_level level, const struct node_id *peer,
		     const char *fmt, ...)
{
	va_list ap;
	char *msg;
	FILE *stream = level >= LOG_UNUSUAL ? stderr : stdout;
	va_start(ap, fmt);
	msg = tal_vfmt(NULL, fmt, ap);
	va_end(ap);

	if (peer != NULL)
		fprintf(stream, "[%s] %s: %s\n", log_level_name(level),
			node_id_to_hexstr(msg, peer), msg);
	else
		fprintf(stream, "[%s]: %s\n", log_level_name(level), msg);

	tal_free(msg);
}

void hsmd_status_failed(enum status_failreason reason, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	exit(0x80 | (reason & 0xFF));
}
