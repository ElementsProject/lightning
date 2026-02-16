#include "config.h"
#include <assert.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/tal/str/str.h>
#include <common/status_wiregen.h>
#include <common/utils.h>
#include <plugins/askrene/child/child_log.h>
#include <wire/wire_sync.h>

static int log_fd = -1;

static const char *child_logv(const tal_t *ctx,
			      enum log_level level,
			      const char *fmt,
			      va_list ap)
{
	const char *str = tal_vfmt(ctx, fmt, ap);
	u8 *msg;

	/* We reuse status_wire here */
	msg = towire_status_log(NULL, level, NULL, str);
	if (!wire_sync_write(log_fd, take(msg)))
		abort();
	return str;
}

const char *child_log(const tal_t *ctx,
		      enum log_level level,
		      const char *fmt,
		      ...)
{
	va_list args;
	const char *str;

	va_start(args, fmt);
	str = child_logv(ctx, level, fmt, args);
	va_end(args);
	return str;
}

void child_err(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	child_logv(tmpctx, LOG_BROKEN, fmt, args);
	va_end(args);

	abort();
}

void set_child_log_fd(int fd)
{
	assert(log_fd == -1);
	assert(fd != -1);
	log_fd = fd;
}
