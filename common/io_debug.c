#include <ccan/err/err.h>
#include <ccan/take/take.h>
#include <common/io_debug.h>
#include <common/utils.h>

int debug_poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
	const char *t;

	t = taken_any();
	if (t)
		errx(1, "Outstanding taken pointers: %s", t);

	t = tmpctx_any();
	if (t)
		errx(1, "Outstanding tmpctx: %s", t);

	return poll(fds, nfds, timeout);
}
