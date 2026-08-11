#include "config.h"
#include <assert.h>
#include <common/utils.h>
#include <errno.h>
#include <poll.h>
#include <wire/wire_io.h>
#include <wire/wire_sync.h>

/* Wait until fd is ready (readable or writable), tolerating EINTR. */
static bool wait_fd(int fd, short events)
{
	int r;

	do {
		r = poll(&(struct pollfd){.fd = fd, .events = events}, 1, -1);
	} while (r < 0 && errno == EINTR);

	return r > 0;
}

/* Like read_all, but tolerates an fd with O_NONBLOCK set: on EAGAIN we poll
 * for readability and resume, preserving any partial read.  Subdaemon HSM fds
 * can be O_NONBLOCK on macOS (the flag follows the shared open file
 * description as the socketpair is sent via SCM_RIGHTS), so without this we
 * would spuriously fail with EAGAIN. */
static bool read_all_tolerant(int fd, void *buf, size_t size)
{
	while (size) {
		ssize_t done = read(fd, buf, size);
		if (done < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				if (!wait_fd(fd, POLLIN))
					return false;
				continue;
			}
			return false;
		}
		if (done == 0)
			return false;
		buf = (char *)buf + done;
		size -= done;
	}

	return true;
}

/* Mirror of read_all_tolerant for writes. */
static bool write_all_tolerant(int fd, const void *buf, size_t size)
{
	while (size) {
		ssize_t done = write(fd, buf, size);
		if (done < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				if (!wait_fd(fd, POLLOUT))
					return false;
				continue;
			}
			return false;
		}
		if (done == 0)
			return false;
		buf = (const char *)buf + done;
		size -= done;
	}

	return true;
}

bool wire_sync_write(int fd, const void *msg TAKES)
{
	wire_len_t hdr = cpu_to_wirelen(tal_bytelen(msg));
	bool ret;

	assert(tal_bytelen(msg) < WIRE_LEN_LIMIT);
	ret = write_all_tolerant(fd, &hdr, sizeof(hdr))
		&& write_all_tolerant(fd, msg, tal_count(msg));

	tal_free_if_taken(msg);
	return ret;
}

u8 *wire_sync_read(const tal_t *ctx, int fd)
{
	wire_len_t len;
	u8 *msg;

	if (!read_all_tolerant(fd, &len, sizeof(len)))
		return NULL;
	if (wirelen_to_cpu(len) >= WIRE_LEN_LIMIT) {
		errno = E2BIG;
		return NULL;
	}
	msg = tal_arr(ctx, u8, wirelen_to_cpu(len));
	if (!read_all_tolerant(fd, msg, wirelen_to_cpu(len)))
		return tal_free(msg);
	return msg;
}
