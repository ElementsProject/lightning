#include "config.h"
#include <ccan/closefrom/closefrom.h>
#include <ccan/err/err.h>
#include <common/dev_disconnect.h>
#include <common/status.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <wire/peer_wire.h>

#if DEVELOPER
/* We move the fd if and only if we do a disconnect. */
static int dev_disconnect_fd = -1;
static char dev_disconnect_line[200];
static int dev_disconnect_count, dev_disconnect_len;

static void next_dev_disconnect(void)
{
	int r;
	char *asterisk;

	r = read(dev_disconnect_fd,
		 dev_disconnect_line, sizeof(dev_disconnect_line)-1);
	if (r < 0)
		err(1, "Reading dev_disconnect file");
	if (lseek(dev_disconnect_fd, -r, SEEK_CUR) < 0) {
		err(1, "lseek failure");
	}

	/* Get first line */
	dev_disconnect_line[r] = '\n';
	dev_disconnect_len = strcspn(dev_disconnect_line, "\n");
	dev_disconnect_line[dev_disconnect_len] = '\0';

	asterisk = strchr(dev_disconnect_line, '*');
	if (asterisk) {
		dev_disconnect_count = atoi(asterisk+1);
		if (dev_disconnect_count < 1)
			errx(1, "dev_disconnect invalid count: %s",
			     dev_disconnect_line);
		*asterisk = '\0';
	} else
		dev_disconnect_count = 1;
}

void dev_disconnect_init(int fd)
{
	/* So we can move forward if we do use the line. */
	dev_disconnect_fd = fd;
}

enum dev_disconnect dev_disconnect(const struct node_id *id, int pkt_type)
{
	if (dev_disconnect_fd == -1)
		return DEV_DISCONNECT_NORMAL;

	if (!dev_disconnect_count)
		next_dev_disconnect();

	if (!dev_disconnect_line[0]
	    || !streq(peer_wire_name(pkt_type), dev_disconnect_line+1))
		return DEV_DISCONNECT_NORMAL;

	if (--dev_disconnect_count != 0) {
		return DEV_DISCONNECT_NORMAL;
	}

	if (lseek(dev_disconnect_fd, dev_disconnect_len+1, SEEK_CUR) < 0) {
		err(1, "lseek failure");
	}

	status_peer_debug(id, "dev_disconnect: %s (%s)", dev_disconnect_line,
			  peer_wire_name(pkt_type));
	return dev_disconnect_line[0];
}

void dev_sabotage_fd(int fd, bool close_fd)
{
	int fds[2];

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0)
		err(1, "dev_sabotage_fd: creating socketpair");

#if defined(TCP_NODELAY)
	/* On Linux, at least, this flushes. */
	int opt = TCP_NODELAY;
	int val = 1;
	setsockopt(fd, IPPROTO_TCP, opt, &val, sizeof(val));
#else
#error No TCP_NODELAY?
#endif

	/* Move fd out the way if we don't want to close it. */
	if (!close_fd) {
		if (dup(fd) == -1) {
			; /* -Wunused-result */
		}
	} else
		/* Close other end of socket. */
		close(fds[0]);

	/* Move other over to the fd we want to sabotage. */
	dup2(fds[1], fd);
	close(fds[1]);
}

/* Replace fd with blackhole until dev_disconnect file is truncated. */
void dev_blackhole_fd(int fd)
{
	int fds[2];
	int i;
	struct stat st;

	int maxfd;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0)
		err(1, "dev_blackhole_fd: creating socketpair");

	switch (fork()) {
	case -1:
		err(1, "dev_blackhole_fd: forking");
	case 0:
		/* Close everything but the dev_disconnect_fd, the socket
		 * which is pretending to be the peer, and stderr.
		 * The "correct" way to do this would be to move the
		 * fds we want to preserve to the low end (0, 1, 2...)
		 * of the fd space and then just do a single closefrom
		 * call, but dup2 could fail with ENFILE (which is a
		 * *system*-level error, i.e. the entire system has too
		 * many processes with open files) and we have no
		 * convenient way to inform the parent of the error.
		 * So loop until we reach whichever is higher of fds[0]
		 * or dev_disconnect_fd, and *then* closefrom after that.
		 */
		maxfd = (fds[0] > dev_disconnect_fd) ? fds[0] :
						       dev_disconnect_fd ;
		for (i = 0; i < maxfd; i++)
			if (i != fds[0]
			    && i != dev_disconnect_fd
			    && i != STDERR_FILENO)
				close(i);
		closefrom(maxfd + 1);

		/* Close once dev_disconnect file is truncated. */
		for (;;) {
			if (fstat(dev_disconnect_fd, &st) != 0)
				err(1, "fstat of dev_disconnect_fd failed");
			if (st.st_size == 0)
				_exit(0);
			sleep(1);
		}
	}

	close(fds[0]);
	dup2(fds[1], fd);
	close(fds[1]);
}
#endif
