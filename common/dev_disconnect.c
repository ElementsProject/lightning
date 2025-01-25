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

enum dev_disconnect_out dev_disconnect_out(const struct node_id *id, int pkt_type)
{
	if (dev_disconnect_fd == -1)
		return DEV_DISCONNECT_OUT_NORMAL;

	if (!dev_disconnect_count)
		next_dev_disconnect();

	if (!dev_disconnect_line[0]
	    || !streq(peer_wire_name(pkt_type), dev_disconnect_line+1))
		return DEV_DISCONNECT_OUT_NORMAL;

	if (--dev_disconnect_count != 0) {
		return DEV_DISCONNECT_OUT_NORMAL;
	}

	if (lseek(dev_disconnect_fd, dev_disconnect_len+1, SEEK_CUR) < 0) {
		err(1, "lseek failure");
	}

	status_peer_debug(id, "dev_disconnect: %s (%s)",
			  dev_disconnect_line,
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
