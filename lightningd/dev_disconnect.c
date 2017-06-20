#include <assert.h>
#include <ccan/err/err.h>
#include <ccan/str/str.h>
#include <lightningd/dev_disconnect.h>
#include <lightningd/status.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <wire/gen_peer_wire.h>

/* We move the fd IFF we do a disconnect. */
static int dev_disconnect_fd = -1;
static char dev_disconnect_line[200];

void dev_disconnect_init(int fd)
{
	int r;

	r = read(fd, dev_disconnect_line, sizeof(dev_disconnect_line)-1);
	if (r < 0)
		err(1, "Reading dev_disconnect file");
	lseek(fd, -r, SEEK_CUR);

	/* Get first line */
	dev_disconnect_line[r] = '\n';
	*strchr(dev_disconnect_line, '\n') = '\0';

	/* So we can move forward if we do use the line. */
	dev_disconnect_fd = fd;
}

char dev_disconnect(int pkt_type)
{
	if (!streq(wire_type_name(pkt_type), dev_disconnect_line+1))
		return DEV_DISCONNECT_NORMAL;

	assert(dev_disconnect_fd != -1);
	lseek(dev_disconnect_fd, strlen(dev_disconnect_line)+1, SEEK_CUR);

	status_trace("dev_disconnect: %s", dev_disconnect_line);
	return dev_disconnect_line[0];
}

void dev_sabotage_fd(int fd)
{
	int fds[2];

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0)
		errx(1, "dev_sabotage_fd: creating socketpair");

	/* Close one. */
	close(fds[0]);
	/* Move other over to the fd we want to sabotage. */
	dup2(fds[1], fd);
	close(fds[1]);
}
