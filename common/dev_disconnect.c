#include <assert.h>
#include <ccan/err/err.h>
#include <ccan/str/str.h>
#include <common/dev_disconnect.h>
#include <common/status.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <wire/gen_peer_wire.h>

/* We move the fd IFF we do a disconnect. */
static int dev_disconnect_fd = -1;
static char dev_disconnect_line[200];
static int dev_disconnect_count, dev_disconnect_len;

bool dev_suppress_commit;

void dev_disconnect_init(int fd)
{
	int r;
	char *asterisk;

	r = read(fd, dev_disconnect_line, sizeof(dev_disconnect_line)-1);
	if (r < 0)
		err(1, "Reading dev_disconnect file");
	lseek(fd, -r, SEEK_CUR);

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

	/* So we can move forward if we do use the line. */
	dev_disconnect_fd = fd;
}

enum dev_disconnect dev_disconnect(int pkt_type)
{
	if (!streq(wire_type_name(pkt_type), dev_disconnect_line+1))
		return DEV_DISCONNECT_NORMAL;

	if (dev_disconnect_count != 1) {
		dev_disconnect_count--;
		return DEV_DISCONNECT_NORMAL;
	}

	assert(dev_disconnect_fd != -1);
	lseek(dev_disconnect_fd, dev_disconnect_len+1, SEEK_CUR);

	status_trace("dev_disconnect: %s", dev_disconnect_line);

	if (dev_disconnect_line[0] == DEV_DISCONNECT_SUPPRESS_COMMIT)
		dev_suppress_commit = true;
	return dev_disconnect_line[0];
}

void dev_sabotage_fd(int fd)
{
	int fds[2];

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0)
		err(1, "dev_sabotage_fd: creating socketpair");

	/* Close one. */
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

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0)
		err(1, "dev_blackhole_fd: creating socketpair");

	switch (fork()) {
	case -1:
		err(1, "dev_blackhole_fd: forking");
	case 0:
		/* Close everything but the dev_disconnect_fd, the socket
		 * which is pretending to be the peer, and stderr. */
		for (i = 0; i < sysconf(_SC_OPEN_MAX); i++)
			if (i != fds[0]
			    && i != dev_disconnect_fd
			    && i != STDERR_FILENO)
				close(i);

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
