#include "config.h"
#include <ccan/noerr/noerr.h>
#include <common/socket_close.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* makes read() return EINTR after 5 seconds */
static void break_read(int signum)
{
}

bool socket_close(int fd)
{
	char unused[64];
	struct sigaction act, old_act;
	int sys_res, saved_errno;

	/* We shutdown.  Usually they then shutdown too, and read() gives 0 */
	sys_res = shutdown(fd, SHUT_WR);
	if (sys_res < 0) {
		close_noerr(fd);
		return false;
	}

	/* Let's not get too enthusiastic about waiting. */
	memset(&act, 0, sizeof(act));
	act.sa_handler = break_read;
	sigaction(SIGALRM, &act, &old_act);

	alarm(5);

	while ((sys_res = read(fd, unused, sizeof(unused))) > 0);
	saved_errno = errno;

	alarm(0);
	sigaction(SIGALRM, &old_act, NULL);

	if (sys_res < 0) {
		close(fd);
		errno = saved_errno;
		return false;
	}

	return close(fd) == 0;
}
