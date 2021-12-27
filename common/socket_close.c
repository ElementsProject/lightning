#include "config.h"
#include <ccan/noerr/noerr.h>
#include <common/socket_close.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/*
Simplified (minus all the error checks):

	shutdown(fd, SHUT_WR);
	for (;;) {
		char unused[64]
		sys_res = read(fd, unused, 64);
		if (sys_res == 0)
			break;
	}
	close(fd);
*/

/* makes read() return EINTR */
static void break_read(int signum)
{
}

bool socket_close(int fd)
{
	char unused[64];
	struct sigaction act, old_act;
	int sys_res;

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

	alarm(0);
	sigaction(SIGALRM, &old_act, NULL);

	if (sys_res < 0) {
		close_noerr(fd);
		return false;
	}

	return close(fd) == 0;
}
