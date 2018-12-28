#include "socket_close.h"
#include <ccan/noerr/noerr.h>
#include <errno.h>
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

bool socket_close(int fd)
{
	char unused[64];
	int sys_res;

	sys_res = shutdown(fd, SHUT_WR);
	if (sys_res < 0) {
		close_noerr(fd);
		return false;
	}

	for (;;) {
		do {
			sys_res = read(fd, unused, sizeof(unused));
		} while (sys_res < 0 && errno == EINTR);
		if (sys_res < 0) {
			close_noerr(fd);
			return false;
		}
		if (sys_res == 0)
			break;
	}

	if (close(fd) < 0)
		return false;
	else
		return true;
}
