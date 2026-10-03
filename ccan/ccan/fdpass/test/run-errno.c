/* Temporary auditor regression test (audit 2026-08-05).
 * Proves: fdpass_recv sets errno = -EINVAL instead of EINVAL when the
 * peer's message carries no (valid) SCM_RIGHTS control message.
 * fdpass.h:20 documents "On failure, returns -1 and sets errno.";
 * errno values must be positive (EINVAL == 22, not -22).
 * Currently FAILS (errno == -EINVAL); must pass after repair. */
#include <ccan/fdpass/fdpass.h>
/* Include the C files directly. */
#include <ccan/fdpass/fdpass.c>
#include <ccan/tap/tap.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>

int main(void)
{
	int sv[2];

	alarm(10);
	plan_tests(5);

	ok1(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

	/* Case 1: plain data byte, no ancillary data at all. */
	ok1(write(sv[1], "1", 1) == 1);
	errno = 0;
	ok1(fdpass_recv(sv[0]) == -1 && errno == EINVAL);

	/* Case 2: orderly shutdown, nothing sent (recvmsg returns 0). */
	close(sv[0]);
	close(sv[1]);
	ok1(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	close(sv[1]);
	errno = 0;
	ok1(fdpass_recv(sv[0]) == -1 && errno == EINVAL);

	close(sv[0]);

	/* This exits depending on whether all tests passed */
	return exit_status();
}
