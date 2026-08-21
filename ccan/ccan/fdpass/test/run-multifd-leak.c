/* Regression test: when the peer sends TWO fds in ONE SCM_RIGHTS cmsg
 * (cmsg_len = CMSG_LEN(2*sizeof(int))), fdpass_recv must reject the
 * message without leaking whatever fd(s) the kernel already installed
 * into this process.  On some ABIs (notably 32-bit, where
 * CMSG_SPACE(sizeof(int)) leaves room for only one fd's worth of
 * ancillary data) the kernel truncates the message down to what looks
 * like a legitimate single-fd receive, so the check can't rely on
 * cmsg_len alone and must also honour MSG_CTRUNC. */
#include <ccan/fdpass/fdpass.h>
/* Include the C files directly. */
#include <ccan/fdpass/fdpass.c>
#include <ccan/tap/tap.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>

static int count_fds(void)
{
	DIR *d = opendir("/dev/fd");
	struct dirent *de;
	int n = 0;

	if (!d)
		return -1;
	while ((de = readdir(d)) != NULL) {
		if (de->d_name[0] != '.')
			n++;
	}
	closedir(d);
	return n - 1; /* exclude the fd used by opendir itself */
}

static void send_two_fds(int sock, int fd1, int fd2)
{
	struct msghdr msg = { 0 };
	struct cmsghdr *cmsg;
	struct iovec iov;
	char c = 0;
	union {
		char buf[CMSG_SPACE(2 * sizeof(int))];
		struct cmsghdr align;
	} u;
	int fds[2] = { fd1, fd2 };

	memset(&u, 0, sizeof(u));
	msg.msg_control = u.buf;
	msg.msg_controllen = sizeof(u.buf);
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(2 * sizeof(int));
	memcpy(CMSG_DATA(cmsg), fds, sizeof(fds));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	iov.iov_base = &c;
	iov.iov_len = 1;
	sendmsg(sock, &msg, 0);
}

int main(void)
{
	int sv[2];
	int pfds[2];
	int before, after, i;

	alarm(10);
	plan_tests(5);

	ok1(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	ok1(pipe(pfds) == 0);
	ok1((before = count_fds()) >= 0);

	for (i = 0; i < 16; i++)
		send_two_fds(sv[1], pfds[0], pfds[0]);
	for (i = 0; i < 16; i++) {
		if (fdpass_recv(sv[0]) != -1)
			break;
	}
	ok1(i == 16);

	after = count_fds();
	ok(after == before,
	   "no fds leaked by rejected recvs (before=%d after=%d, leaked=%d)",
	   before, after, after - before);

	close(pfds[0]);
	close(pfds[1]);
	close(sv[0]);
	close(sv[1]);

	/* This exits depending on whether all tests passed */
	return exit_status();
}
