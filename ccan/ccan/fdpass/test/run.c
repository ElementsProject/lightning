#include <ccan/fdpass/fdpass.h>
/* Include the C files directly. */
#include <ccan/fdpass/fdpass.c>
#include <ccan/tap/tap.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>

static void child(int sockfd)
{
	char c;
	int newfd = fdpass_recv(sockfd);
	assert(newfd >= 0);
	assert(read(newfd, &c, 1) == 1);
	assert(c == 0x77);
	exit(0);
}

static void child_nofd(int sockfd)
{
	assert(fdpass_recv(sockfd) == -1);
	exit(0);
}

static void parent(int sockfd)
{
	int pfds[2];

	ok1(pipe(pfds) == 0);
	ok1(fdpass_send(sockfd, pfds[0]));
	ok1(close(pfds[0]) == 0);
	ok1(write(pfds[1], "\x77", 1) == 1);
	ok1(close(pfds[1]) == 0);
}

int main(void)
{
	int sv[2];
	int pid, wstatus;

	plan_tests(17);
	ok1(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

	pid = fork();
	if (pid == 0) {
		close(sv[1]);
		child(sv[0]);
	}

	parent(sv[1]);
	ok1(waitpid(pid, &wstatus, 0) == pid);
	ok1(WIFEXITED(wstatus));
	ok1(WEXITSTATUS(wstatus) == 0);

	pid = fork();
	if (pid == 0) {
		close(sv[1]);
		child_nofd(sv[0]);
	}
	/* Don't write an fd. */
	ok1(write(sv[1], "1", 1) == 1);
	ok1(waitpid(pid, &wstatus, 0) == pid);
	ok1(WIFEXITED(wstatus));
	ok1(WEXITSTATUS(wstatus) == 0);
	
	pid = fork();
	if (pid == 0) {
		close(sv[1]);
		child_nofd(sv[0]);
	}
	/* Don't write anything. */
	close(sv[1]);
	ok1(waitpid(pid, &wstatus, 0) == pid);
	ok1(WIFEXITED(wstatus));
	ok1(WEXITSTATUS(wstatus) == 0);
	
	close(sv[0]);
	/* Test fdpass_recv from invalid fd. */
	ok1(fdpass_recv(sv[0]) == -1 && errno == EBADF);

	/* This exits depending on whether all tests passed */
	return exit_status();
}
