#include <ccan/pipecmd/pipecmd.h>
/* Include the C files directly. */
#include <ccan/pipecmd/pipecmd.c>
#include <ccan/tap/tap.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>

int main(int argc, char *argv[])
{
	pid_t child;
	int fd, oldfd, status;
	char buf[5] = "test";
	char template[] = "/tmp/run-preserve.XXXXXX";

	/* We call ourselves, to test pipe. */
	if (argc == 2) {
		if (strcmp(argv[1], "out") == 0) {
			if (write(STDOUT_FILENO, buf, sizeof(buf)) != sizeof(buf))
				exit(2);
		} else if (strcmp(argv[1], "in") == 0) {
			if (read(STDIN_FILENO, buf, sizeof(buf)) != sizeof(buf))
				exit(3);
			if (memcmp(buf, "test", sizeof(buf)) != 0)
				exit(4);
		} else if (strcmp(argv[1], "err") == 0) {
			if (write(STDERR_FILENO, buf, sizeof(buf)) != sizeof(buf))
				exit(5);
		} else
			abort();
		exit(0);
	}

	/* This is how many tests you plan to run */
	plan_tests(25);

	/* Preserve stdin test. */
	fd = mkstemp(template);
	ok1(write(fd, buf, sizeof(buf)) == sizeof(buf));
	ok1(fd >= 0);
	ok1(dup2(fd, STDIN_FILENO) == STDIN_FILENO);
	ok1(lseek(STDIN_FILENO, 0, SEEK_SET) == 0);
	child = pipecmd(&pipecmd_preserve, NULL, NULL, argv[0], "in", NULL);
	if (!ok1(child > 0))
		exit(1);
	ok1(waitpid(child, &status, 0) == child);
	ok1(WIFEXITED(status));
	ok1(WEXITSTATUS(status) == 0);

	close(STDIN_FILENO);

	/* Preserve stdout test */
	fd = open(template, O_WRONLY|O_TRUNC);
	ok1(fd >= 0);
	oldfd = dup(STDOUT_FILENO);
	/* Can't use OK after this, since we mug stdout */
	if (dup2(fd, STDOUT_FILENO) != STDOUT_FILENO)
		exit(1);
	child = pipecmd(NULL, &pipecmd_preserve, NULL, argv[0], "out", NULL);
	if (child == -1)
		exit(1);
	/* Restore stdout */
	dup2(oldfd, STDOUT_FILENO);
	close(oldfd);
	ok1(waitpid(child, &status, 0) == child);
	ok1(WIFEXITED(status));
	ok1(WEXITSTATUS(status) == 0);

	fd = open(template, O_RDONLY);
	ok1(read(fd, buf, sizeof(buf)) == sizeof(buf));
	ok1(close(fd) == 0);
	ok1(memcmp(buf, "test", sizeof(buf)) == 0);

	/* Preserve stderr test. */
	fd = open(template, O_WRONLY|O_TRUNC);
	ok1(fd >= 0);
	oldfd = dup(STDERR_FILENO);
	ok1(dup2(fd, STDERR_FILENO) == STDERR_FILENO);
	child = pipecmd(NULL, NULL, &pipecmd_preserve, argv[0], "err", NULL);
	if (!ok1(child > 0))
		exit(1);

	/* Restore stderr. */
	ok1(dup2(oldfd, STDERR_FILENO));
	ok1(waitpid(child, &status, 0) == child);
	ok1(WIFEXITED(status));
	ok1(WEXITSTATUS(status) == 0);
	close(oldfd);

	fd = open(template, O_RDONLY);
	ok1(read(fd, buf, sizeof(buf)) == sizeof(buf));
	ok1(close(fd) == 0);
	ok1(memcmp(buf, "test", sizeof(buf)) == 0);
	unlink(template);

	/* This exits depending on whether all tests passed */
	return exit_status();
}
