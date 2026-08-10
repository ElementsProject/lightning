/* Regression test: pipecmdarr leaks the parent-side pipe fds when
 * (a) the exec fails (child reports errno via the execfail pipe), or
 * (b) pipe()/fcntl()/fork() fails after the command pipes were created.
 * Both paths only close par_close[] and forget tochild[1], fromchild[0]
 * and errfromchild[0]. */
#include <ccan/pipecmd/pipecmd.h>
/* Include the C files directly. */
#include <ccan/pipecmd/pipecmd.c>
#include <ccan/tap/tap.h>
#include <string.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/resource.h>

static int count_fds(void)
{
	DIR *d = opendir("/proc/self/fd");
	struct dirent *de;
	int n = 0;

	if (!d)
		return -1;
	while ((de = readdir(d)) != NULL) {
		if (de->d_name[0] != '.')
			n++;
	}
	closedir(d);
	return n;
}


#if defined(__has_include)
#if __has_include(<valgrind/valgrind.h>)
#include <valgrind/valgrind.h>
#define HAVE_VALGRIND_H 1
#endif
#endif

int main(void)
{
#ifdef HAVE_VALGRIND_H
	/* valgrind perturbs the child-exit/fd-count behavior this test
	 * measures. */
	if (RUNNING_ON_VALGRIND) {
		plan_skip_all("not meaningful under valgrind");
		return exit_status();
	}
#endif
	pid_t child;
	int infd, outfd, errfd, before, after, saved_errno;
	struct rlimit rl, saved;
	char *const arr[] = { (char *)"/bin/true", NULL };

	alarm(10);
	plan_tests(5);

	/* (a) exec failure with all pipes requested must not leak fds. */
	before = count_fds();
	errno = 0;
	child = pipecmd(&infd, &outfd, &errfd, "/doesnotexist", NULL);
	saved_errno = errno;
	ok1(child == -1);
	ok1(saved_errno == ENOENT);
	after = count_fds();
	ok1(after == before);

	/* (b) pipe(execfail) failing after the three command pipes were
	 * created must not leak the parent-side ends either. */
	getrlimit(RLIMIT_NOFILE, &saved);
	before = count_fds();
	rl = saved;
	/* Room for exactly the three command pipes (6 fds). */
	rl.rlim_cur = before + 6;
	if (setrlimit(RLIMIT_NOFILE, &rl) != 0) {
		ok(0, "setrlimit failed");
		exit(1);
	}
	errno = 0;
	child = pipecmdarr(&infd, &outfd, &errfd, arr);
	saved_errno = errno;
	setrlimit(RLIMIT_NOFILE, &saved);
	ok1(child == -1 && saved_errno == EMFILE);
	after = count_fds();
	ok1(after == before);

	return exit_status();
}
