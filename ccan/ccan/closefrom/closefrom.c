/* CC0 license (public domain) - see LICENSE file for details */
#include <ccan/closefrom/closefrom.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <unistd.h>

/* See also:
 * https://stackoverflow.com/a/918469
 *
 * The implementation below is not exhaustive of all the suggested above.
 */

#if !HAVE_CLOSEFROM

/* IBM AIX.
 * https://www.ibm.com/docs/en/aix/7.2?topic=f-fcntl-dup-dup2-subroutine
 */
#if HAVE_F_CLOSEM

#include <fcntl.h>

void closefrom(int fromfd)
{
	(void) fcntl(fromfd, F_CLOSEM, 0);
}

bool closefrom_may_be_slow(void)
{
	return false;
}

#else /* !HAVE_F_CLOSEM */

#if HAVE_NR_CLOSE_RANGE
#include <sys/syscall.h>
#endif

#define PROC_PID_FD_LEN \
	( 6  /* /proc/ */ \
	+ 20 /* 64-bit $PID */ \
	+ 3  /* /fd */ \
	+ 1  /* NUL */ \
	)

static bool can_get_maxfd(void)
{
#if HAVE_F_MAXFD
	int res = fcntl(0, F_MAXFD);
	if (res < 0)
		return false;
	else
		return true;
#else
	return false;
#endif
}

/* Linux >= 5.9 */
static bool can_close_range(void)
{
#if HAVE_NR_CLOSE_RANGE
	int res = syscall(__NR_close_range, INT_MAX, INT_MAX, 0);
	if (res < 0)
		return false;
	return true;
#else
	return false;
#endif
}

/* On Linux, Solaris, AIX, Cygwin, and NetBSD.  */
static bool can_open_proc_pid_fd(void)
{
	char dnam[PROC_PID_FD_LEN];
	DIR *dir;

	sprintf(dnam, "/proc/%ld/fd", (long) getpid());
	dir = opendir(dnam);
	if (!dir)
		return false;
	closedir(dir);
	return true;
}

/* On FreeBSD and MacOS.  */
static bool can_open_dev_fd(void)
{
	DIR *dir;
	dir = opendir("/dev/fd");
	if (!dir)
		return false;
	closedir(dir);
	return true;
}

bool closefrom_may_be_slow(void)
{
	if (can_get_maxfd())
		return false;
	else if (can_close_range())
		return false;
	else if (can_open_proc_pid_fd())
		return false;
	else if (can_open_dev_fd())
		return false;
	else
		return true;
}

/* It is possible that we run out of available file descriptors.
 * However, if we are going to close anyway, we could just try
 * closing file descriptors until we reach maxfd.
 */
static
DIR *try_opendir(const char *dnam, int *fromfd, int maxfd)
{
	DIR *dir;

	do {
		dir = opendir(dnam);
		if (!dir && (errno == ENFILE || errno == EMFILE)) {
			if (*fromfd < maxfd)
				close((*fromfd)++);
			else
				break;
		}
	} while (!dir && (errno == ENFILE || errno == EMFILE));

	return dir;
}

void closefrom(int fromfd)
{
	int saved_errno = errno;

	int res;
	int maxfd;

	char dnam[PROC_PID_FD_LEN];
	DIR *dir;
	struct dirent *entry;

	(void) res;

	if (fromfd < 0)
		goto quit;

#if HAVE_NR_CLOSE_RANGE
	res = syscall(__NR_close_range, fromfd, INT_MAX, 0);
	if (res == 0)
		goto quit;
#endif

	maxfd = sysconf(_SC_OPEN_MAX);

	sprintf(dnam, "/proc/%ld/fd", (long) getpid());
	dir = try_opendir(dnam, &fromfd, maxfd);
	if (!dir)
		dir = try_opendir("/dev/fd", &fromfd, maxfd);

	if (dir) {
		while ((entry = readdir(dir))) {
			long fd;
			char *endp;

			fd = strtol(entry->d_name, &endp, 10);
			if (entry->d_name != endp && *endp == '\0' &&
			    fd >= 0 && fd < INT_MAX && fd >= fromfd &&
			    fd != dirfd(dir) )
				close(fd);
		}
		closedir(dir);
		goto quit;
	}

#if HAVE_F_MAXFD
	res = fcntl(0, F_MAXFD);
	if (res >= 0)
		maxfd = res + 1;
#endif

	/* Fallback.  */
	for (; fromfd < maxfd; ++fromfd)
		close(fromfd);

quit:
	errno = saved_errno;
}

#endif /* !HAVE_F_CLOSEM */

void closefrom_limit(unsigned int arg_limit)
{
	rlim_t limit = (rlim_t) arg_limit;

	struct rlimit nofile;

	if (!closefrom_may_be_slow())
		return;

	if (limit == 0)
		limit = 4096;

	getrlimit(RLIMIT_NOFILE, &nofile);

	/* Respect the max limit.
	 * If we are not running as root then we cannot raise
	 * it, but we *can* lower the max limit.
	 */
	if (nofile.rlim_max != RLIM_INFINITY && limit > nofile.rlim_max)
		limit = nofile.rlim_max;

	nofile.rlim_cur = limit;
	nofile.rlim_max = limit;

	setrlimit(RLIMIT_NOFILE, &nofile);
}

#endif /* !HAVE_CLOSEFROM */
