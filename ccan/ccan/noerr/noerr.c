/* CC0 (Public domain) - see LICENSE file for details */
#include "noerr.h"
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>

int close_noerr(int fd)
{
	int saved_errno = errno, ret;

	if (close(fd) != 0)
		ret = errno;
	else
		ret = 0;

	errno = saved_errno;
	return ret;
}

int fclose_noerr(FILE *fp)
{
	int saved_errno = errno, ret;

	if (fclose(fp) != 0)
		ret = errno;
	else
		ret = 0;

	errno = saved_errno;
	return ret;
}

int unlink_noerr(const char *pathname)
{
	int saved_errno = errno, ret;

	if (unlink(pathname) != 0)
		ret = errno;
	else
		ret = 0;

	errno = saved_errno;
	return ret;
}

void free_noerr(void *p)
{
	int saved_errno = errno;
	free(p);
	errno = saved_errno;
}
