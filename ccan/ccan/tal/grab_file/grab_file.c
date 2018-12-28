/* Licensed under LGPLv2+ - see LICENSE file for details */
#include "grab_file.h"
#include <ccan/tal/tal.h>
#include <ccan/noerr/noerr.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>

void *grab_fd(const void *ctx, int fd)
{
	int ret;
	size_t max, size;
	char *buffer;
	struct stat st;

	size = 0;

	if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode))
		max = st.st_size;
	else
		max = 16384;

	buffer = tal_arr(ctx, char, max+1);
	while ((ret = read(fd, buffer + size, max - size)) != 0) {
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			return tal_free(buffer);
		}
		size += ret;
		if (size == max) {
			size_t extra = max;
			if (extra > 1024 * 1024)
				extra = 1024 * 1024;

			if (!tal_resize(&buffer, max+extra+1))
				return NULL;

			max += extra;
		}
	}
	buffer[size] = '\0';
	tal_resize(&buffer, size+1);

	return buffer;
}

void *grab_file(const void *ctx, const char *filename)
{
	int fd;
	char *buffer;

	if (!filename)
		fd = dup(STDIN_FILENO);
	else
		fd = open(filename, O_RDONLY, 0);

	if (fd < 0)
		return NULL;

	buffer = grab_fd(ctx, fd);
	close_noerr(fd);
	return buffer;
}
