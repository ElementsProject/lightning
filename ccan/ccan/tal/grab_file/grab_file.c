/* Licensed under LGPLv2+ - see LICENSE file for details */
#include "grab_file.h"
#include <ccan/tal/tal.h>
#include <ccan/noerr/noerr.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>

static void *grab_fd_internal(const void *ctx, int fd, bool add_nul_term)
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

	buffer = tal_arr(ctx, char, max+add_nul_term);
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

			if (!tal_resize(&buffer, max+extra+add_nul_term))
				return NULL;

			max += extra;
		}
	}
	if (add_nul_term)
		buffer[size] = '\0';
	tal_resize(&buffer, size+add_nul_term);

	return buffer;
}

static void *grab_file_internal(const void *ctx, const char *filename, bool add_nul_term)
{
	int fd;
	char *buffer;

	if (!filename)
		fd = dup(STDIN_FILENO);
	else
		fd = open(filename, O_RDONLY, 0);

	if (fd < 0)
		return NULL;

	buffer = grab_fd_internal(ctx, fd, add_nul_term);
	close_noerr(fd);
	return buffer;
}

void *grab_fd_raw(const void *ctx, int fd)
{
	return grab_fd_internal(ctx, fd, false);
}

void *grab_fd_str(const void *ctx, int fd)
{
	return grab_fd_internal(ctx, fd, true);
}

void *grab_file_str(const void *ctx, const char *filename)
{
	return grab_file_internal(ctx, filename, true);
}

void *grab_file_raw(const void *ctx, const char *filename)
{
	return grab_file_internal(ctx, filename, false);
}
