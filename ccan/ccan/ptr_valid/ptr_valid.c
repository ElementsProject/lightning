// Licensed under BSD-MIT: See LICENSE.
#include "ptr_valid.h"
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ccan/noerr/noerr.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <string.h>

#if HAVE_PROC_SELF_MAPS
static char *grab(const char *filename)
{
	int ret, fd;
	size_t max = 16384, s = 0;
	char *buffer;

	fd = open(filename, O_RDONLY);
	if (fd < 0)
		return NULL;

	buffer = malloc(max+1);
	if (!buffer)
		goto close;

	while ((ret = read(fd, buffer + s, max - s)) > 0) {
		s += ret;
		if (s == max) {
			buffer = realloc(buffer, max*2+1);
			if (!buffer)
				goto close;
			max *= 2;
		}
	}
	if (ret < 0)
		goto free;

	close(fd);
	buffer[s] = '\0';
	return buffer;

free:
	free(buffer);
close:
	close_noerr(fd);
	return NULL;
}

static char *skip_line(char *p)
{
	char *nl = strchr(p, '\n');
	if (!nl)
		return NULL;
	return nl + 1;
}

static struct ptr_valid_map *add_map(struct ptr_valid_map *map,
				     unsigned int *num,
				     unsigned int *max,
				     unsigned long start, unsigned long end, bool is_write)
{
	if (*num == *max) {
		*max *= 2;
		map = realloc(map, sizeof(*map) * *max);
		if (!map)
			return NULL;
	}
	map[*num].start = (void *)start;
	map[*num].end = (void *)end;
	map[*num].is_write = is_write;
	(*num)++;
	return map;
}

static struct ptr_valid_map *get_proc_maps(unsigned int *num)
{
	char *buf, *p;
	struct ptr_valid_map *map;
	unsigned int max = 16;

	buf = grab("/proc/self/maps");
	if (!buf) {
		*num = 0;
		return NULL;
	}

	map = malloc(sizeof(*map) * max);
	if (!map)
		goto free_buf;

	*num = 0;
	for (p = buf; p && *p; p = skip_line(p)) {
		unsigned long start, end;
		char *endp;

		/* Expect '<start-in-hex>-<end-in-hex> rw... */
		start = strtoul(p, &endp, 16);
		if (*endp != '-')
			goto malformed;
		end = strtoul(endp+1, &endp, 16);
		if (*endp != ' ')
			goto malformed;

		endp++;
		if (endp[0] != 'r' && endp[0] != '-')
			goto malformed;
		if (endp[1] != 'w' && endp[1] != '-')
			goto malformed;

		/* We only add readable mappings. */
		if (endp[0] == 'r') {
			map = add_map(map, num, &max, start, end,
				      endp[1] == 'w');
			if (!map)
				goto free_buf;
		}
	}

	free(buf);
	return map;


malformed:
	free(map);
free_buf:
	free(buf);
	*num = 0;
	return NULL;
}
#else
static struct ptr_valid_map *get_proc_maps(unsigned int *num)
{
	*num = 0;
	return NULL;
}
#endif

static bool check_with_maps(struct ptr_valid_batch *batch,
			    const char *p, size_t size, bool is_write)
{
	unsigned int i;

	for (i = 0; i < batch->num_maps; i++) {
		if (p >= batch->maps[i].start && p < batch->maps[i].end) {
			/* Overlap into other maps?  Recurse with remainder. */
			if (p + size > batch->maps[i].end) {
				size_t len = p + size - batch->maps[i].end;
				if (!check_with_maps(batch, batch->maps[i].end,
						     len, is_write))
					return false;
			}
			return !is_write || batch->maps[i].is_write;
		}
	}
	return false;
}

static void finish_child(struct ptr_valid_batch *batch)
{
	close(batch->to_child);
	close(batch->from_child);
	while (waitpid(batch->child_pid, NULL, 0) < 0 && errno == EINTR);
	batch->child_pid = 0;
}

static bool child_alive(struct ptr_valid_batch *batch)
{
	return batch->child_pid != 0;
}

static void run_child(int infd, int outfd)
{
	volatile char *p;

	/* This is how we expect to exit. */
	while (read(infd, &p, sizeof(p)) == sizeof(p)) {
		size_t i, size;
		bool is_write;
		char ret = 0;

		/* This is weird. */
		if (read(infd, &size, sizeof(size)) != sizeof(size))
			exit(1);
		if (read(infd, &is_write, sizeof(is_write)) != sizeof(is_write))
			exit(2);

		for (i = 0; i < size; i++) {
			ret = p[i];
			if (is_write)
				p[i] = ret;
		}

		/* If we're still here, the answer is "yes". */
		if (write(outfd, &ret, 1) != 1)
			exit(3);
	}
	exit(0);
}

static bool create_child(struct ptr_valid_batch *batch)
{
	int outpipe[2], inpipe[2];

	if (pipe(outpipe) != 0)
		return false;
	if (pipe(inpipe) != 0)
		goto close_outpipe;

	fflush(stdout);
	batch->child_pid = fork();
	if (batch->child_pid == 0) {
		close(outpipe[1]);
		close(inpipe[0]);
		run_child(outpipe[0], inpipe[1]);
	}

	if (batch->child_pid == -1)
		goto cleanup_pid;

	close(outpipe[0]);
	close(inpipe[1]);

	batch->to_child = outpipe[1];
	batch->from_child = inpipe[0];
	return true;

cleanup_pid:
	batch->child_pid = 0;
	close_noerr(inpipe[0]);
	close_noerr(inpipe[1]);
close_outpipe:
	close_noerr(outpipe[0]);
	close_noerr(outpipe[1]);
	return false;
}

static bool check_with_child(struct ptr_valid_batch *batch,
			     const void *p, size_t size, bool is_write)
{
	char ret;

	if (!child_alive(batch)) {
		if (!create_child(batch))
			return false;
	}

	if (write(batch->to_child, &p, sizeof(p))
	    + write(batch->to_child, &size, sizeof(size))
	    + write(batch->to_child, &is_write, sizeof(is_write))
	    != sizeof(p) + sizeof(size) + sizeof(is_write)) {
		finish_child(batch);
		errno = EFAULT;
		return false;
	}

	if (read(batch->from_child, &ret, sizeof(ret)) != sizeof(ret)) {
		finish_child(batch);
		errno = EFAULT;
		return false;
	}
	return true;
}

/* msync seems most well-defined test, but page could be mapped with
 * no permissions, and can't distiguish readonly from writable. */
bool ptr_valid_batch(struct ptr_valid_batch *batch,
		     const void *p, size_t alignment, size_t size, bool write)
{
	char *start, *end;
	bool ret;

	if ((intptr_t)p & (alignment - 1))
		return false;

	start = (void *)((intptr_t)p & ~(getpagesize() - 1));
	end = (void *)(((intptr_t)p + size - 1) & ~(getpagesize() - 1));

	/* We cache single page hits. */
	if (start == end) {
		if (batch->last && batch->last == start)
			return batch->last_ok;
	}

	if (batch->num_maps)
		ret = check_with_maps(batch, p, size, write);
	else
		ret = check_with_child(batch, p, size, write);

	if (start == end) {
		batch->last = start;
		batch->last_ok = ret;
	}

	return ret;
}

bool ptr_valid_batch_string(struct ptr_valid_batch *batch, const char *p)
{
	while (ptr_valid_batch(batch, p, 1, 1, false)) {
		if (*p == '\0')
			return true;
		p++;
	}
	return false;
}

bool ptr_valid(const void *p, size_t alignment, size_t size, bool write)
{
	bool ret;
	struct ptr_valid_batch batch;
	if (!ptr_valid_batch_start(&batch))
		return false;
	ret = ptr_valid_batch(&batch, p, alignment, size, write);
	ptr_valid_batch_end(&batch);
	return ret;
}

bool ptr_valid_string(const char *p)
{
	bool ret;
	struct ptr_valid_batch batch;
	if (!ptr_valid_batch_start(&batch))
		return false;
	ret = ptr_valid_batch_string(&batch, p);
	ptr_valid_batch_end(&batch);
	return ret;
}

bool ptr_valid_batch_start(struct ptr_valid_batch *batch)
{
	batch->child_pid = 0;
	batch->maps = get_proc_maps(&batch->num_maps);
	batch->last = NULL;
	return true;
}

void ptr_valid_batch_end(struct ptr_valid_batch *batch)
{
	if (child_alive(batch))
		finish_child(batch);
	free(batch->maps);
}
