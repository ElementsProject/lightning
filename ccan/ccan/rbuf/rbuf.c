/* Licensed under BSD-MIT - see LICENSE file for details */
#include <ccan/rbuf/rbuf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>

bool rbuf_open(struct rbuf *rbuf, const char *name, char *buf, size_t buf_max,
	       void *(*expandfn)(struct membuf *, void *, size_t))
{
	int fd = open(name, O_RDONLY);
	if (fd >= 0) {
		rbuf_init(rbuf, fd, buf, buf_max, expandfn);
		return true;
	}
	return false;
}

size_t rbuf_good_size(int fd)
{
	struct stat st;

	if (fstat(fd, &st) == 0 && st.st_blksize >= 4096)
		return st.st_blksize;
	return 4096;
}

static ssize_t get_more(struct rbuf *rbuf)
{
	ssize_t r;

	/* This is so we only call rbuf_good_size once. */
	if (tcon_unwrap(&rbuf->m)->max_elems == 0)
		membuf_prepare_space(&rbuf->m, rbuf_good_size(rbuf->fd));
	else /* membuf doubles internally, so just ask for anything. */
		membuf_prepare_space(&rbuf->m, 1);

	/* This happens if realloc fails (errno already ENOMEM) */
	if (!membuf_num_space(&rbuf->m))
		return -1;

	r = read(rbuf->fd, membuf_space(&rbuf->m), membuf_num_space(&rbuf->m));
	if (r <= 0)
		return r;

	membuf_add(&rbuf->m, r);
	return r;
}

void *rbuf_fill_all(struct rbuf *rbuf)
{
	ssize_t r;

	while ((r = get_more(rbuf)) != 0)
		if (r < 0)
			return NULL;
	return rbuf_start(rbuf);
}

void *rbuf_fill(struct rbuf *rbuf)
{
	if (!rbuf_len(rbuf)) {
		if (get_more(rbuf) < 0)
			return NULL;
	}
	return rbuf_start(rbuf);
}

char *rbuf_read_str(struct rbuf *rbuf, char term)
{
	char *p;
	ssize_t r = 0;
	size_t prev = 0;

	while (!(p = memchr(membuf_elems(&rbuf->m) + prev,
			    term,
			    membuf_num_elems(&rbuf->m) - prev))) {
		prev += r;
		r = get_more(rbuf);
		if (r < 0)
			return NULL;
		/* EOF with no term. */
		if (r == 0) {
			char *ret;
			size_t len = rbuf_len(rbuf);

			/* Nothing read at all? */
			if (!len && term) {
				errno = 0;
				return NULL;
			}

			/* Put term after input (get_more made room). */
			assert(membuf_num_space(&rbuf->m) > 0);
			ret = membuf_consume(&rbuf->m, len);
			ret[len] = '\0';
			return ret;
		}
	}
	*p = '\0';
	return membuf_consume(&rbuf->m, p + 1 - (char *)rbuf_start(rbuf));
}
