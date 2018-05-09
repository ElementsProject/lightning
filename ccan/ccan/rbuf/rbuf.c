/* Licensed under BSD-MIT - see LICENSE file for details */
#include <ccan/rbuf/rbuf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>

bool rbuf_open(struct rbuf *rbuf, const char *name, char *buf, size_t buf_max)
{
	int fd = open(name, O_RDONLY);
	if (fd >= 0) {
		rbuf_init(rbuf, fd, buf, buf_max);
		return true;
	}
	return false;
}

static size_t rem(const struct rbuf *buf)
{
	return buf->buf_end - (buf->start + buf->len);
}

size_t rbuf_good_size(int fd)
{
	struct stat st;

	if (fstat(fd, &st) == 0 && st.st_blksize >= 4096)
		return st.st_blksize;
	return 4096;
}

static bool enlarge_buf(struct rbuf *buf, size_t len,
			void *(*resize)(void *buf, size_t len))
{
	char *new;
	if (!resize) {
		errno = ENOMEM;
		return false;
	}
	if (!len)
		len = rbuf_good_size(buf->fd);
	new = resize(buf->buf, len);
	if (!new)
		return false;
	buf->start += (new - buf->buf);
	buf->buf = new;
	buf->buf_end = new + len;
	return true;
}

static ssize_t get_more(struct rbuf *rbuf,
			void *(*resize)(void *buf, size_t len))
{
	size_t r;

	if (rbuf->start + rbuf->len == rbuf->buf_end) {
		if (!enlarge_buf(rbuf, (rbuf->buf_end - rbuf->buf) * 2, resize))
			return -1;
	}

	r = read(rbuf->fd, rbuf->start + rbuf->len, rem(rbuf));
	if (r <= 0)
		return r;

	rbuf->len += r;
	return r;
}

void *rbuf_fill_all(struct rbuf *rbuf, void *(*resize)(void *buf, size_t len))
{
	ssize_t r;

	/* Move back to start of buffer if we're empty. */
	if (!rbuf->len)
		rbuf->start = rbuf->buf;

	while ((r = get_more(rbuf, resize)) != 0)
		if (r < 0)
			return NULL;
	return rbuf->start;
}

void *rbuf_fill(struct rbuf *rbuf, void *(*resize)(void *buf, size_t len))
{
	if (!rbuf->len) {
		rbuf->start = rbuf->buf;
		if (get_more(rbuf, resize) < 0)
			return NULL;
	}
	return rbuf->start;
}

char *rbuf_read_str(struct rbuf *rbuf, char term,
		    void *(*resize)(void *buf, size_t len))
{
	char *p, *ret;
	ssize_t r = 0;
	size_t prev = 0;

	/* Move back to start of buffer if we're empty. */
	if (!rbuf->len)
		rbuf->start = rbuf->buf;

	while (!(p = memchr(rbuf->start + prev, term, rbuf->len - prev))) {
		prev += r;
		r = get_more(rbuf, resize);
		if (r < 0)
			return NULL;
		/* EOF with no term. */
		if (r == 0) {
			/* Nothing read at all? */
			if (!rbuf->len && term) {
				errno = 0;
				return NULL;
			}
			/* Put term after input (get_more made room). */
			assert(rbuf->start + rbuf->len < rbuf->buf_end);
			rbuf->start[rbuf->len] = '\0';
			ret = rbuf->start;
			rbuf_consume(rbuf, rbuf->len);
			return ret;
		}
	}
	*p = '\0';
	ret = rbuf->start;
	rbuf_consume(rbuf, p + 1 - ret);
	return ret;
}
