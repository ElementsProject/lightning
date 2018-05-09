/* Licensed under BSD-MIT - see LICENSE file for details */
#ifndef CCAN_RBUF_H
#define CCAN_RBUF_H
#include <stdio.h> // For size_t
#include <limits.h> // For UCHAR_MAX
#include <assert.h>
#include <stdbool.h>

struct rbuf {
	int fd;

	/* Where to read next. */
	char *start;
	/* How much of what is there is valid. */
	size_t len;

	/* The entire buffer memory we have to work with. */
	char *buf, *buf_end;
};

/**
 * rbuf_init - set up a buffer.
 * @buf: the struct rbuf.
 * @fd: the file descriptor.
 * @buf: the buffer to use.
 * @buf_max: the size of the buffer.
 */
static inline void rbuf_init(struct rbuf *buf,
			     int fd, char *buffer, size_t buf_max)
{
	buf->fd = fd;
	buf->start = buf->buf = buffer;
	buf->len = 0;
	buf->buf_end = buffer + buf_max;
}

/**
 * rbuf_open - set up a buffer by opening a file.
 * @buf: the struct rbuf.
 * @filename: the filename
 * @buf: the buffer to use.
 * @buf_max: the size of the buffer.
 *
 * Returns false if the open fails.  If @buf_max is 0, then the buffer
 * will be resized to rbuf_good_size() on first rbuf_fill.
 *
 * Example:
 *	struct rbuf in;
 *
 *	if (!rbuf_open(&in, "foo", NULL, 0))
 *		err(1, "Could not open foo");
 */
bool rbuf_open(struct rbuf *rbuf, const char *name, char *buf, size_t buf_max);

/**
 * rbuf_good_size - get a good buffer size for this fd.
 * @fd: the file descriptor.
 *
 * If you don't know what size you want, try this.
 */
size_t rbuf_good_size(int fd);

/**
 * rbuf_fill - read into a buffer if it's empty.
 * @buf: the struct rbuf
 * @resize: the call to resize the buffer.
 *
 * If @resize is needed and is NULL, or returns false, rbuf_read will
 * return NULL (with errno set to ENOMEM).  If a read fails, then NULL
 * is also returned.  If there is nothing more to read, it will return
 * NULL with errno set to 0.  Otherwise, returns @buf->start; @buf->len
 * is the valid length of the buffer.
 *
 * You need to call rbuf_consume() to mark data in the buffer as
 * consumed.
 *
 * Example:
 *	while (rbuf_fill(&in, realloc)) {
 *		printf("%.*s\n", (int)in.len, in.start);
 *		rbuf_consume(&in, in.len);
 *	}
 *	if (errno)
 *		err(1, "reading foo");
 */
void *rbuf_fill(struct rbuf *rbuf, void *(*resize)(void *buf, size_t len));

/**
 * rbuf_consume - helper to use up data in a buffer.
 * @buf: the struct rbuf
 * @len: the length (from @buf->start) you used.
 *
 * After rbuf_fill() you should indicate the data you've used with
 * rbuf_consume().  That way rbuf_fill() will know if it has anything
 * to do.
 */
static inline void rbuf_consume(struct rbuf *buf, size_t len)
{
	buf->len -= len;
	buf->start += len;
}

/**
 * rbuf_fill_all - read rest of file into a buffer.
 * @buf: the struct rbuf
 * @resize: the call to resize the buffer.
 *
 * If @resize is needed and is NULL, or returns false, rbuf_read_all
 * will return NULL (with errno set to ENOMEM).  If a read fails,
 * then NULL is also returned, otherwise returns @buf->start.
 *
 * Example:
 *	if (!rbuf_fill_all(&in, realloc)) {
 *		if (errno)
 *			err(1, "reading foo");
 *	}
 */
void *rbuf_fill_all(struct rbuf *rbuf, void *(*resize)(void *buf, size_t len));

/**
 * rbuf_read_str - fill into a buffer up to a terminator, and consume string.
 * @buf: the struct rbuf
 * @term: the character to terminate the read.
 * @resize: the call to resize the buffer.
 *
 * If @resize is needed and is NULL, or returns false, rbuf_read_str
 * will return NULL (with errno set to ENOMEM).  If a read fails,
 * then NULL is also returned, otherwise the next string.  It
 * replaces the terminator @term (if any) with NUL, otherwise NUL
 * is placed after EOF.  If you need to, you can tell this has happened
 * because the nul terminator will be at @buf->start (normally it will
 * be at @buf->start - 1).
 *
 * If there is nothing remaining to be read, NULL is returned with
 * errno set to 0, unless @term is NUL, in which case it returns the
 * empty string.
 *
 * Note: using @term set to NUL is a cheap way of getting an entire
 * file into a C string, as long as the file doesn't contain NUL.
 *
 * Example:
 *	char *line;
 *
 *	line = rbuf_read_str(&in, '\n', realloc);
 *	if (!line) {
 *		if (errno)
 *			err(1, "reading foo");
 *		else
 *			printf("Empty file\n");
 *	} else
 *		printf("First line is %s\n", line);
 *
 */
char *rbuf_read_str(struct rbuf *rbuf, char term,
		    void *(*resize)(void *buf, size_t len));

#endif /* CCAN_RBUF_H */
