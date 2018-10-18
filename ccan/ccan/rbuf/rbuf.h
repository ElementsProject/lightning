/* Licensed under BSD-MIT - see LICENSE file for details */
#ifndef CCAN_RBUF_H
#define CCAN_RBUF_H
#include <stdio.h> // For size_t
#include <limits.h> // For UCHAR_MAX
#include <assert.h>
#include <stdbool.h>
#include <ccan/membuf/membuf.h>

struct rbuf {
	int fd;
	MEMBUF(char) m;
};

/**
 * rbuf_init - set up a buffer.
 * @rbuf: the struct rbuf.
 * @fd: the file descriptor.
 * @buf: the buffer to use.
 * @buf_max: the size of the buffer.
 * @expandfn: usually membuf_realloc.
 */
static inline void rbuf_init(struct rbuf *rbuf,
			     int fd, char *buffer, size_t buf_max,
			     void *(*expandfn)(struct membuf *, void *, size_t))
{
	rbuf->fd = fd;
	membuf_init(&rbuf->m, buffer, buf_max, expandfn);
}

/**
 * rbuf_open - set up a buffer by opening a file.
 * @rbuf: the struct rbuf.
 * @filename: the filename
 * @buf: the buffer to use.
 * @buf_max: the size of the buffer.
 * @expandfn: usually membuf_realloc.
 *
 * Returns false if the open fails.  If @buf_max is 0, then the buffer
 * will be resized to rbuf_good_size() on first rbuf_fill.
 *
 * Example:
 *	struct rbuf in;
 *
 *	if (!rbuf_open(&in, "foo", NULL, 0, membuf_realloc))
 *		err(1, "Could not open foo");
 */
bool rbuf_open(struct rbuf *rbuf, const char *name, char *buf, size_t buf_max,
	       void *(*expandfn)(struct membuf *, void *, size_t));

/**
 * rbuf_good_size - get a good buffer size for this fd.
 * @fd: the file descriptor.
 *
 * If you don't know what size you want, try this.
 */
size_t rbuf_good_size(int fd);

/**
 * rbuf_fill - read into a buffer if it's empty.
 * @rbuf: the struct rbuf
 *
 * If @expandfn fails, rbuf_fill will return NULL (with errno set to ENOMEM).
 * If a read fails, then NULL is also returned.  If there is nothing more to
 * read, it will return NULL with errno set to 0.  Otherwise, returns first
 * populated bytes (aka. rbuf_start()); rbuf_len() is the valid length of the
 * buffer.
 *
 * You need to call rbuf_consume() to mark data in the buffer as
 * consumed.
 *
 * Example:
 *	while (rbuf_fill(&in)) {
 *		printf("%.*s\n", (int)rbuf_len(&in), rbuf_start(&in));
 *		rbuf_consume(&in, rbuf_len(&in));
 *	}
 *	if (errno)
 *		err(1, "reading foo");
 */
void *rbuf_fill(struct rbuf *rbuf);

/**
 * rbuf_consume - helper to use up data in a buffer.
 * @rbuf: the struct rbuf
 * @len: the length (from @buf->start) you used.
 *
 * After rbuf_fill() you should indicate the data you've used with
 * rbuf_consume().  That way rbuf_fill() will know if it has anything
 * to do.
 */
static inline void rbuf_consume(struct rbuf *rbuf, size_t len)
{
	membuf_consume(&rbuf->m, len);
}

/**
 * rbuf_len - helper to determine how many bytes in rbuf
 * @rbuf: the struct rbuf
 */
static inline size_t rbuf_len(const struct rbuf *rbuf)
{
	return membuf_num_elems(&rbuf->m);
}

/**
 * rbuf_start - helper to get pointert to unconsumed bytes in rbuf
 * @rbuf: the struct rbuf
 */
static inline char *rbuf_start(const struct rbuf *rbuf)
{
	return membuf_elems(&rbuf->m);
}

/**
 * rbuf_fill_all - read rest of file into a buffer.
 * @rbuf: the struct rbuf
 *
 * If a read or @expandfn fails then NULL returned, otherwise returns
 * @rbuf->start.
 *
 * Example:
 *	if (!rbuf_fill_all(&in))
 *		err(1, "reading foo");
 */
void *rbuf_fill_all(struct rbuf *rbuf);

/**
 * rbuf_read_str - fill into a buffer up to a terminator, and consume string.
 * @rbuf: the struct rbuf
 * @term: the character to terminate the read.
 *
 * If a read or @expandfn fails, then NULL is returned, otherwise the next
 * string.  It replaces the terminator @term (if any) with NUL, otherwise NUL
 * is placed after EOF.  If you need to, you can tell this has happened
 * because the nul terminator will be at rbuf_start(@rbuf) (normally it will be
 * at rbuf_start(@rbuf) - 1).
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
 *	line = rbuf_read_str(&in, '\n');
 *	if (!line) {
 *		if (errno)
 *			err(1, "reading foo");
 *		else
 *			printf("Empty file\n");
 *	} else
 *		printf("First line is %s\n", line);
 *
 */
char *rbuf_read_str(struct rbuf *rbuf, char term);

/**
 * rbuf_cleanup - reset rbuf, return buffer for freeing.
 * @rbuf: the struct rbuf
 *
 * The rbuf will be empty after this, and crash if you try to use it.
 * You can rbuf_init() it again, however.
 *
 * Example:
 *	free(rbuf_cleanup(&in));
 */
static inline char *rbuf_cleanup(struct rbuf *rbuf)
{
	return membuf_cleanup(&rbuf->m);
}
#endif /* CCAN_RBUF_H */
