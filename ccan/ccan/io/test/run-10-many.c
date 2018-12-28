#include <ccan/io/io.h>
/* Include the C files directly. */
#include <ccan/io/poll.c>
#include <ccan/io/io.c>
#include <ccan/tap/tap.h>
#include <sys/wait.h>
#include <stdio.h>

#define NUM 100
#define NUM_ITERS 1000

struct buffer {
	int iters;
	struct io_conn *reader, *writer;
	char buf[32];
};

static struct io_plan *poke_reader(struct io_conn *conn, struct buffer *buf);
static struct io_plan *poke_writer(struct io_conn *conn, struct buffer *buf);

static struct io_plan *read_buf(struct io_conn *conn, struct buffer *buf)
{
	return io_read(conn, &buf->buf, sizeof(buf->buf), poke_writer, buf);
}

static struct io_plan *poke_writer(struct io_conn *conn, struct buffer *buf)
{
	assert(conn == buf->reader);

	if (buf->iters == NUM_ITERS)
		return io_close(conn);

	/* You write. */
	io_wake(&buf->writer);

	/* I'll wait until you wake me. */
	return io_wait(conn, &buf->reader, read_buf, buf);
}

static struct io_plan *write_buf(struct io_conn *conn, struct buffer *buf)
{
	return io_write(conn, &buf->buf, sizeof(buf->buf), poke_reader, buf);
}

static struct io_plan *poke_reader(struct io_conn *conn, struct buffer *buf)
{
	assert(conn == buf->writer);
	/* You read. */
	io_wake(&buf->reader);

	if (++buf->iters == NUM_ITERS)
		return io_close(conn);

	/* I'll wait until you tell me to write. */
	return io_wait(conn, &buf->writer, write_buf, buf);
}

static struct io_plan *setup_reader(struct io_conn *conn, struct buffer *buf)
{
	return io_wait(conn, &buf->reader, read_buf, buf);
}

static struct buffer buf[NUM];

int main(void)
{
	unsigned int i;
	int fds[2], last_read, last_write;

	plan_tests(5 + NUM);

	ok1(pipe(fds) == 0);
	last_read = fds[0];
	last_write = fds[1];

	for (i = 1; i < NUM; i++) {
		if (pipe(fds) < 0)
			break;
		memset(buf[i].buf, i, sizeof(buf[i].buf));
		sprintf(buf[i].buf, "%i-%i", i, i);

		/* Wait for writer to tell us to read. */
		buf[i].reader = io_new_conn(NULL, last_read,
					    setup_reader, &buf[i]);
		if (!buf[i].reader)
			break;
		buf[i].writer = io_new_conn(NULL, fds[1], write_buf, &buf[i]);
		if (!buf[i].writer)
			break;
		last_read = fds[0];
	}
	if (!ok1(i == NUM))
		exit(exit_status());

	/* Last one completes the cirle. */
	i = 0;
	sprintf(buf[i].buf, "%i-%i", i, i);
	buf[i].reader = io_new_conn(NULL, last_read, setup_reader, &buf[i]);
	ok1(buf[i].reader);
	buf[i].writer = io_new_conn(NULL, last_write, write_buf, &buf[i]);
	ok1(buf[i].writer);

	/* They should eventually exit */
	ok1(io_loop(NULL, NULL) == NULL);

	for (i = 0; i < NUM; i++) {
		char b[sizeof(buf[0].buf)];
		memset(b, i, sizeof(b));
		sprintf(b, "%i-%i", i, i);
		ok1(memcmp(b, buf[(i + NUM_ITERS) % NUM].buf, sizeof(b)) == 0);
	}

	/* This exits depending on whether all tests passed */
	return exit_status();
}
