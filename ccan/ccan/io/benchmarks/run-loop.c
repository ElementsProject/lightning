#include <ccan/io/io.h>
#include <ccan/time/time.h>
#include <sys/wait.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <err.h>
#include <signal.h>

#define NUM 500
#define NUM_ITERS 10000

struct buffer {
	int iters;
	struct io_conn *reader, *writer;
	char buf[32];
};

static struct io_plan poke_reader(struct io_conn *conn, struct buffer *buf);

static struct io_plan poke_writer(struct io_conn *conn, struct buffer *buf)
{
	assert(conn == buf->reader);

	if (buf->iters == NUM_ITERS)
		return io_close();

	/* You write. */
	io_wake(buf->writer,
		io_write(&buf->buf, sizeof(buf->buf), poke_reader, buf));

	/* I'll wait until you wake me. */
	return io_idle();
}

static struct io_plan poke_reader(struct io_conn *conn, struct buffer *buf)
{
	assert(conn == buf->writer);
	/* You read. */
	io_wake(buf->reader,
		io_read(&buf->buf, sizeof(buf->buf), poke_writer, buf));

	if (++buf->iters == NUM_ITERS)
		return io_close();

	/* I'll wait until you tell me to write. */
	return io_idle();
}

int main(void)
{
	unsigned int i;
	int fds[2], last_read, last_write;
	struct timespec start, end;
	struct buffer buf[NUM];

	if (pipe(fds) != 0)
		err(1, "pipe");
	last_read = fds[0];
	last_write = fds[1];

	for (i = 1; i < NUM; i++) {
		buf[i].iters = 0;
		if (pipe(fds) < 0)
			err(1, "pipe");
		memset(buf[i].buf, i, sizeof(buf[i].buf));
		sprintf(buf[i].buf, "%i-%i", i, i);

		buf[i].reader = io_new_conn(last_read, io_idle());
		if (!buf[i].reader)
			err(1, "Creating reader %i", i);
		buf[i].writer = io_new_conn(fds[1],
					    io_write(&buf[i].buf,
						     sizeof(buf[i].buf),
						     poke_reader, &buf[i]));
		if (!buf[i].writer)
			err(1, "Creating writer %i", i);
		last_read = fds[0];
	}

	/* Last one completes the cirle. */
	i = 0;
	buf[i].iters = 0;
	sprintf(buf[i].buf, "%i-%i", i, i);
	buf[i].reader = io_new_conn(last_read, io_idle());
	if (!buf[i].reader)
		err(1, "Creating reader %i", i);
	buf[i].writer = io_new_conn(last_write, io_write(&buf[i].buf,
							 sizeof(buf[i].buf),
							 poke_reader, &buf[i]));
	if (!buf[i].writer)
		err(1, "Creating writer %i", i);

	/* They should eventually exit */
	start = time_now();
	if (io_loop() != NULL)
		errx(1, "io_loop?");
	end = time_now();

	for (i = 0; i < NUM; i++) {
		char b[sizeof(buf[0].buf)];
		memset(b, i, sizeof(b));
		sprintf(b, "%i-%i", i, i);
		if (memcmp(b, buf[(i + NUM_ITERS) % NUM].buf, sizeof(b)) != 0)
			errx(1, "Buffer for %i was '%s' not '%s'",
			     i, buf[(i + NUM_ITERS) % NUM].buf, b);
	}

	printf("run-many: %u %u iterations: %llu usec\n",
	       NUM, NUM_ITERS, (long long)time_to_usec(time_sub(end, start)));
	return 0;
}
