/* Wait for many fds to connect, then try to stream the file to some of them in small chunks.
 *
 * This approximates the connectd behaviour in CLN, where we send gossip to peers.
 */
#include <ccan/io/io.h>
#include <ccan/ptrint/ptrint.h>
#include <ccan/time/time.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <err.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* We expect num_expected connections, and how many will be writers */
static size_t max_readers, max_writers;

/* How many raeaders and writers still going */
static size_t num_readers, num_writers;

/* How many times to do the write */
static size_t write_iterations;

/* The buffer to write */
static char writebuf[256];

/* We need this for readers, though we don't actually care! */
static size_t len_ignored;

struct timemono start_time;

static void finished(void)
{
	struct timerel elapsed = timemono_since(start_time);
	printf("Finished: %"PRIu64"usec\n", time_to_usec(elapsed));
	exit(0);
}

static struct io_plan *write_loop(struct io_conn *conn, ptrint_t *iter)
{
	ptrdiff_t n = ptr2int(iter);

	if (n > write_iterations) {
		--num_writers;
		if (num_writers == 0)
			finished();
		return io_wait(conn, conn, io_never, NULL);
	}
	return io_write(conn, writebuf, sizeof(writebuf), write_loop, int2ptr(n + 1));
}

static struct io_plan *read_loop(struct io_conn *conn, void *unused)
{
	return io_read_partial(conn, writebuf, sizeof(writebuf), &len_ignored, read_loop, unused);
}

static void reader_failed(struct io_conn *conn, intptr_t *num)
{
	err(1, "Reader %zu/%zu", (size_t)ptr2int(num), max_readers);
}

static void writer_failed(struct io_conn *conn, intptr_t *num)
{
	err(1, "Writer %zu/%zu", (size_t)ptr2int(num), max_writers);
}

static struct io_plan *connection_in(struct io_conn *conn, void *sleep_on)
{
	if (num_readers < max_readers) {
		printf("r");
		fflush(stdout);
		num_readers++;
		io_set_finish(conn, reader_failed, int2ptr(num_readers));
		return read_loop(conn, NULL);
	}

	/* We assign writers last: not sure it matters, but it's more reflective
	 * of lightning where more recent connections tend to ask for gossip */
	num_writers++;
	printf("w");
	fflush(stdout);

	io_set_finish(conn, writer_failed, int2ptr(num_writers));
	io_set_finish(conn, writer_failed, NULL);
	if (num_writers < max_writers)
		return io_wait(conn, sleep_on, write_loop, int2ptr(0));

	/* Everyone is connected.  Wake them and start final one */
	io_wake(sleep_on);
	printf("Starting!\n");
	start_time = time_mono();
	return write_loop(conn, int2ptr(0));
}

int main(int argc, char *argv[])
{
	int fd;
	struct sockaddr_in s4;
	int on = 1;

	if (argc != 5)
		errx(1, "Usage: <portnum> <num-idle> <num-streaming> <mb-streamed>");

	memset(&s4, 0, sizeof(s4));
	s4.sin_family = AF_INET;
	s4.sin_port = htons(atol(argv[1]));
	s4.sin_addr.s_addr = INADDR_ANY;

	max_readers = atol(argv[2]);
	max_writers = atol(argv[3]);
	write_iterations = atol(argv[4]) * (1024 * 1024 / sizeof(writebuf));

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0)
		err(1, "Creating socket");

	/* Re-use, please.. */
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)))
		err(1, "Setting reuseaddr");

	if (bind(fd, &s4, sizeof(s4)) != 0)
		err(1, "Binding");

	if (listen(fd, 1) != 0)
		err(1, "Listening");

	io_new_listener(NULL, fd, connection_in, &s4);
	io_loop(NULL, NULL);
	errx(1, "Sockets exited?");
}
