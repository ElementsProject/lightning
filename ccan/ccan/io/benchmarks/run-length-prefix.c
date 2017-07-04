/* Simulate a server with connections of different speeds.  We count
 * how many connections complete in 10 seconds. */
#include <ccan/io/io.h>
#include <ccan/time/time.h>
#include <ccan/err/err.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <signal.h>
#include <assert.h>

#define REQUEST_MAX 131072
#define NUM_CONNS 500 /* per child */
#define NUM_CHILDREN 2

static unsigned int completed;

struct client {
	unsigned int len;
	char *request_buffer;
};

static struct io_plan write_reply(struct io_conn *conn, struct client *client);
static struct io_plan read_body(struct io_conn *conn, struct client *client)
{
	assert(client->len <= REQUEST_MAX);
	return io_read(client->request_buffer, client->len,
		       write_reply, client);
}

static struct io_plan io_read_header(struct client *client)
{
	return io_read(&client->len, sizeof(client->len), read_body, client);
}

/* once we're done, loop again. */
static struct io_plan write_complete(struct io_conn *conn, struct client *client)
{
	completed++;
	return io_read_header(client);
}

static struct io_plan write_reply(struct io_conn *conn, struct client *client)
{
	return io_write(&client->len, sizeof(client->len),
			write_complete, client);
}

/* This runs in the child. */
static void create_clients(struct sockaddr_un *addr, int waitfd)
{
	struct client data;
	int i, sock[NUM_CONNS], len[NUM_CONNS], done[NUM_CONNS],
		result[NUM_CONNS], count = 0;

	for (i = 0; i < NUM_CONNS; i++) {
		len[i] = (random() % REQUEST_MAX) + 1;
		sock[i] = socket(AF_UNIX, SOCK_STREAM, 0);
		if (sock[i] < 0)
			err(1, "creating socket");
		if (connect(sock[i], (void *)addr, sizeof(*addr)) != 0)
			err(1, "connecting socket");
		/* Make nonblocking. */
		io_fd_block(sock[i], false);
		done[i] = 0;
	}

	read(waitfd, &i, 1);

	for (;;) {
		for (i = 0; i < NUM_CONNS; i++) {
			int ret, totlen = len[i] + sizeof(len[i]);
			if (done[i] < sizeof(len[i]) + len[i]) {
				data.len = len[i];
				ret = write(sock[i], (void *)&data + done[i],
					    totlen - done[i]);
				if (ret > 0)
					done[i] += ret;
				else if (ret < 0 && errno != EAGAIN)
					goto fail;
			} else {
				int off = done[i] - totlen;
				ret = read(sock[i], (void *)&result[i] + off,
					   sizeof(result[i]) - off);
				if (ret > 0) {
					done[i] += ret;
					if (done[i] == totlen
					    + sizeof(result[i])) {
						assert(result[i] == len[i]);
						count++;
						done[i] = 0;
					}
				} else if (ret < 0 && errno != EAGAIN)
					goto fail;
			}
		}
	}
fail:
	printf("Child did %u\n", count);
	exit(0);
}

static int timeout[2];
static void sigalarm(int sig)
{
	write(timeout[1], "1", 1);
}

static struct io_plan do_timeout(struct io_conn *conn, char *buf)
{
	return io_break(buf, io_idle());
}

int main(int argc, char *argv[])
{
	unsigned int i, j;
	struct sockaddr_un addr;
	struct timespec start, end;
	char buffer[REQUEST_MAX];
	int fd, wake[2];
	char buf;

	addr.sun_family = AF_UNIX;
	sprintf(addr.sun_path, "/tmp/run-different-speed.sock.%u", getpid());

	if (pipe(wake) != 0 || pipe(timeout) != 0)
		err(1, "Creating pipes");

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		err(1, "Creating socket");

	if (bind(fd, (void *)&addr, sizeof(addr)) != 0)
		err(1, "Binding to %s", addr.sun_path);

	if (listen(fd, NUM_CONNS) != 0)
		err(1, "Listening on %s", addr.sun_path);

	for (i = 0; i < NUM_CHILDREN; i++) {
		switch (fork()) {
		case -1:
			err(1, "forking");
		case 0:
			close(wake[1]);
			create_clients(&addr, wake[0]);
			break;
		}
		for (j = 0; j < NUM_CONNS; j++) {
			struct client *client = malloc(sizeof(*client));
			int ret = accept(fd, NULL, 0);
			if (ret < 0)
				err(1, "Accepting fd");
			/* For efficiency, we share buffer */
			client->request_buffer = buffer;
			io_new_conn(ret, io_read_header(client));
		}
	}

	io_new_conn(timeout[0], io_read(&buf, 1, do_timeout, &buf));

	close(wake[0]);
	for (i = 0; i < NUM_CHILDREN; i++)
		write(wake[1], "1", 1);

	signal(SIGALRM, sigalarm);
	alarm(10);
	start = time_now();
	io_loop();
	end = time_now();
	close(fd);

	printf("%u connections complete (%u ns per conn)\n",
	       completed,
	       (int)time_to_nsec(time_divide(time_sub(end, start), completed)));
	return 0;
}
