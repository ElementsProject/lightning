/* Async dns helper. */
#include "dns.h"
#include "lightningd.h"
#include "log.h"
#include "peer.h"
#include <assert.h>
#include <ccan/err/err.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/tal/str/str.h>
#include <ccan/tal/tal.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>

struct dns_async {
	struct lightningd_state *state;
	struct io_plan *(*init)(struct io_conn *,
				struct lightningd_state *,
				const char *name, const char *port);
	const char *name, *port;
	int pid;
	size_t num_addresses;
	struct netaddr *addresses;
};

/* This runs in the child */
static void lookup_and_write(int fd, const char *name, const char *port)
{
	struct addrinfo *addr, *i;
	struct netaddr *addresses;
	size_t num;

	if (getaddrinfo(name, port, NULL, &addr) != 0)
		return;

	num = 0;
	for (i = addr; i; i = i->ai_next)
		num++;

	addresses = tal_arr(NULL, struct netaddr, num);
	num = 0;
	for (i = addr; i; i = i->ai_next) {
		addresses[num].type = i->ai_socktype;
		addresses[num].protocol = i->ai_protocol;
		addresses[num].addrlen = i->ai_addrlen;
		memset(&addresses[num].saddr, 0, sizeof(addresses[num].saddr));
		/* Let parent report this error. */
		if (i->ai_addrlen <= sizeof(addresses[num].saddr))
			memcpy(&addresses[num].saddr, i->ai_addr, i->ai_addrlen);
		num++;
	}

	if (!num) {
		tal_free(addresses);
		return;
	}

	if (write_all(fd, &num, sizeof(num)))
		write_all(fd, addresses, num * sizeof(addresses[0]));
	tal_free(addresses);
}

static struct io_plan *connected(struct io_conn *conn, struct dns_async *d)
{
	/* No longer need to try more connections. */
	io_set_finish(conn, NULL, NULL);
	return d->init(conn, d->state, d->name, d->port);
}

static void try_connect_one(struct dns_async *d);

/* If this connection failed, try connecting to another address. */
static void connect_failed(struct io_conn *conn, struct dns_async *d)
{
	try_connect_one(d);
}

static struct io_plan *init_conn(struct io_conn *conn, struct dns_async *d)
{
	struct addrinfo a;

	netaddr_to_addrinfo(&a, &d->addresses[0]);
	io_set_finish(conn, connect_failed, d);

	/* That new connection owns d */
	tal_steal(conn, d);
	return io_connect(conn, &a, connected, d);
}

static void try_connect_one(struct dns_async *d)
{
	int fd;

	while (d->num_addresses) {
		const struct netaddr *a = &d->addresses[0];

		/* Consume that address. */
		d->addresses++;
		d->num_addresses--;

		/* Now we can warn if it's overlength */
		if (a->addrlen > sizeof(a->saddr)) {
			log_broken(d->state->base_log,
				   "DNS lookup gave overlength address for %s:%s"
				   " for family %u, len=%u",
				   d->name, d->port,
				   a->saddr.s.sa_family, a->addrlen);
		} else {
			/* Might not even be able to create eg. IPv6 sockets */
			fd = socket(a->saddr.s.sa_family, a->type, a->protocol);
			if (fd >= 0) {
				io_new_conn(d->state, fd, init_conn, d);
				break;
			}
		}
	}
}

static struct io_plan *start_connecting(struct io_conn *conn,
					struct dns_async *d)
{
	assert(d->num_addresses);
	try_connect_one(d);
	return io_close(conn);
}

static struct io_plan *read_addresses(struct io_conn *conn, struct dns_async *d)
{
	d->addresses = tal_arr(d, struct netaddr, d->num_addresses);
	return io_read(conn, d->addresses,
		       d->num_addresses * sizeof(d->addresses[0]),
		       start_connecting, d);
}

static struct io_plan *init_dns_conn(struct io_conn *conn, struct dns_async *d)
{
	return io_read(conn, &d->num_addresses, sizeof(d->num_addresses),
		       read_addresses, d);
}

static void reap_child(struct io_conn *conn, struct dns_async *d)
{
	waitpid(d->pid, NULL, 0);
}

struct dns_async *dns_resolve_and_connect(struct lightningd_state *state,
		  const char *name, const char *port,
		  struct io_plan *(*init)(struct io_conn *,
					  struct lightningd_state *,
					  const char *name, const char *port))
{
	int pfds[2];
	struct dns_async *d = tal(NULL, struct dns_async);
	struct io_conn *conn;

	d->state = state;
	d->init = init;
	d->name = tal_strdup(d, name);
	d->port = tal_strdup(d, port);

	/* First fork child to get addresses. */
	if (pipe(pfds) != 0) {
		log_unusual(state->base_log, "Creating pipes for dns lookup: %s",
			    strerror(errno));
		return NULL;
	}

	fflush(stdout);
	d->pid = fork();
	switch (d->pid) {
	case -1:
		log_unusual(state->base_log, "forking for dns lookup: %s",
			    strerror(errno));
		close(pfds[0]);
		close(pfds[1]);
		return NULL;
	case 0:
		close(pfds[0]);
		lookup_and_write(pfds[1], name, port);
		exit(0);
	}

	close(pfds[1]);
	conn = io_new_conn(state, pfds[0], init_dns_conn, d);
	io_set_finish(conn, reap_child, d);
	tal_steal(conn, d);
	return d;
}
