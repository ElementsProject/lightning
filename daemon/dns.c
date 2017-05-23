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
	struct lightningd_state *dstate;
	struct io_plan *(*init)(struct io_conn *, struct lightningd_state *,
				const struct netaddr *,
				void *);
	void (*fail)(struct lightningd_state *, void *arg);
	const char *name;
	void *arg;
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
	struct addrinfo hints;

	/* We don't want UDP sockets (yet?) */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if (getaddrinfo(name, port, &hints, &addr) != 0)
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
	struct io_plan *plan;

	/* No longer need to try more connections via connect_failed. */
	io_set_finish(conn, NULL, NULL);

	plan = d->init(conn, d->dstate, &d->addresses[-1], d->arg);
	tal_free(d);

	return plan;
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

	/* Consume that address. */
	d->addresses++;
	d->num_addresses--;

	io_set_finish(conn, connect_failed, d);

	/* That new connection owns d */
	return io_connect(conn, &a, connected, d);
}

static void try_connect_one(struct dns_async *d)
{
	int fd;

	while (d->num_addresses) {
		const struct netaddr *a = &d->addresses[0];

		/* Now we can warn if it's overlength */
		if (a->addrlen > sizeof(a->saddr)) {
			log_broken(d->dstate->base_log,
				   "DNS lookup gave overlength address for %s"
				   " for family %u, len=%u",
				   d->name, a->saddr.s.sa_family, a->addrlen);
		} else {
			/* Might not even be able to create eg. IPv6 sockets */
			fd = socket(a->saddr.s.sa_family, a->type, a->protocol);
			if (fd >= 0) {
				io_new_conn(d->dstate, fd, init_conn, d);
				return;
			}
		}

		/* Consume that address. */
		d->addresses++;
		d->num_addresses--;
	}

	/* We're out of things to try.  Fail. */
	d->fail(d->dstate, d->arg);
	tal_free(d);
}

static struct io_plan *start_connecting(struct io_conn *conn,
					struct dns_async *d)
{
	assert(d->num_addresses);

	/* OK, we've read all we want, child should exit. */
	waitpid(d->pid, NULL, 0);

	/* No need to call dns_lookup_failed now. */
	io_set_finish(conn, NULL, NULL);

	try_connect_one(d);
	return io_close(conn);
}

struct dns_async *multiaddress_connect_(struct lightningd_state *dstate,
		  const struct netaddr *addresses,
		  struct io_plan *(*init)(struct io_conn *,
					  struct lightningd_state *,
					  const struct netaddr *,
					  void *arg),
		  void (*fail)(struct lightningd_state *, void *arg),
		  void *arg)
{
	struct dns_async *d = tal(dstate, struct dns_async);

	d->dstate = dstate;
	d->init = init;
	d->fail = fail;
	d->arg = arg;
	d->name = "names from address list";
	d->num_addresses = tal_count(addresses);
	d->addresses = tal_dup_arr(d, struct netaddr, addresses,
				   d->num_addresses, 0);
	try_connect_one(d);
	return d;
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

static void dns_lookup_failed(struct io_conn *conn, struct dns_async *d)
{
	waitpid(d->pid, NULL, 0);
	d->fail(d->dstate, d->arg);
	tal_free(d);
}

struct dns_async *dns_resolve_and_connect_(struct lightningd_state *dstate,
		  const char *name, const char *port,
		  struct io_plan *(*init)(struct io_conn *,
					  struct lightningd_state *,
					  const struct netaddr *,
					  void *arg),
		  void (*fail)(struct lightningd_state *, void *arg),
		  void *arg)
{
	int pfds[2];
	struct dns_async *d = tal(dstate, struct dns_async);
	struct io_conn *conn;

	d->dstate = dstate;
	d->init = init;
	d->fail = fail;
	d->arg = arg;
	d->name = tal_fmt(d, "%s:%s", name, port);

	/* First fork child to get addresses. */
	if (pipe(pfds) != 0) {
		log_unusual(dstate->base_log,
			    "Creating pipes for dns lookup: %s",
			    strerror(errno));
		return NULL;
	}

	fflush(stdout);
	d->pid = fork();
	switch (d->pid) {
	case -1:
		log_unusual(dstate->base_log, "forking for dns lookup: %s",
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
	conn = io_new_conn(dstate, pfds[0], init_dns_conn, d);
	io_set_finish(conn, dns_lookup_failed, d);
	return d;
}
