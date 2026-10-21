#include "config.h"
#include <ccan/closefrom/closefrom.h>
#include <ccan/io/io.h>
#include <ccan/list/list.h>
#include <ccan/noerr/noerr.h>
#include <ccan/tal/str/str.h>
#include <common/status.h>
#include <common/timeout.h>
#include <common/wireaddr.h>
#include <connectd/dns.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/*~ Name resolution must never run on connectd's single io thread: with a
 * slow or unresponsive nameserver, glibc's getaddrinfo() would sit in the
 * loop for ~10s, holding up every peer on the machine.  libc helpers are
 * no help: getaddrinfo_a() is GNU-only (musl, i.e. our static builds, has
 * nothing), and threads are against this daemon's grain (tal is not
 * threadsafe).
 *
 * So instead we fork() a child to run getaddrinfo() and serialize the results
 * down a pipe; the parent never blocks: it simply reads the pipe from the io
 * loop, and runs the caller's callback from a loop callback.  fork() is safe
 * here because connectd is single-threaded, and since connectd sets
 * SIGCHLD to SIG_IGN the children reap themselves: pipe EOF is all we need
 * to know a child is finished.
 *
 * Doing the lookup in libc inside the child, rather than parsing DNS
 * ourselves, keeps /etc/hosts, search domains, systemd-resolved and
 * AI_ADDRCONFIG ordering behaving exactly as before, and keeps DNS packet
 * parsing out of connectd itself. */

#define DNS_TOTAL_TIMEOUT_SECS 30
/* One child per lookup, and we don't want a gossip churn (which can fire
 * off hundreds of connects) to fork hundreds of resolvers: excess lookups
 * queue FIFO and start as a child exits.  The 30 second cap spans queue
 * time too, so no lookup waits longer than that. */
#define DNS_MAX_CONCURRENT_LOOKUPS 10
#define DNS_MAX_ADDRS 64
/* One serialized address: type byte (1=v4, 2=v6), 16 zero-padded address
 * bytes, then 2 raw network-order port bytes. */
#define DNS_RECORD_LEN 19
#define DNS_PIPE_MAX (DNS_MAX_ADDRS * DNS_RECORD_LEN)
#define DNS_READ_BUF 512

/* How many resolvers we have running, and those waiting for a slot
 * (connectd is single-threaded, so plain statics are fine). */
static unsigned int dns_num_active;
static struct list_head dns_queue = LIST_HEAD_INIT(dns_queue);

struct dns_lookup {
	struct timers *timers;
	dns_result_cb cb;
	void *cb_arg;

	char *hostname;
	u16 port;

	/* Results: once finished, exactly one is meaningful: addrs
	 * (non-empty) or err (a string). */
	struct wireaddr *addrs;
	const char *err;
	bool finished;

	/* Queued for a child slot / actually has a child+pipe? */
	bool queued;
	bool started;
	struct list_node list;

	pid_t child;		/* 0 once we know it's gone. */
	struct io_conn *conn;	/* Pipe read end, NULL once gone. */
	struct oneshot *total_timer;
	struct oneshot *call_timer;

	/* Bytes accumulated from the child, and bytes of the last read. */
	u8 *in;
	size_t inode;
	u8 readbuf[DNS_READ_BUF];
	size_t readlen;
};

static void dns_start(struct dns_lookup *lookup);
static void dns_pump_queue(void);
static void dns_resolve_in_child(int fd, const char *hostname, u16 port);
static void dns_conn_destroy(struct io_conn *conn, struct dns_lookup *lookup);
static struct io_plan *dns_read_init(struct io_conn *conn,
				     struct dns_lookup *lookup);

/* Defer the callback onto the io loop: we never call it synchronously, and
 * it must be the last thing we do (it may free lookup, and thus us). */
static void dns_call_cb(struct dns_lookup *lookup)
{
	lookup->call_timer = NULL;
	status_debug("dns: lookup of %s %s",
		     lookup->hostname,
		     lookup->err ? lookup->err : "succeeded");
	/* Callback may free lookup: the lookups above are all we do first. */
	if (lookup->err)
		lookup->cb(lookup->cb_arg, NULL, lookup->err);
	else
		lookup->cb(lookup->cb_arg, lookup->addrs, NULL);
}

/* Stop everything and schedule the callback.  Safe from timer or normal
 * loop context; from inside an io callback on lookup->conn, detach the conn
 * (lookup->conn = NULL) and return io_close() rather than using this. */
static void dns_finish(struct dns_lookup *lookup)
{
	struct io_conn *conn;

	if (lookup->finished)
		return;
	lookup->finished = true;

	lookup->total_timer = tal_free(lookup->total_timer);
	if (lookup->queued) {
		list_del(&lookup->list);
		lookup->queued = false;
	}
	if (lookup->child > 0) {
		/* No EOF seen yet, so the child must still be resolving:
		 * any exit would have closed the pipe and woken us.  Safe
		 * to kill: its pid cannot have been recycled yet. */
		kill(lookup->child, SIGKILL);
		lookup->child = 0;
	}
	if (lookup->conn) {
		conn = lookup->conn;
		lookup->conn = NULL;	/* Destructor checks this. */
		tal_free(conn);
	}
	lookup->call_timer = new_reltimer(lookup->timers, lookup,
					  time_from_sec(0), dns_call_cb,
					  lookup);
	/* Our child (if we had one) is gone now, so a queued lookup may
	 * have a slot: hand it over (after scheduling our own callback,
	 * for fairness). */
	if (lookup->started) {
		lookup->started = false;
		dns_num_active--;
		dns_pump_queue();
	}
}

/* Hand the lookup its pipe and child: called directly if a slot is free,
 * else from dns_pump_queue when one exits. */
static void dns_start(struct dns_lookup *lookup)
{
	int fds[2];

	assert(!lookup->started);

	if (pipe(fds) != 0) {
		lookup->err = tal_fmt(lookup, "dns pipe failed: %s",
				      strerror(errno));
		dns_finish(lookup);
		return;
	}
	/* Not strictly needed (we don't exec), but NSS backends can
	 * subprocess, and leaking the write end there would pin EOF. */
	fcntl(fds[0], F_SETFD, FD_CLOEXEC);
	fcntl(fds[1], F_SETFD, FD_CLOEXEC);

	lookup->child = fork();
	if (lookup->child < 0) {
		close(fds[0]);
		close(fds[1]);
		lookup->err = tal_fmt(lookup, "dns fork failed: %s",
				      strerror(errno));
		dns_finish(lookup);
		return;
	}

	if (lookup->child == 0) {
		close(fds[0]);
		dns_resolve_in_child(fds[1], lookup->hostname, lookup->port);
		/* Not reached. */
	}

	close(fds[1]);

	lookup->conn = io_new_conn(lookup, fds[0], dns_read_init, lookup);
	if (!lookup->conn) {	/* Out of poll fds, etc. */
		close_noerr(fds[0]);
		/* child > 0, so dns_finish will kill it. */
		lookup->err = tal_fmt(lookup, "dns pipe setup failed");
		dns_finish(lookup);
		return;
	}
	tal_add_destructor2(lookup->conn, dns_conn_destroy, lookup);

	status_debug("dns: async lookup of %s started", lookup->hostname);
	dns_num_active++;
	lookup->started = true;
}

/* Start queued lookups while we have child slots free.  A failed start
 * finishes its lookup (with an error, via callback) without ever taking a
 * slot, so the loop simply moves on to the next one. */
static void dns_pump_queue(void)
{
	while (dns_num_active < DNS_MAX_CONCURRENT_LOOKUPS
	       && !list_empty(&dns_queue)) {
		struct dns_lookup *lookup
			= list_pop(&dns_queue, struct dns_lookup, list);
		lookup->queued = false;
		dns_start(lookup);
	}
}

/*~ Parsing the child's output: strictly, and fail-closed on anything
 * unexpected. */
static void dns_parse_results(struct dns_lookup *lookup)
{
	const u8 *p = lookup->in;
	size_t n = lookup->inode;

	if (n == 0) {
		lookup->err = tal_fmt(lookup, "dns lookup of %s failed",
				      lookup->hostname);
		return;
	}
	if (n % DNS_RECORD_LEN != 0) {
		lookup->err = tal_fmt(lookup,
				      "dns resolver returned malformed data");
		return;
	}

	for (size_t off = 0; off < n; off += DNS_RECORD_LEN) {
		struct wireaddr wa;
		/* The records are packed at arbitrary byte offsets, so we
		 * must copy the address into an aligned struct, not cast
		 * the buffer pointer. */
		struct in_addr ip4;
		struct in6_addr ip6;
		u16 port = ((u16)p[off + 17] << 8) | p[off + 18];

		if (p[off] == 1) {
			memcpy(&ip4, p + off + 1, sizeof(ip4));
			wireaddr_from_ipv4(&wa, &ip4, port);
		} else if (p[off] == 2) {
			memcpy(&ip6, p + off + 1, sizeof(ip6));
			wireaddr_from_ipv6(&wa, &ip6, port);
		} else {
			lookup->err = tal_fmt(lookup, "dns resolver returned"
					      " unexpected address type %u",
					      p[off]);
			tal_free(lookup->addrs);
			lookup->addrs = tal_arr(lookup, struct wireaddr, 0);
			return;
		}

		/* getaddrinfo can hand us repeats: dedup. */
		if (wireaddr_arr_contains(lookup->addrs, &wa))
			continue;
		tal_arr_expand(&lookup->addrs, wa);
	}

	if (tal_count(lookup->addrs) == 0)
		lookup->err = tal_fmt(lookup, "dns lookup of %s returned no"
				      " addresses", lookup->hostname);
}

/* The pipe closed: normally that means the child exited (EOF fails the
 * conn rather than calling our read callback), and we parse the bytes it
 * managed to send.  Any io error which closes the conn lands here too:
 * either way, don't trust the pid to kill: the child may already have been
 * reaped (SIGCHLD is ignored) and its pid recycled into another child
 * entirely. */
static void dns_conn_destroy(struct io_conn *conn, struct dns_lookup *lookup)
{
	if (lookup->finished)
		return;

	lookup->conn = NULL;	/* Being freed: dns_finish mustn't. */
	lookup->child = 0;
	dns_parse_results(lookup);
	dns_finish(lookup);
}

/*~ io callbacks: must not free conn, so anything terminal detaches conn and
 * returns io_close().  EOF itself is *not* seen here (that fails the conn and
 * runs its destructor): we're only ever called with lookup->readlen > 0. */
static struct io_plan *dns_read_reply(struct io_conn *conn,
				      struct dns_lookup *lookup)
{
	size_t newlen = lookup->inode + lookup->readlen;

	if (newlen > DNS_PIPE_MAX) {
		lookup->err = tal_fmt(lookup, "dns resolver returned too many"
				      " addresses");
		lookup->child = 0;	/* Closing will EPIPE it out. */
		lookup->conn = NULL;
		dns_finish(lookup);
		return io_close(conn);
	}

	tal_resize(&lookup->in, newlen);
	memcpy(lookup->in + lookup->inode, lookup->readbuf, lookup->readlen);
	lookup->inode = newlen;

	return io_read_partial(conn, lookup->readbuf,
			       sizeof(lookup->readbuf), &lookup->readlen,
			       dns_read_reply, lookup);
}

static struct io_plan *dns_read_init(struct io_conn *conn,
				     struct dns_lookup *lookup)
{
	return io_read_partial(conn, lookup->readbuf,
			       sizeof(lookup->readbuf), &lookup->readlen,
			       dns_read_reply, lookup);
}

static void dns_total_timeout(struct dns_lookup *lookup)
{
	lookup->total_timer = NULL;
	lookup->err = tal_fmt(lookup, "dns lookup timed out");
	dns_finish(lookup);	/* Kills the child, if it had one. */
}

/* If ctx goes away, we vanish too: main job is leaving the queue if we
 * were still sitting in it. */
static void destroy_dns_lookup(struct dns_lookup *lookup)
{
	if (lookup->queued) {
		list_del(&lookup->list);
		lookup->queued = false;
	}
}

/*~ Child side: we're a copy of connectd, so first shed every fd we
 * inherited (see dns_resolve_in_child), then touch nothing shared, make no
 * status_ calls (they'd impersonate connectd to lightningd) and never
 * return: only _exit(). */
static bool write_all(int fd, const void *p, size_t len)
{
	while (len != 0) {
		ssize_t n = write(fd, p, len);
		if (n <= 0) {
			if (n < 0 && errno == EINTR)
				continue;
			return false;
		}
		p += n;
		len -= n;
	}
	return true;
}

static void dns_resolve_in_child(int fd, const char *hostname, u16 port)
{
	struct addrinfo hints, *res, *rp;
	char portstr[7];
	unsigned int num = 0;

	/* We're a fork, so we inherited every fd connectd holds: peer
	 * sockets, the lightningd wires, and the *other* lookups' pipes:
	 * a child which then wedges would pin those pipes' EOF until its
	 * own alarm() fired.  Move our pipe to a fixed low fd and drop
	 * everything else: from here we hold exactly one fd, and
	 * status_ calls through stdout can't even leak to lightningd. */
	if (fd != STDIN_FILENO) {
		if (dup2(fd, STDIN_FILENO) == -1)
			_exit(1);
		close(fd);
		fd = STDIN_FILENO;
	}
	/* dup2() clears close-on-exec, and NSS backends can subprocess:
	 * a stray inheritor of the write end would pin the parent's EOF
	 * just as well as a wedged child would. */
	fcntl(fd, F_SETFD, FD_CLOEXEC);
	closefrom(STDIN_FILENO + 1);

	/* In case libc itself wedges, don't outlive the parent's cap. */
	alarm(DNS_TOTAL_TIMEOUT_SECS);
	signal(SIGPIPE, SIG_IGN);

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = AF_UNSPEC;
	hints.ai_protocol = 0;
	/* AI_ADDRCONFIG speeds up connects on single-stack hosts by
	 * pruning unreachable address families. */
	hints.ai_flags = AI_ADDRCONFIG;

	snprintf(portstr, sizeof(portstr), "%u", port);
	if (getaddrinfo(hostname, portstr, &hints, &res) != 0)
		_exit(0);	/* Write nothing: parent sees EOF. */

	for (rp = res; rp; rp = rp->ai_next) {
		u8 rec[DNS_RECORD_LEN];

		if (num == DNS_MAX_ADDRS)
			break;
		memset(rec, 0, sizeof(rec));
		if (rp->ai_family == AF_INET) {
			const struct sockaddr_in *s4 = (void *)rp->ai_addr;
			if (rp->ai_addrlen < sizeof(*s4))
				continue;
			rec[0] = 1;
			memcpy(rec + 1, &s4->sin_addr, 4);
			memcpy(rec + 17, &s4->sin_port, 2);
		} else if (rp->ai_family == AF_INET6) {
			const struct sockaddr_in6 *s6 = (void *)rp->ai_addr;
			if (rp->ai_addrlen < sizeof(*s6))
				continue;
			rec[0] = 2;
			memcpy(rec + 1, &s6->sin6_addr, 16);
			memcpy(rec + 17, &s6->sin6_port, 2);
		} else {
			continue;
		}
		/* On EPIPE the parent is gone: stop. */
		if (!write_all(fd, rec, sizeof(rec)))
			break;
		num++;
	}
	_exit(0);
}

struct dns_lookup *async_dns_resolve(const tal_t *ctx,
				     struct timers *timers,
				     const char *hostname,
				     u16 port,
				     dns_result_cb cb,
				     void *cb_arg)
{
	struct dns_lookup *lookup = tal(ctx, struct dns_lookup);

	lookup->timers = timers;
	lookup->cb = cb;
	lookup->cb_arg = cb_arg;
	lookup->hostname = tal_strdup(lookup, hostname);
	lookup->port = port;
	lookup->addrs = tal_arr(lookup, struct wireaddr, 0);
	lookup->err = NULL;
	lookup->finished = false;
	lookup->queued = false;
	lookup->started = false;
	list_node_init(&lookup->list);
	lookup->child = 0;
	lookup->conn = NULL;
	lookup->call_timer = NULL;
	lookup->in = tal_arr(lookup, u8, 0);
	lookup->inode = 0;
	lookup->readlen = 0;
	/* If ctx dies while we're queued, we must leave the queue.  We
	 * deliberately don't kill a running child here: it may already have
	 * exited and its pid been recycled (SIGCHLD is ignored), and it
	 * will die on EPIPE or its own alarm regardless. */
	tal_add_destructor(lookup, destroy_dns_lookup);

	/* The cap spans queueing too: a lookup never takes longer than
	 * DNS_TOTAL_TIMEOUT_SECS from ask to callback. */
	lookup->total_timer = new_reltimer(timers, lookup,
					   time_from_sec(DNS_TOTAL_TIMEOUT_SECS),
					   dns_total_timeout, lookup);

	if (dns_num_active < DNS_MAX_CONCURRENT_LOOKUPS) {
		dns_start(lookup);
	} else {
		status_debug("dns: lookup of %s queued, %u running",
			     hostname, dns_num_active);
		list_add_tail(&dns_queue, &lookup->list);
		lookup->queued = true;
	}
	return lookup;
}
