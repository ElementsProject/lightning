#include "daemon/dns.h"
#include "daemon/log.h"
#include "irc.h"

void (*irc_privmsg_cb)(struct ircstate *, const struct privmsg *) = NULL;
void (*irc_command_cb)(struct ircstate *, const struct irccommand *) = NULL;
void (*irc_connect_cb)(struct ircstate *) = NULL;
void (*irc_disconnect_cb)(struct ircstate *) = NULL;

static struct io_plan *irc_connected(struct io_conn *conn, struct lightningd_state *dstate, const struct netaddr *netaddr, struct ircstate *state);
static void irc_disconnected(struct io_conn *conn, struct ircstate *state);

bool irc_send_msg(struct ircstate *state, struct privmsg *m)
{
	return irc_send(state, "PRIVMSG", "%s :%s", m->channel, m->msg);
}

/* Send a raw irccommand to the IRC server. */
bool irc_send(struct ircstate *state, const char *command, const char *fmt, ...)
{
	va_list ap;
	struct irccommand *c = tal(state, struct irccommand);

	c->prefix = NULL;

	if (!state->connected)
		return false;

	va_start(ap, fmt);
	c->command = tal_strdup(c, command);
	c->params = tal_vfmt(c, fmt, ap);
	va_end(ap);

	list_add_tail(&state->writequeue, &c->list);
	io_wake(state);
	return true;
}

/* Write buffered irccommands to the IRC connection. Commands can be
   buffered using irc_send. */
static struct io_plan *irc_write_loop(struct io_conn *conn, struct ircstate *state)
{
	state->writebuffer = tal_free(state->writebuffer);

	struct irccommand *m = list_pop(&state->writequeue, struct irccommand, list);
	if (m == NULL)
		return io_out_wait(conn, state, irc_write_loop, state);

	bool hasprefix = m->prefix == NULL;
	state->writebuffer = tal_fmt(
		state, "%s%s%s %s\r\n",
		hasprefix ? "" : m->prefix,
		hasprefix ? "" : " ",
		m->command,
		m->params);

	tal_free(m);

	log_debug(state->log, "Sending: \"%s\"", state->writebuffer);

	return io_write(
		       conn,
		       state->writebuffer, strlen(state->writebuffer),
		       irc_write_loop, state
		       );
}

/*
 * Called by the read loop to handle individual lines. This splits the
 * line into a struct irccommand and passes it on to the specific
 * handlers for the irccommand type. It silently drops any irccommand
 * that has an unhandled type.
 */
static void handle_irc_command(struct ircstate *state, const char *line)
{
	log_debug(state->log, "Received: \"%s\"", line);

	struct irccommand *m = talz(state, struct irccommand);
	char** splits = tal_strsplit(m, line, " ", STR_NO_EMPTY);
	int numsplits = tal_count(splits) - 1;

	if (numsplits > 2 && strstarts(splits[0], ":")) {
		m->prefix = splits[0];
		splits++;
	}
	m->command = splits[0];
	m->params = tal_strjoin(m, splits + 1, " ", STR_NO_TRAIL);

	if (streq(m->command, "PING")) {
		irc_send(state, "PONG", "%s", m->params);

	} else if (streq(m->command, "PRIVMSG")) {
		struct privmsg *pm = talz(m, struct privmsg);
		pm->sender = m->prefix;
		pm->channel = splits[1];
		pm->msg = tal_strjoin(m, splits + 2, " ", STR_NO_TRAIL);
		irc_privmsg_cb(state, pm);
	}

	if (irc_command_cb != NULL)
		irc_command_cb(state, m);

	tal_free(m);
}

/*
 * Read incoming data and split it along the newline boundaries. Takes
 * care of buffering incomplete lines and passes the lines to the
 * handle_irc_command handler.
 */
static struct io_plan *irc_read_loop(struct io_conn *conn, struct ircstate *state)
{

	size_t len = state->readlen + state->buffered;
	char *start = state->buffer, *end;

	while ((end = memchr(start, '\n', len)) != NULL) {
		/* Strip "\r\n" from lines. */
		const char *line = tal_strndup(state, start, end - 1 - start);
		handle_irc_command(state, line);
		tal_free(line);
		len -= (end + 1 - start);
		start = end + 1;
	}

	/* Move any partial data back down. */
	memmove(state->buffer, start, len);
	state->buffered = len;

	return io_read_partial(conn, state->buffer + state->buffered,
			       sizeof(state->buffer) - state->buffered,
			       &state->readlen, irc_read_loop, state);
}

static void irc_failed(struct lightningd_state *dstate, struct ircstate *state)
{
	irc_disconnected(state->conn, state);
	state->connected = false;
}

static void irc_disconnected(struct io_conn *conn, struct ircstate *state)
{
	log_debug(state->log, "Lost connection to IRC server");
	state->connected = false;
	state->conn = NULL;
	state->readlen = 0;
	state->buffered = 0;
	memset(state->buffer, 0, sizeof(state->buffer));

	/* Clear any pending commands, they're no longer useful */
	while (!list_empty(&state->writequeue))
		tal_free(list_pop(&state->writequeue, struct irccommand, list));

	/* Same goes for partially written commands */
	state->writebuffer = tal_free(state->writebuffer);

	if (irc_disconnect_cb != NULL)
		irc_disconnect_cb(state);
}

void irc_connect(struct ircstate *state)
{
	state->connected = false;
	list_head_init(&state->writequeue);

	log_debug(state->log, "Connecting to IRC server %s", state->server);
	dns_resolve_and_connect(state->dstate, state->server, "6667", irc_connected, irc_failed, state);
}

static struct io_plan *irc_connected(struct io_conn *conn, struct lightningd_state *dstate, const struct netaddr *netaddr, struct ircstate *state)
{
	io_set_finish(conn, irc_disconnected, state);
	state->conn = conn;
	state->connected = true;
	irc_send(state, "USER", "%s 0 * :A lightning node", state->nick);
	irc_send(state, "NICK", "%s", state->nick);

	if (irc_connect_cb != NULL)
		irc_connect_cb(state);

	return io_duplex(conn,
			 io_read_partial(conn,
					 state->buffer, sizeof(state->buffer),
					 &state->readlen, irc_read_loop, state),
			 irc_write_loop(conn, state));
}
