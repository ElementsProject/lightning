#ifndef LIGHTNING_IRC_H
#define LIGHTNING_IRC_H

#include "config.h"
#include "daemon/lightningd.h"
#include <ccan/io/io.h>
#include <ccan/short_types/short_types.h>
#include <ccan/str/str.h>
#include <ccan/tal/str/str.h>
#include <ccan/time/time.h>
#include <ccan/timer/timer.h>
#include <netdb.h>
#include <stdio.h>
#include <sys/socket.h>

struct irccommand {
	struct list_node list;
	const char *prefix;
	const char *command;
	const char *params;
};

struct privmsg {
	const char *channel;
	const char *sender;
	const char *msg;
};

struct ircstate {
	/* Meta information */
	const char *nick;
	const char *server;

	/* Connection and reading */
	struct io_conn *conn;
	char buffer[512];
	size_t readlen;
	size_t buffered;

	/* Write queue related */
	struct list_head writequeue;
	char *writebuffer;

	/* Pointer to external state, making it available to callbacks */
	struct lightningd_state *dstate;

	struct log *log;

	/* Are we currently connected? */
	bool connected;

	/* Time to wait after getting disconnected before reconnecting. */
	struct timerel reconnect_timeout;
};

/* Callbacks to register for incoming messages, events and raw commands */
extern void (*irc_privmsg_cb)(struct ircstate *, const struct privmsg *);
extern void (*irc_command_cb)(struct ircstate *, const struct irccommand *);
extern void (*irc_connect_cb)(struct ircstate *);
extern void (*irc_disconnect_cb)(struct ircstate *);

/* Send messages to IRC */
bool irc_send(struct ircstate *state, const char *command, const char *fmt, ...) PRINTF_FMT(3,4);
bool irc_send_msg(struct ircstate *state, struct privmsg *m);

/* Register IRC connection with io */
void irc_connect(struct ircstate *state);

#endif /* LIGHTNING_IRC_H */
