#include <ccan/err/err.h>
#include <ccan/io/io.h>
#include <ccan/tal/str/str.h>
#include <common/memleak.h>
#include <lightningd/app_connection.h>
#include <lightningd/channel.h>
#include <lightningd/htlc_end.h>
#include <lightningd/json.h>
#include <lightningd/log.h>
#include <lightningd/peer_control.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>

enum app_result_type {
	/* Reject the payment immediately */
	PAYMENT_REJECT = 0,
	/* Keep the payment for now */
	PAYMENT_KEEP = 1,
	/* There was a connection error */
	PAYMENT_CONNECTION_ERROR = 3,
};

struct app_connection {
	/* The global state */
	struct lightningd *ld;
	int fd;
};

static bool write_all(int fd, const void *buf, size_t count)
{
	while(count) {
		ssize_t written = write(fd, buf, count);
		if(written < 0) return false;
		buf += written;
		count -= written;
	}
	return true;
}

static enum app_result_type read_app_response(const struct app_connection *appcon)
{
	/* The buffer (required to interpret tokens). */
	char *buffer = tal_arr(tmpctx, char, 64);

	/* How much is already filled. */
	size_t used = 0;

	jsmntok_t *toks;
	bool valid;

	/* Keep reading until we have a valid JSON object */
	while (true) {
		size_t remaining_space = tal_count(buffer) - used;

		ssize_t num_read = read(appcon->fd, buffer + used, remaining_space);
		if (num_read < 0) {
			//FIXME: proper logging
			return PAYMENT_CONNECTION_ERROR;
		}
		used += num_read;
		remaining_space -= num_read;

		toks = json_parse_input(buffer, used, &valid);
		if (toks) {
			if (tal_count(toks) == 1) {
				/* Empty buffer? (eg. just whitespace). */
				used = 0;
			} else {
				/* We have what we want */
				break;
			}
		}

		if (!valid) {
			//FIXME: proper logging
			return PAYMENT_CONNECTION_ERROR;
		}

		/* We may need to allocate more space for the rest. */
		if (!remaining_space) {
			tal_resize(&buffer, used * 2);
		}
	}

	/* FIXME: We may have read more than just the reponse we expect.
	This data is ignored; maybe this is not desired behavior.

	It should not be a problem, if the app behaves normally, that is,
	if the only data it ever sends is a single reply object after every call
	we do.
	*/

	//FIXME: actually read the result from the JSON data

	return PAYMENT_REJECT;
}

void handle_app_payment(
	enum onion_type *failcode,
	const struct htlc_in *hin,
	const struct route_step *rs)
{
	struct log *log = hin->key.channel->log;
	struct lightningd *ld = hin->key.channel->peer->ld;
	struct app_connection *appcon = ld->app_connection;
	char *command;

	log_debug(log, "Using app connection to handle the payment");

	if(!appcon) {
		log_debug(log, "App connection is not active: rejecting the payment");
		*failcode = WIRE_INVALID_REALM;
		return;
	}

	// Write the command to the socket
	command = tal_fmt(tmpctx,
		"{"
		"\"method\": \"handle_payment\", "
		"\"params\": {"
			"\"realm\": %d"
		"}, "
		"\"id\": 0}",
		rs->hop_data.realm
		);
	if(!write_all(appcon->fd, command, strlen(command))) {
		//FIXME: proper handling, e.g. closing the app connection
		log_debug(log, "Failed to write command to app connection socket");
		*failcode = WIRE_INVALID_REALM;
		return;
	}

	//Read response from the socket
	switch(read_app_response(appcon))
	{
	case PAYMENT_REJECT:
		log_debug(log, "App rejected the payment");
		*failcode = WIRE_INVALID_REALM;
		break;
	case PAYMENT_KEEP:
		log_debug(log, "App accepted the payment");
		*failcode = 0;
		break;
	case PAYMENT_CONNECTION_ERROR:
		log_debug(log, "App connection error: accepting the payment for now");
		//FIXME: proper handling, e.g. closing the app connection
		*failcode = 0;
		break;
	}
}

static struct io_plan *app_connected(struct io_conn *conn,
				      struct lightningd *ld)
{
	struct app_connection *appcon;

	//FIXME: refuse connections if we already have one, or support multiple
	//FIXME: handle closing of existing connection

	appcon = tal(ld, struct app_connection);
	appcon->ld = ld;
	appcon->fd = io_conn_fd(conn);

	//Register appcon in ld
	log_debug(ld->log, "Connected app");
	ld->app_connection = appcon;

	return io_close_taken_fd(conn);
}

static struct io_plan *incoming_app_connected(struct io_conn *conn,
					       struct lightningd *ld)
{
	/* Lifetime of app conn is limited to fd connect time. */
	return app_connected(notleak(conn), ld);
}

void setup_app_connection(struct lightningd *ld, const char *app_filename)
{
	struct sockaddr_un addr;
	int fd, old_umask;

	if (streq(app_filename, ""))
		return;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		errx(1, "domain socket creation failed");
	}
	if (strlen(app_filename) + 1 > sizeof(addr.sun_path))
		errx(1, "app filename '%s' too long", app_filename);
	strcpy(addr.sun_path, app_filename);
	addr.sun_family = AF_UNIX;

	/* Of course, this is racy! */
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0)
		errx(1, "app filename '%s' in use", app_filename);
	unlink(app_filename);

	/* This file is only rw by us! */
	old_umask = umask(0177);
	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)))
		err(1, "Binding app socket to '%s'", app_filename);
	umask(old_umask);

	if (listen(fd, 1) != 0)
		err(1, "Listening on '%s'", app_filename);

	log_debug(ld->log, "Listening on '%s'", app_filename);
	/* Technically this is a leak, but there's only one */
	notleak(io_new_listener(ld, fd, incoming_app_connected, ld));
}

