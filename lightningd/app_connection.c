#include <ccan/err/err.h>
#include <ccan/io/io.h>
#include <common/memleak.h>
#include <lightningd/app_connection.h>
#include <lightningd/channel.h>
#include <lightningd/htlc_end.h>
#include <lightningd/log.h>
#include <lightningd/peer_control.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

struct app_connection {
	/* The global state */
	struct lightningd *ld;

	/* The buffer (required to interpret tokens). */
	char *buffer;

	/* Internal state: */
	/* How much is already filled. */
	size_t used;
	/* How much has just been filled. */
	size_t len_read;

	/* We've been told to stop. */
	bool stop;
};

void handle_app_payment(
	enum onion_type *failcode,
	const struct htlc_in *hin,
	const struct route_step *rs)
{
	struct log *log = hin->key.channel->log;
	struct lightningd *ld = hin->key.channel->peer->ld;
	struct app_connection *appcon = ld->app_connection;

	log_debug(log, "Using app connection to handle the payment");

	if(!appcon) {
		log_debug(log, "App connection is not active");
		*failcode = WIRE_INVALID_REALM;
		return;
	}

	//FIXME: write request to connection
	io_wake(appcon);
	*failcode = 0;
}

static struct io_plan *write_app(struct io_conn *conn,
				  struct app_connection *appcon)
{
	return NULL; //FIXME
}

static struct io_plan *read_app(struct io_conn *conn,
				 struct app_connection *appcon)
{
	return NULL; //FIXME
}

static void destroy_appcon(struct app_connection *appcon)
{
	//un-register the connection in ld
	log_debug(appcon->ld->log, "Disconnected app");
	appcon->ld->app_connection = NULL;
}

static struct io_plan *app_connected(struct io_conn *conn,
				      struct lightningd *ld)
{
	struct app_connection *appcon;

	appcon = tal(conn, struct app_connection);
	appcon->ld = ld;
	appcon->used = 0;
	appcon->buffer = tal_arr(appcon, char, 64);
	appcon->stop = false;

	tal_add_destructor(appcon, destroy_appcon);

	//Register appcon in ld
	log_debug(ld->log, "Connected app");
	ld->app_connection = appcon;

	return io_duplex(conn,
			 io_read_partial(conn, appcon->buffer,
					 tal_count(appcon->buffer),
					 &appcon->len_read, read_app, appcon),
			 write_app(conn, appcon));
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

