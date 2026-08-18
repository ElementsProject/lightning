/* Test the client-connection lifecycle when a request is rejected:
 * when libhsmd returns NULL from hsmd_handle_client_message, hsmd must
 * close the client connection exactly once, and must not touch it
 * again afterwards.
 *
 * That contract isn't observable from outside the process (the client
 * just sees its fd close), so a black-box test can't verify it.
 * Instead we compile hsmd.c into this test and watch the connection
 * itself:
 *
 * 1. io_set_finish() on the client conn: ccan/io runs the finish
 *    callback exactly when the conn is closed, so counting calls tells
 *    us the conn was closed once (not zero times, not twice).
 *
 * 2. Every io_write_wire() from hsmd.c is intercepted (see the macro
 *    below), and a write to the client conn *after* its finish
 *    callback has run aborts the test.  This makes any ordering
 *    violation fail deterministically, without needing ASan or
 *    valgrind to notice.
 */
#include "config.h"
#include <assert.h>
#include <bitcoin/chainparams.h>
#include <bitcoin/privkey.h>
#include <bitcoin/pubkey.h>
#include <common/setup.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <wire/wire_io.h>

/* The client conn created in main(), watched by the checks below. */
static struct io_conn *client_conn;

/* How many times the client conn's finish callback has run. */
static int finish_count;

/* Distinct pointer for io_break, so main() knows why io_loop returned. */
static char closed_token[] = "closed";

/* Wrapper around the real io_write_wire_: a closed conn (finish
 * callback already ran) must never be written to again. */
static struct io_plan *check_client_write(struct io_conn *conn,
					  const u8 *data,
					  struct io_plan *(*next)(struct io_conn *, void *),
					  void *next_arg)
{
	if (conn == client_conn && finish_count != 0) {
		fprintf(stderr,
			"write to client conn after close (finish_count=%d)\n",
			finish_count);
		abort();
	}
	return io_write_wire_(conn, data, next, next_arg);
}

/* Redefine io_write_wire before pulling in hsmd.c, so every write the
 * daemon makes (req_reply in particular) goes through the check above. */
#undef io_write_wire
#define io_write_wire(conn, data, next, arg)				\
	check_client_write((conn), (data),				\
			   typesafe_cb_preargs(struct io_plan *, void *, \
					       (next), (arg),		\
					       struct io_conn *),	\
			   (arg))

/* Include the daemon itself so we can drive its statics (new_client,
 * handle_client via the io loop).  Rename its main() out of the way. */
int unused_main(int argc, char *argv[]);
#define main unused_main
#include "../hsmd.c"
#undef main
#undef io_write_wire

/* Finish callback for the client conn: ccan/io calls this exactly when
 * the conn is closed.  Closing is what ends the test, so break out. */
static void client_finished(struct io_conn *conn UNUSED, int *count)
{
	(*count)++;
	io_break(closed_token);
}

/* Any valid pubkey will do as the client's node id. */
static void make_peer_id(struct node_id *id)
{
	struct privkey priv;
	struct pubkey pub;

	memset(&priv, 1, sizeof(priv));
	assert(pubkey_from_privkey(&priv, &pub));
	node_id_from_pubkey(id, &pub);
}

int main(int argc, char *argv[])
{
	int status_fds[2], client_fds[2];
	struct node_id peer_id;
	struct secret secret;
	struct client *c;
	const struct chainparams *params;
	u8 hsmseed[32];
	u8 *msg;
	void *ret;

	common_setup(argv[0]);
	uintmap_init(&clients);

	/* hsmd reports bad requests to lightningd over status_conn; give
	 * it a socketpair whose other end we simply never read. */
	assert(socketpair(AF_LOCAL, SOCK_STREAM, 0, status_fds) == 0);
	status_conn = daemon_conn_new(NULL, status_fds[0], NULL, NULL, NULL);
	status_setup_async(status_conn);

	/* Initialize libhsmd's secrets from a dummy seed (normally done
	 * via the WIRE_HSMD_INIT message from lightningd). */
	params = chainparams_for_network("regtest");
	memset(hsmseed, 1, sizeof(hsmseed));
	msg = hsmd_init(hsmseed, sizeof(hsmseed), 6,
			params->bip32_key_version, HSM_SECRET_PLAIN);
	assert(msg);
	/* hsmd_init returns take(): consume the marker, then free. */
	taken(msg);
	tal_free(msg);

	/* Connect a fake per-channel client (as if lightningd had passed
	 * an fd to a channeld).  dbid 1 = an ordinary channel client;
	 * HSM_PERM_COMMITMENT_POINT allows check_future_secret. */
	assert(socketpair(AF_LOCAL, SOCK_STREAM, 0, client_fds) == 0);
	make_peer_id(&peer_id);
	c = new_client(NULL, params, &peer_id, 1,
		       HSM_PERM_COMMITMENT_POINT, client_fds[0]);
	client_conn = c->conn;
	io_set_finish(c->conn, client_finished, &finish_count);

	/* Send a request libhsmd is guaranteed to reject: commitment
	 * index 2^48 is beyond the shachain, so per_commit_secret fails
	 * and the handler returns via hsmd_status_bad_request -> NULL. */
	memset(&secret, 0, sizeof(secret));
	msg = towire_hsmd_check_future_secret(NULL, 1ULL << SHACHAIN_BITS,
					      &secret);
	assert(wire_sync_write(client_fds[1], take(msg)));

	/* Run the daemon's io loop.  It reads the request, rejects it,
	 * and must close the client conn, which fires client_finished. */
	ret = io_loop(NULL, NULL);
	assert(ret == closed_token);

	/* The heart of the test: closed exactly once. */
	assert(finish_count == 1);

	close(client_fds[1]);
	close(status_fds[1]);
	tal_free(status_conn);
	common_shutdown();
	return 0;
}
