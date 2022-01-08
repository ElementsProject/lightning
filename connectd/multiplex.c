/*~ This contains all the code to shuffle data between socket to the peer
 * itself, and the subdaemons. */
#include "config.h"
#include <assert.h>
#include <ccan/io/io.h>
#include <common/status.h>
#include <common/utils.h>
#include <connectd/multiplex.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>

/* These four function handle subd->peer */
static struct io_plan *after_final_msg(struct io_conn *peer_conn,
				       struct peer *peer)
{
	/* io_close will want to free this itself! */
	assert(peer->to_peer == peer_conn);

	/* Invert ownership, so io_close frees peer for us */
	tal_steal(NULL, peer_conn);
	tal_steal(peer_conn, peer);

	return io_close(peer_conn);
}

static struct io_plan *write_to_peer(struct io_conn *peer_conn,
				     struct peer *peer)
{
	assert(peer->to_peer == peer_conn);

	/* Free last sent one (if any) */
	tal_free(peer->sent_to_peer);

	/* Pop tail of send queue */
	peer->sent_to_peer = msg_dequeue(peer->peer_outq);

	/* Nothing to send? */
	if (!peer->sent_to_peer) {
		/* Send final once subd is not longer connected */
		if (peer->final_msg && !peer->to_subd) {
			return io_write(peer_conn,
					peer->final_msg,
					tal_bytelen(peer->final_msg),
					after_final_msg, peer);
		}
		/* Tell them to read again, */
		io_wake(&peer->subd_in);

		/* Wait for them to wake us */
		return msg_queue_wait(peer_conn, peer->peer_outq,
				      write_to_peer, peer);
	}

	return io_write(peer_conn,
			peer->sent_to_peer,
			tal_bytelen(peer->sent_to_peer),
			write_to_peer, peer);
}

static struct io_plan *read_from_subd(struct io_conn *subd_conn,
				      struct peer *peer);
static struct io_plan *read_from_subd_done(struct io_conn *subd_conn,
					   struct peer *peer)
{
	size_t len = ((size_t *)peer->subd_in)[1023];
	assert(peer->to_subd == subd_conn);

	/* Trim to length */
	tal_resize(&peer->subd_in, len);

	/* Tell them to write. */
	msg_enqueue(peer->peer_outq, take(peer->subd_in));
	peer->subd_in = NULL;
	/* Wait for them to wake us */
	return io_wait(subd_conn, &peer->subd_in, read_from_subd, peer);
}

static struct io_plan *read_from_subd(struct io_conn *subd_conn,
				      struct peer *peer)
{
	/* We stash the length at the end */
	size_t *buf = tal_arr(peer, size_t, 1024);
	assert(peer->to_subd == subd_conn);

	peer->subd_in = (u8 *)buf;
	return io_read_partial(subd_conn, peer->subd_in,
			       sizeof(size_t) * 1023,
			       &buf[1023],
			       read_from_subd_done, peer);
}

/* These four function handle peer->subd */
static struct io_plan *write_to_subd(struct io_conn *subd_conn,
				     struct peer *peer)
{
	assert(peer->to_subd == subd_conn);

	/* Free last sent one (if any) */
	tal_free(peer->sent_to_subd);

	/* Pop tail of send queue */
	peer->sent_to_subd = msg_dequeue(peer->subd_outq);

	/* Nothing to send? */
	if (!peer->sent_to_subd) {
		/* Tell them to read again, */
		io_wake(&peer->peer_in);

		/* Wait for them to wake us */
		return msg_queue_wait(subd_conn, peer->subd_outq,
				      write_to_subd, peer);
	}

	return io_write(subd_conn,
			peer->sent_to_subd,
			tal_bytelen(peer->sent_to_subd),
			write_to_subd, peer);
}

static struct io_plan *read_from_peer(struct io_conn *peer_conn,
				      struct peer *peer);
static struct io_plan *read_from_peer_done(struct io_conn *peer_conn,
					   struct peer *peer)
{
	size_t len = ((size_t *)peer->peer_in)[1023];
	assert(peer->to_peer == peer_conn);

	/* Trim to length */
	tal_resize(&peer->peer_in, len);

	/* Tell them to write. */
	msg_enqueue(peer->subd_outq, take(peer->peer_in));
	peer->peer_in = NULL;
	/* Wait for them to wake us */
	return io_wait(peer_conn, &peer->peer_in, read_from_peer, peer);
}

static struct io_plan *read_from_peer(struct io_conn *peer_conn,
				      struct peer *peer)
{
	/* We stash the length at the end */
	size_t *buf = tal_arr(peer, size_t, 1024);
	assert(peer->to_peer == peer_conn);

	peer->peer_in = (u8 *)buf;
	return io_read_partial(peer_conn, peer->peer_in,
			       sizeof(size_t) * 1023,
			       &buf[1023],
			       read_from_peer_done, peer);
}

static struct io_plan *subd_conn_init(struct io_conn *subd_conn, struct peer *peer)
{
	peer->to_subd = subd_conn;
	return io_duplex(subd_conn,
			 read_from_subd(subd_conn, peer),
			 write_to_subd(subd_conn, peer));
}

static void destroy_subd_conn(struct io_conn *subd_conn, struct peer *peer)
{
	assert(subd_conn == peer->to_subd);
	peer->to_subd = NULL;
	/* In case they were waiting for this to send final_msg */
	if (peer->final_msg)
		msg_wake(peer->peer_outq);
}

bool multiplex_subd_setup(struct peer *peer, int *fd_for_subd)
{
	int fds[2];

	if (socketpair(AF_LOCAL, SOCK_STREAM, 0, fds) != 0) {
		status_broken("Failed to create socketpair: %s",
			      strerror(errno));
		return false;
	}
	peer->to_subd = io_new_conn(peer, fds[0], subd_conn_init, peer);
	tal_add_destructor2(peer->to_subd, destroy_subd_conn, peer);
	*fd_for_subd = fds[1];
	return true;
}

static void destroy_peer_conn(struct io_conn *peer_conn, struct peer *peer)
{
	assert(peer->to_peer == peer_conn);
	peer->to_peer = NULL;

	/* Close internal connections if not already. */
	if (peer->to_subd)
		io_close(peer->to_subd);
}

struct io_plan *multiplex_peer_setup(struct io_conn *peer_conn,
				     struct peer *peer)
{
	/*~ If conn closes, we close the subd connections and wait for
	 * lightningd to tell us to close with the peer */
	tal_add_destructor2(peer_conn, destroy_peer_conn, peer);

	return io_duplex(peer_conn,
			 read_from_peer(peer_conn, peer),
			 write_to_peer(peer_conn, peer));
}

void multiplex_final_msg(struct peer *peer, const u8 *final_msg TAKES)
{
	peer->final_msg = tal_dup_talarr(peer, u8, final_msg);
	if (!peer->to_subd)
		io_wake(peer->peer_outq);
}
