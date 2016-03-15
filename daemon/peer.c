#include "bitcoind.h"
#include "close_tx.h"
#include "commit_tx.h"
#include "controlled_time.h"
#include "cryptopkt.h"
#include "dns.h"
#include "find_p2sh_out.h"
#include "jsonrpc.h"
#include "lightningd.h"
#include "log.h"
#include "names.h"
#include "peer.h"
#include "secrets.h"
#include "state.h"
#include "timeout.h"
#include <bitcoin/base58.h>
#include <bitcoin/script.h>
#include <bitcoin/tx.h>
#include <ccan/array_size/array_size.h>
#include <ccan/io/io.h>
#include <ccan/list/list.h>
#include <ccan/noerr/noerr.h>
#include <ccan/ptrint/ptrint.h>
#include <ccan/str/hex/hex.h>
#include <ccan/structeq/structeq.h>
#include <ccan/tal/str/str.h>
#include <ccan/tal/tal.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>

#define FIXME_STUB(peer) do { log_broken((peer)->dstate->base_log, "%s:%u: Implement %s!", __FILE__, __LINE__, __func__); abort(); } while(0)

struct json_connecting {
	/* This owns us, so we're freed after command_fail or command_success */
	struct command *cmd;
	const char *name, *port;
	u64 satoshis;
};

struct pending_cmd {
	struct list_node list;
	void (*dequeue)(struct peer *, void *arg);
	void *arg;
};

static struct peer *find_peer(struct lightningd_state *dstate,
			      const char *buffer,
			      jsmntok_t *peeridtok)
{
	struct pubkey peerid;
	struct peer *peer;

	if (!pubkey_from_hexstr(dstate->secpctx,
				buffer + peeridtok->start,
				peeridtok->end - peeridtok->start, &peerid))
		return NULL;

	list_for_each(&dstate->peers, peer, list) {
		if (peer->state != STATE_INIT && pubkey_eq(&peer->id, &peerid))
			return peer;
	}
	return NULL;
}

static void queue_output_pkt(struct peer *peer, Pkt *pkt)
{
	size_t n = tal_count(peer->outpkt);
	tal_resize(&peer->outpkt, n+1);
	peer->outpkt[n] = pkt;

	/* In case it was waiting for output. */
	io_wake(peer);
}

static struct json_result *null_response(const tal_t *ctx)
{
	struct json_result *response;
		
	response = new_json_result(ctx);
	json_object_start(response, NULL);
	json_object_end(response);
	return response;
}
	
static void peer_cmd_complete(struct peer *peer, enum command_status status)
{
	assert(peer->curr_cmd.cmd != INPUT_NONE);

	/* If it's a json command, complete that now. */
	if (peer->curr_cmd.jsoncmd) {
		if (status == CMD_FAIL)
			/* FIXME: y'know, details. */
			command_fail(peer->curr_cmd.jsoncmd, "Failed");
		else {
			assert(status == CMD_SUCCESS);
			command_success(peer->curr_cmd.jsoncmd,
					null_response(peer->curr_cmd.jsoncmd));
		}
	}
	peer->curr_cmd.cmd = INPUT_NONE;
}

static void set_current_command(struct peer *peer, 
				const enum state_input input,
				void *idata,
				struct command *jsoncmd)
{
	assert(peer->curr_cmd.cmd == INPUT_NONE);
	assert(input != INPUT_NONE);

	peer->curr_cmd.cmd = input;
	/* This is a union, so assign to any member. */
	peer->curr_cmd.cmddata.pkt = idata;
	peer->curr_cmd.jsoncmd = jsoncmd;
}

static void state_single(struct peer *peer,
			 const enum state_input input,
			 const union input *idata)
{
	enum command_status status;
	Pkt *outpkt;
	const struct bitcoin_tx *broadcast;

	status = state(peer, peer, input, idata, &outpkt, &broadcast);
	log_debug(peer->log, "%s => %s",
		  input_name(input), state_name(peer->state));
	switch (status) {
	case CMD_NONE:
		break;
	case CMD_SUCCESS:
		log_add(peer->log, " (command success)");
		peer_cmd_complete(peer, CMD_SUCCESS);
		break;
	case CMD_FAIL:
		log_add(peer->log, " (command FAIL)");
		peer_cmd_complete(peer, CMD_FAIL);
		break;
	case CMD_REQUEUE:
		log_add(peer->log, " (Command requeue)");
		break;
	}

	if (outpkt) {
		log_add(peer->log, " (out %s)", input_name(outpkt->pkt_case));
		queue_output_pkt(peer, outpkt);
	}
	if (broadcast) {
		struct sha256_double txid;

		bitcoin_txid(broadcast, &txid);
		/* FIXME: log_struct */
		log_add(peer->log, " (tx %02x%02x%02x%02x...)",
			txid.sha.u.u8[0], txid.sha.u.u8[1],
			txid.sha.u.u8[2], txid.sha.u.u8[3]);
		bitcoind_send_tx(peer->dstate, broadcast);
	}

	/* Start output if not running already; it will close conn. */
	if (peer->cond == PEER_CLOSED)
		io_wake(peer);

	/* FIXME: Some of these should just result in this peer being killed? */
	if (state_is_error(peer->state)) {
		log_broken(peer->log, "Entered error state %s",
			   state_name(peer->state));
		fatal("Peer entered error state");
	}

	/* Break out and free this peer if it's completely done. */
	if (peer->state == STATE_CLOSED)
		io_break(peer);
}

static void try_command(struct peer *peer)
{
	/* If we can accept a command, and we have one queued, run it. */
	while (peer->cond == PEER_CMD_OK
	       && !list_empty(&peer->pending_cmd)) {
		struct pending_cmd *pend = list_pop(&peer->pending_cmd,
						    struct pending_cmd, list);

		assert(peer->curr_cmd.cmd == INPUT_NONE);

		/* This can fail to enqueue a command! */
		pend->dequeue(peer, pend->arg);
		tal_free(pend);

		if (peer->curr_cmd.cmd != INPUT_NONE) {
			state_single(peer, peer->curr_cmd.cmd,
				     &peer->curr_cmd.cmddata);
		}
	}
}

#define queue_cmd(peer, cb, arg)					\
	queue_cmd_((peer),						\
		   typesafe_cb_preargs(void, void *,			\
				       (cb), (arg),			\
				       struct peer *),			\
		   (arg))

static void queue_cmd_(struct peer *peer,
		       void (*dequeue)(struct peer *peer, void *arg),
		       void *arg)
{
	struct pending_cmd *pend = tal(peer, struct pending_cmd);

	pend->dequeue = dequeue;
	pend->arg = arg;

	list_add_tail(&peer->pending_cmd, &pend->list);
	try_command(peer);
};

static void state_event(struct peer *peer, 
			const enum state_input input,
			const union input *idata)
{
	state_single(peer, input, idata);
	try_command(peer);
}

static struct io_plan *pkt_out(struct io_conn *conn, struct peer *peer)
{
	Pkt *out;
	size_t n = tal_count(peer->outpkt);

	if (n == 0) {
		/* We close the connection once we've sent everything. */
		if (peer->cond == PEER_CLOSED)
			return io_close(conn);
		return io_out_wait(conn, peer, pkt_out, peer);
	}

	out = peer->outpkt[0];
	memmove(peer->outpkt, peer->outpkt + 1, (sizeof(*peer->outpkt)*(n-1)));
	tal_resize(&peer->outpkt, n-1);
	return peer_write_packet(conn, peer, out, pkt_out);
}

static struct io_plan *pkt_in(struct io_conn *conn, struct peer *peer)
{
	union input idata;
	const tal_t *ctx = tal(peer, char);

	idata.pkt = tal_steal(ctx, peer->inpkt);

	/* We ignore packets if they tell us to. */
	if (peer->cond != PEER_CLOSED)
		state_event(peer, peer->inpkt->pkt_case, &idata);

	/* Free peer->inpkt unless stolen above. */
	tal_free(ctx);

	return peer_read_packet(conn, peer, pkt_in);
}

static void do_anchor_offer(struct peer *peer, void *unused)
{
	set_current_command(peer, peer->us.offer_anchor, NULL, NULL);
}

/* Crypto is on, we are live. */
static struct io_plan *peer_crypto_on(struct io_conn *conn, struct peer *peer)
{
	peer_secrets_init(peer);
	peer_get_revocation_hash(peer, 0, &peer->us.revocation_hash);
	peer_get_revocation_hash(peer, 1, &peer->us.next_revocation_hash);

	assert(peer->state == STATE_INIT);

	/* Using queue_cmd is overkill here, but it works. */
	queue_cmd(peer, do_anchor_offer, NULL);
	try_command(peer);

	return io_duplex(conn,
			 peer_read_packet(conn, peer, pkt_in),
			 pkt_out(conn, peer));
}

static void destroy_peer(struct peer *peer)
{
	if (peer->conn)
		io_close(peer->conn);
	list_del_from(&peer->dstate->peers, &peer->list);
}

static void peer_disconnect(struct io_conn *conn, struct peer *peer)
{
	Pkt *outpkt;
	const struct bitcoin_tx *broadcast;

	log_info(peer->log, "Disconnected");

	/* No longer connected. */
	peer->conn = NULL;

	/* Not even set up yet?  Simply free.*/
	if (peer->state == STATE_INIT) {
		tal_free(peer);
		return;
	}

	/* FIXME: Try to reconnect. */
	if (peer->cond == PEER_CLOSING
	    || peer->cond == PEER_CLOSED)
		return;

	state(peer, peer, CMD_CLOSE, NULL, &outpkt, &broadcast);
	/* Can't send packet, so ignore it. */
	tal_free(outpkt);

	if (broadcast) {
		struct sha256_double txid;

		bitcoin_txid(broadcast, &txid);
		/* FIXME: log_struct */
		log_debug(peer->log, "CMD_CLOSE: tx %02x%02x%02x%02x...",
			  txid.sha.u.u8[0], txid.sha.u.u8[1],
			  txid.sha.u.u8[2], txid.sha.u.u8[3]);
		bitcoind_send_tx(peer->dstate, broadcast);
	}
}

static struct peer *new_peer(struct lightningd_state *dstate,
			     struct io_conn *conn,
			     int addr_type, int addr_protocol,
			     enum state_input offer_anchor,
			     const char *in_or_out)
{
	struct peer *peer = tal(dstate, struct peer);

	assert(offer_anchor == CMD_OPEN_WITH_ANCHOR
	       || offer_anchor == CMD_OPEN_WITHOUT_ANCHOR);

	/* FIXME: Stop listening if too many peers? */
	list_add(&dstate->peers, &peer->list);

	peer->state = STATE_INIT;
	peer->cond = PEER_CMD_OK;
	peer->dstate = dstate;
	peer->addr.type = addr_type;
	peer->addr.protocol = addr_protocol;
	peer->io_data = NULL;
	peer->secrets = NULL;
	list_head_init(&peer->watches);
	peer->outpkt = tal_arr(peer, Pkt *, 0);
	peer->curr_cmd.cmd = INPUT_NONE;
	list_head_init(&peer->pending_cmd);
	peer->current_htlc = NULL;
	peer->commit_tx_counter = 0;
	peer->close_tx = NULL;
	peer->cstate = NULL;
	peer->close_watch_timeout = NULL;
	peer->anchor.watches = NULL;
	peer->cur_commit.watch = NULL;

	/* If we free peer, conn should be closed, but can't be freed
	 * immediately so don't make peer a parent. */
	peer->conn = conn;
	io_set_finish(conn, peer_disconnect, peer);
	
	peer->us.offer_anchor = offer_anchor;
	if (!seconds_to_rel_locktime(dstate->config.rel_locktime,
				     &peer->us.locktime))
		fatal("Invalid locktime configuration %u",
		      dstate->config.rel_locktime);
	peer->us.mindepth = dstate->config.anchor_confirms;
	/* FIXME: Make this dynamic. */
	peer->us.commit_fee = dstate->config.commitment_fee;

	peer->us.commit = peer->them.commit = NULL;
	
	/* FIXME: Attach IO logging for this peer. */
	tal_add_destructor(peer, destroy_peer);

	peer->addr.addrlen = sizeof(peer->addr.saddr);
	if (getpeername(io_conn_fd(conn), &peer->addr.saddr.s,
			&peer->addr.addrlen) != 0) {
		log_unusual(dstate->base_log,
			    "Could not get address for peer: %s",
			    strerror(errno));
		return tal_free(peer);
	}

	peer->log = new_log(peer, dstate->log_record, "%s%s:%s:",
			    log_prefix(dstate->base_log), in_or_out,
			    netaddr_name(peer, &peer->addr));
	return peer;
}

static struct io_plan *peer_connected_out(struct io_conn *conn,
					  struct lightningd_state *dstate,
					  struct json_connecting *connect)
{
	/* Initiator currently funds channel */
	struct peer *peer = new_peer(dstate, conn, SOCK_STREAM, IPPROTO_TCP,
				     CMD_OPEN_WITH_ANCHOR, "out");
	if (!peer) {
		command_fail(connect->cmd, "Failed to make peer for %s:%s",
			     connect->name, connect->port);
		return io_close(conn);
	}
	log_info(peer->log, "Connected out to %s:%s",
		 connect->name, connect->port);
	peer->anchor.satoshis = connect->satoshis;

	command_success(connect->cmd, null_response(connect));
	return peer_crypto_setup(conn, peer, peer_crypto_on);
}

static struct io_plan *peer_connected_in(struct io_conn *conn,
					 struct lightningd_state *dstate)
{
	struct peer *peer = new_peer(dstate, conn, SOCK_STREAM, IPPROTO_TCP,
				     CMD_OPEN_WITHOUT_ANCHOR, "in");
	if (!peer)
		return io_close(conn);

	log_info(peer->log, "Peer connected in");
	return peer_crypto_setup(conn, peer, peer_crypto_on);
}

static int make_listen_fd(struct lightningd_state *dstate,
			  int domain, void *addr, socklen_t len)
{
	int fd = socket(domain, SOCK_STREAM, 0);
	if (fd < 0) {
		log_debug(dstate->base_log, "Failed to create %u socket: %s",
			  domain, strerror(errno));
		return -1;
	}

	if (!addr || bind(fd, addr, len) == 0) {
		if (listen(fd, 5) == 0)
			return fd;
		log_unusual(dstate->base_log,
			    "Failed to listen on %u socket: %s",
			    domain, strerror(errno));
	} else
		log_debug(dstate->base_log, "Failed to bind on %u socket: %s",
			  domain, strerror(errno));

	close_noerr(fd);
	return -1;
}

void setup_listeners(struct lightningd_state *dstate, unsigned int portnum)
{
	struct sockaddr_in addr;
	struct sockaddr_in6 addr6;
	socklen_t len;
	int fd1, fd2;
	u16 listen_port;

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(portnum);

	addr6.sin6_family = AF_INET6;
	addr6.sin6_addr = in6addr_any;
	addr6.sin6_port = htons(portnum);

	/* IPv6, since on Linux that (usually) binds to IPv4 too. */
	fd1 = make_listen_fd(dstate, AF_INET6, portnum ? &addr6 : NULL,
			     sizeof(addr6));
	if (fd1 >= 0) {
		struct sockaddr_in6 in6;

		len = sizeof(in6);
		if (getsockname(fd1, (void *)&in6, &len) != 0) {
			log_unusual(dstate->base_log,
				    "Failed get IPv6 sockname: %s",
				    strerror(errno));
			close_noerr(fd1);
		} else {
			addr.sin_port = in6.sin6_port;
			listen_port = ntohs(addr.sin_port);
			log_info(dstate->base_log,
				 "Creating IPv6 listener on port %u",
				 listen_port);
			io_new_listener(dstate, fd1, peer_connected_in, dstate);
		}
	}

	/* Just in case, aim for the same port... */
	fd2 = make_listen_fd(dstate, AF_INET,
			     addr.sin_port ? &addr : NULL, sizeof(addr));
	if (fd2 >= 0) {
		len = sizeof(addr);
		if (getsockname(fd2, (void *)&addr, &len) != 0) {
			log_unusual(dstate->base_log,
				    "Failed get IPv4 sockname: %s",
				    strerror(errno));
			close_noerr(fd2);
		} else {
			listen_port = ntohs(addr.sin_port);
			log_info(dstate->base_log,
				 "Creating IPv4 listener on port %u",
				 listen_port);
			io_new_listener(dstate, fd2, peer_connected_in, dstate);
		}
	}

	if (fd1 < 0 && fd2 < 0)
		fatal("Could not bind to a network address");
}

static void peer_failed(struct lightningd_state *dstate,
			struct json_connecting *connect)
{
	/* FIXME: Better diagnostics! */
	command_fail(connect->cmd, "Failed to connect to peer %s:%s",
		     connect->name, connect->port);
}

static void json_connect(struct command *cmd,
			const char *buffer, const jsmntok_t *params)
{
	struct json_connecting *connect;
	jsmntok_t *host, *port, *satoshis;

	if (!json_get_params(buffer, params,
			     "host", &host,
			     "port", &port,
			     "satoshis", &satoshis,
			     NULL)) {
		command_fail(cmd, "Need host, port and satoshis");
		return;
	}

	connect = tal(cmd, struct json_connecting);
	connect->cmd = cmd;
	connect->name = tal_strndup(connect, buffer + host->start,
				    host->end - host->start);
	connect->port = tal_strndup(connect, buffer + port->start,
				    port->end - port->start);
	if (!json_tok_u64(buffer, satoshis, &connect->satoshis))
		command_fail(cmd, "'%.*s' is not a valid number",
			     (int)(satoshis->end - satoshis->start),
			     buffer + satoshis->start);
	if (!dns_resolve_and_connect(cmd->dstate, connect->name, connect->port,
				     peer_connected_out, peer_failed, connect)) {
		command_fail(cmd, "DNS failed");
		return;
	}
}

const struct json_command connect_command = {
	"connect",
	json_connect,
	"Connect to a {host} at {port} offering anchor of {satoshis}",
	"Returns an empty result on success"
};

struct anchor_watch {
	struct peer *peer;
	enum state_input depthok;
	enum state_input timeout;
	enum state_input unspent;
	enum state_input theyspent;
	enum state_input otherspent;

	/* If timeout != INPUT_NONE, this is the timer. */
	struct oneshot *timer;
};

static void anchor_depthchange(struct peer *peer, int depth,
			       const struct sha256_double *blkhash,
			       struct anchor_watch *w)
{
	/* Still waiting for it to reach depth? */
	if (w->depthok != INPUT_NONE) {
		/* Beware sign! */
		if (depth >= (int)peer->us.mindepth) {
			enum state_input in = w->depthok;
			w->depthok = INPUT_NONE;
			/* We don't need the timeout timer any more. */
			w->timer = tal_free(w->timer);
			state_event(peer, in, NULL);
		}
	} else {
		if (depth < 0 && w->unspent != INPUT_NONE) {
			enum state_input in = w->unspent;
			w->unspent = INPUT_NONE;
			state_event(peer, in, NULL);
		}
	}
}

/* We don't compare scriptSigs: we don't know them anyway! */
static bool txmatch(const struct bitcoin_tx *txa, const struct bitcoin_tx *txb)
{
	size_t i;

	if (txa->version != txb->version
	    || txa->input_count != txb->input_count
	    || txa->output_count != txb->output_count
	    || txa->lock_time != txb->lock_time)
		return false;

	for (i = 0; i < txa->input_count; i++) {
		if (!structeq(&txa->input[i].txid, &txb->input[i].txid)
		    || txa->input[i].index != txb->input[i].index
		    || txa->input[i].sequence_number != txb->input[i].sequence_number)
			return false;
	}

	for (i = 0; i < txa->output_count; i++) {
		if (txa->output[i].amount != txb->output[i].amount
		    || txa->output[i].script_length != txb->output[i].script_length
		    || memcmp(txa->output[i].script, txb->output[i].script,
			      txa->output[i].script_length != 0))
			return false;
	}

	return true;
}

static bool is_mutual_close(const struct bitcoin_tx *tx,
			    const struct bitcoin_tx *close_tx)
{
	varint_t i;

	/* Haven't created mutual close yet?  This isn't one then. */
	if (!close_tx)
		return false;

	/* We know it spends anchor, but do txouts match? */
	if (tx->output_count != close_tx->output_count)
		return false;
	for (i = 0; i < tx->output_count; i++) {
		if (tx->output[i].amount != close_tx->output[i].amount)
			return false;
		if (tx->output[i].script_length
		    != close_tx->output[i].script_length)
			return false;
		if (memcmp(tx->output[i].script, close_tx->output[i].script,
			   tx->output[i].script_length) != 0)
			return false;
	}
	return true;
}

static void close_depth_cb(struct peer *peer, int depth)
{
	if (depth >= peer->dstate->config.forever_confirms) {
		state_event(peer, BITCOIN_CLOSE_DONE, NULL);
	}
}

/* We assume the tx is valid!  Don't do a blockchain.info and feed this
 * invalid transactions! */
static void anchor_spent(struct peer *peer,
			 const struct bitcoin_tx *tx,
			 struct anchor_watch *w)
{
	union input idata;

	/* FIXME: change type in idata? */
	idata.btc = (struct bitcoin_event *)tx;
	if (txmatch(tx, peer->them.commit))
		state_event(peer, w->theyspent, &idata);
	else if (is_mutual_close(tx, peer->close_tx))
		add_close_tx_watch(peer, peer, tx, close_depth_cb);
	else
		state_event(peer, w->otherspent, &idata);
}

static void anchor_timeout(struct anchor_watch *w)
{
	assert(w == w->peer->anchor.watches);
	state_event(w->peer, w->timeout, NULL);

	/* Freeing this gets rid of the other watches, and timer, too. */
	w->peer->anchor.watches = tal_free(w);
}

void peer_watch_anchor(struct peer *peer,
		       enum state_input depthok,
		       enum state_input timeout,
		       enum state_input unspent,
		       enum state_input theyspent,
		       enum state_input otherspent)
{
	struct anchor_watch *w;

	w = peer->anchor.watches = tal(peer, struct anchor_watch);

	w->peer = peer;
	w->depthok = depthok;
	w->timeout = timeout;
	w->unspent = unspent;
	w->theyspent = theyspent;
	w->otherspent = otherspent;

	add_anchor_watch(w, peer, &peer->anchor.txid, peer->anchor.index,
			 anchor_depthchange,
			 anchor_spent,
			 w);

	/* For anchor timeout, expect 20 minutes per block, +2 hours.
	 *
	 * Probability(no block in time N) = e^(-N/600).
	 * Thus for 1 block, P = e^(-(7200+1*1200)/600) = 0.83 in a million.
	 *
	 * Glenn Willen says, if we want to know how many 10-minute intervals for
	 * a 1 in a million chance of spurious failure for N blocks, put
	 * this into http://www.wolframalpha.com:
	 *
	 *   e^(-x) * sum x^i / fact(i), i=0 to N < 1/1000000
	 * 
	 * N=20: 51
	 * N=10: 35
	 * N=8:  31
	 * N=6:  28
	 * N=4:  24
	 * N=3:  22
	 * N=2:  20
	 *
	 * So, our formula of 12 + N*2 holds for N <= 20 at least.
	 */
	if (w->timeout != INPUT_NONE) {
		w->timer = oneshot_timeout(peer->dstate, w,
					   7200 + 20*peer->us.mindepth,
					   anchor_timeout, w);
	} else
		w->timer = NULL;
}

void peer_unwatch_anchor_depth(struct peer *peer,
			       enum state_input depthok,
			       enum state_input timeout)
{
	assert(peer->anchor.watches);
	peer->anchor.watches = tal_free(peer->anchor.watches);
}

static void commit_tx_depth(struct peer *peer, int depth,
			    const struct sha256_double *blkhash,
			    ptrint_t *canspend)
{
	log_debug(peer->log, "Commit tx reached depth %i", depth);
	/* FIXME: Handle locktime in blocks, as well as seconds! */

	/* Fell out of a block? */
	if (depth < 0) {
		/* Forget any old block. */
		peer->cur_commit.start_time = 0;
		memset(&peer->cur_commit.blockid, 0xFF,
		       sizeof(peer->cur_commit.blockid));
		return;
	}

	/* In a new block? */
	if (!structeq(blkhash, &peer->cur_commit.blockid)) {
		peer->cur_commit.start_time = 0;
		peer->cur_commit.blockid = *blkhash;
		bitcoind_get_mediantime(peer->dstate, blkhash,
					&peer->cur_commit.start_time);
		return;
	}

	/* Don't yet know the median start time? */
	if (!peer->cur_commit.start_time)
		return;

	/* FIXME: We should really use bitcoin time here. */
	if (controlled_time().ts.tv_sec > peer->cur_commit.start_time
	    + rel_locktime_to_seconds(&peer->them.locktime)) {
		/* Free this watch; we're done */
		peer->cur_commit.watch = tal_free(peer->cur_commit.watch);
		state_event(peer, ptr2int(canspend), NULL);
	}
}

/* FIXME: We tell bitcoind to watch all the outputs, which is overkill */
static void watch_tx_outputs(struct peer *peer, const struct bitcoin_tx *tx)
{
	varint_t i;

	for (i = 0; i < tx->output_count; i++) {
		struct ripemd160 redeemhash;
		if (!is_p2sh(tx->output[i].script, tx->output[i].script_length))
			fatal("Unexpected non-p2sh output");
		memcpy(&redeemhash, tx->output[i].script+2, sizeof(redeemhash));
		bitcoind_watch_addr(peer->dstate, &redeemhash);
	}
}

/* Watch the commit tx until our side is spendable. */
void peer_watch_delayed(struct peer *peer,
			const struct bitcoin_tx *tx,
			enum state_input canspend)
{
	struct sha256_double txid;

	assert(tx == peer->us.commit);
	bitcoin_txid(tx, &txid);
	memset(&peer->cur_commit.blockid, 0xFF,
	       sizeof(peer->cur_commit.blockid));
	peer->cur_commit.watch
		= add_commit_tx_watch(tx, peer, &txid, commit_tx_depth,
				      int2ptr(canspend));

	watch_tx_outputs(peer, tx);
}

static void spend_tx_done(struct peer *peer, int depth,
			  const struct sha256_double *blkhash,
			  ptrint_t *done)
{
	log_debug(peer->log, "tx reached depth %i", depth);
	if (depth >= (int)peer->dstate->config.forever_confirms)
		state_event(peer, ptr2int(done), NULL);
}

/* Watch this tx until it's buried enough to be forgotten. */
void peer_watch_tx(struct peer *peer,
		   const struct bitcoin_tx *tx,
		   enum state_input done)
{
	struct sha256_double txid;

	bitcoin_txid(tx, &txid);
	log_debug(peer->log, "Watching tx %02x%02x%02x%02x...",
		  txid.sha.u.u8[0],
		  txid.sha.u.u8[1],
		  txid.sha.u.u8[2],
		  txid.sha.u.u8[3]);

	add_commit_tx_watch(tx, peer, &txid, spend_tx_done, int2ptr(done));
}

bool peer_create_close_tx(struct peer *peer, u64 fee_satoshis)
{
	struct channel_state cstate;

	assert(!peer->close_tx);
	
	/* We don't need a deep copy here, just fee levels. */
	cstate = *peer->cstate;
	if (!adjust_fee(peer->anchor.satoshis, fee_satoshis,
			&cstate.a, &cstate.b))
		return false;

	log_debug(peer->log,
		  "creating close-tx: to %02x%02x%02x%02x/%02x%02x%02x%02x, amounts %u/%u",
		  peer->us.finalkey.der[0], peer->us.finalkey.der[1],
		  peer->us.finalkey.der[2], peer->us.finalkey.der[3],
		  peer->them.finalkey.der[0], peer->them.finalkey.der[1],
		  peer->them.finalkey.der[2], peer->them.finalkey.der[3],
		  cstate.a.pay_msat / 1000,
		  cstate.b.pay_msat / 1000);

 	peer->close_tx = create_close_tx(peer->dstate->secpctx, peer,
 					 &peer->us.finalkey,
 					 &peer->them.finalkey,
					 &peer->anchor.txid,
					 peer->anchor.index,
 					 peer->anchor.satoshis,
 					 cstate.a.pay_msat / 1000,
 					 cstate.b.pay_msat / 1000);

	peer->our_close_sig.stype = SIGHASH_ALL;
	peer_sign_mutual_close(peer, peer->close_tx, &peer->our_close_sig.sig);
	return true;
}

static void send_close_timeout(struct peer *peer)
{
	/* FIXME: Remove any close_tx watches! */
	state_event(peer, INPUT_CLOSE_COMPLETE_TIMEOUT, NULL);
}

void peer_watch_close(struct peer *peer,
		      enum state_input done, enum state_input timedout)
{
	/* We save some work by assuming these. */
	assert(done == BITCOIN_CLOSE_DONE);

	/* FIXME: Dynamic closing fee! */
	if (!peer->close_tx)
		peer_create_close_tx(peer, peer->dstate->config.closing_fee);

	/* FIXME: We can't send CLOSE, so timeout immediately */
	if (!peer->conn) {
		assert(timedout == INPUT_CLOSE_COMPLETE_TIMEOUT);
		oneshot_timeout(peer->dstate, peer, 0,
				send_close_timeout, peer);
		return;
	}

	/* Give them a reasonable time to respond. */
	/* FIXME: config? */
	if (timedout != INPUT_NONE) {
		assert(timedout == INPUT_CLOSE_COMPLETE_TIMEOUT);
		peer->close_watch_timeout
			= oneshot_timeout(peer->dstate, peer, 120,
					  send_close_timeout, peer);
	}

	/* anchor_spent will get called, we match against close_tx there. */
}
void peer_unwatch_close_timeout(struct peer *peer, enum state_input timedout)
{
	assert(peer->close_watch_timeout);
	peer->close_watch_timeout = tal_free(peer->close_watch_timeout);
}
bool peer_watch_our_htlc_outputs(struct peer *peer,
				 const struct bitcoin_tx *tx,
				 enum state_input tous_timeout,
				 enum state_input tothem_spent,
				 enum state_input tothem_timeout)
{
	FIXME_STUB(peer);
}
bool peer_watch_their_htlc_outputs(struct peer *peer,
				   const struct bitcoin_event *tx,
				   enum state_input tous_timeout,
				   enum state_input tothem_spent,
				   enum state_input tothem_timeout)
{
	FIXME_STUB(peer);
}
void peer_unwatch_htlc_output(struct peer *peer,
			      const struct htlc *htlc,
			      enum state_input all_done)
{
	FIXME_STUB(peer);
}
void peer_unwatch_all_htlc_outputs(struct peer *peer)
{
	FIXME_STUB(peer);
}
void peer_watch_htlc_spend(struct peer *peer,
			   const struct bitcoin_tx *tx,
			   const struct htlc *htlc,
			   enum state_input done)
{
	/* FIXME! */
}
void peer_unwatch_htlc_spend(struct peer *peer,
			     const struct htlc *htlc,
			     enum state_input all_done)
{
	FIXME_STUB(peer);
}
void peer_unexpected_pkt(struct peer *peer, const Pkt *pkt)
{
	FIXME_STUB(peer);
}

/* Someone declined our HTLC: details in pkt (we will also get CMD_FAIL) */
void peer_htlc_declined(struct peer *peer, const Pkt *pkt)
{
	log_unusual(peer->log, "Peer declined htlc, reason %i",
		    pkt->update_decline_htlc->reason_case);
	peer->current_htlc = tal_free(peer->current_htlc);
}

/* Called when their update overrides our update cmd. */
void peer_htlc_ours_deferred(struct peer *peer)
{
	FIXME_STUB(peer);
}

/* Successfully added/fulfilled/timedout/routefail an HTLC. */
void peer_htlc_done(struct peer *peer)
{
	peer->current_htlc = tal_free(peer->current_htlc);
}

/* Someone aborted an existing HTLC. */
void peer_htlc_aborted(struct peer *peer)
{
	FIXME_STUB(peer);
}

/* An on-chain transaction revealed an R value. */
const struct htlc *peer_tx_revealed_r_value(struct peer *peer,
					    const struct bitcoin_event *btc)
{
	FIXME_STUB(peer);
}

bool committed_to_htlcs(const struct peer *peer)
{
	return tal_count(peer->cstate->a.htlcs) != 0
		|| tal_count(peer->cstate->b.htlcs) != 0;
}

/* Create a bitcoin close tx. */
const struct bitcoin_tx *bitcoin_close(const tal_t *ctx, struct peer *peer)
{
	/* Must be signed! */
	assert(peer->close_tx->input[0].script_length != 0);
	return peer->close_tx;
}

/* Create a bitcoin spend tx (to spend our commit's outputs) */
const struct bitcoin_tx *bitcoin_spend_ours(const tal_t *ctx,
					    const struct peer *peer)
{
	u8 *redeemscript;
	const struct bitcoin_tx *commit = peer->us.commit;
	struct bitcoin_signature sig;
	struct bitcoin_tx *tx;
	unsigned int p2sh_out;

	/* The redeemscript for a commit tx is fairly complex. */
	redeemscript = bitcoin_redeem_secret_or_delay(ctx,
						      &peer->us.finalkey,
						      &peer->them.locktime,
						      &peer->them.finalkey,
						      &peer->us.revocation_hash);

	/* Now, create transaction to spend it. */
	tx = bitcoin_tx(ctx, 1, 1);
	bitcoin_txid(commit, &tx->input[0].txid);
	p2sh_out = find_p2sh_out(commit, redeemscript);
	tx->input[0].index = p2sh_out;
	tx->input[0].input_amount = commit->output[p2sh_out].amount;
	/* FIXME: Dynamic fee! */
	tx->fee = peer->dstate->config.closing_fee;

	tx->input[0].sequence_number = bitcoin_nsequence(&peer->them.locktime);

	/* FIXME: In this case, we shouldn't do anything (not worth
	 * collecting) */
	if (commit->output[p2sh_out].amount <= tx->fee)
		fatal("Amount of %"PRIu64" won't cover fee",
		      commit->output[p2sh_out].amount);

	tx->output[0].amount = commit->output[p2sh_out].amount - tx->fee;
	tx->output[0].script = scriptpubkey_p2sh(tx,
				 bitcoin_redeem_single(tx, &peer->us.finalkey));
	tx->output[0].script_length = tal_count(tx->output[0].script);

	/* Now get signature, to set up input script. */
	sig.stype = SIGHASH_ALL;
	peer_sign_spend(peer, tx, redeemscript, &sig.sig);
	tx->input[0].script = scriptsig_p2sh_secret(tx, NULL, 0, &sig,
						    redeemscript,
						    tal_count(redeemscript));
	tx->input[0].script_length = tal_count(tx->input[0].script);

	return tx;
}

/* Create a bitcoin spend tx (to spend their commit's outputs) */
const struct bitcoin_tx *bitcoin_spend_theirs(const tal_t *ctx,
					      const struct peer *peer,
					      const struct bitcoin_event *btc)
{
	FIXME_STUB(peer);
}

/* Create a bitcoin steal tx (to steal all their commit's outputs) */
const struct bitcoin_tx *bitcoin_steal(const tal_t *ctx,
				       const struct peer *peer,
				       struct bitcoin_event *btc)
{
	FIXME_STUB(peer);
}

/* Sign and return our commit tx */
const struct bitcoin_tx *bitcoin_commit(const tal_t *ctx, struct peer *peer)
{
	struct bitcoin_signature sig;

	/* Can't be signed already! */
	assert(peer->us.commit->input[0].script_length == 0);

	sig.stype = SIGHASH_ALL;
	peer_sign_ourcommit(peer, peer->us.commit, &sig.sig);

	peer->us.commit->input[0].script
		= scriptsig_p2sh_2of2(peer->us.commit,
				      &peer->cur_commit.theirsig,
				      &sig,
				      &peer->them.commitkey,
				      &peer->us.commitkey);
	peer->us.commit->input[0].script_length
		= tal_count(peer->us.commit->input[0].script);

	return peer->us.commit;
}

/* Create a HTLC refund collection */
const struct bitcoin_tx *bitcoin_htlc_timeout(const tal_t *ctx,
					      const struct peer *peer,
					      const struct htlc *htlc)
{
	FIXME_STUB(peer);
}

/* Create a HTLC collection */
const struct bitcoin_tx *bitcoin_htlc_spend(const tal_t *ctx,
					    const struct peer *peer,
					    const struct htlc *htlc)
{
	FIXME_STUB(peer);
}

static void created_anchor(struct lightningd_state *dstate,
			   const struct bitcoin_tx *tx,
			   struct peer *peer)
{
	size_t commitfee;

	bitcoin_txid(tx, &peer->anchor.txid);
	peer->anchor.index = find_p2sh_out(tx, peer->anchor.redeemscript);
	assert(peer->anchor.satoshis == tx->output[peer->anchor.index].amount);
	/* We'll need this later, when we're told to broadcast it. */
	peer->anchor.tx = tal_steal(peer, tx);

	commitfee = commit_fee(peer->them.commit_fee, peer->us.commit_fee);
	peer->cstate = initial_funding(peer,
				       peer->us.offer_anchor,
				       peer->anchor.satoshis,
				       commitfee);
	if (!peer->cstate)
		fatal("Insufficient anchor funds for commitfee");

	/* Now we can make initial (unsigned!) commit txs. */
	make_commit_txs(peer, peer,
			&peer->us.revocation_hash,
			&peer->them.revocation_hash,
			peer->cstate,
			&peer->us.commit,
			&peer->them.commit);

	state_event(peer, BITCOIN_ANCHOR_CREATED, NULL);
}

/* Start creation of the bitcoin anchor tx. */
void bitcoin_create_anchor(struct peer *peer, enum state_input done)
{
	struct sha256 h;
	struct ripemd160 redeemhash;
	char *p2shaddr;

	/* We must be offering anchor for us to try creating it */
	assert(peer->us.offer_anchor);

	sha256(&h, peer->anchor.redeemscript,
	       tal_count(peer->anchor.redeemscript));
	ripemd160(&redeemhash, h.u.u8, sizeof(h));

	p2shaddr = p2sh_to_base58(peer, peer->dstate->config.testnet,
				  &redeemhash);

	assert(done == BITCOIN_ANCHOR_CREATED);

	bitcoind_create_payment(peer->dstate, p2shaddr, peer->anchor.satoshis,
				created_anchor, peer);
}

/* We didn't end up broadcasting the anchor: release the utxos.
 * If done != INPUT_NONE, remove existing create_anchor too. */
void bitcoin_release_anchor(struct peer *peer, enum state_input done)
{
	
	/* FIXME: stop bitcoind command  */
	log_unusual(peer->log, "Anchor not spent, please -zapwallettxs");
}

/* Get the bitcoin anchor tx. */
const struct bitcoin_tx *bitcoin_anchor(const tal_t *ctx, struct peer *peer)
{
	return peer->anchor.tx;
}

void make_commit_txs(const tal_t *ctx,
		     const struct peer *peer,
		     const struct sha256 *our_revocation_hash,
		     const struct sha256 *their_revocation_hash,
		     const struct channel_state *cstate,
		     struct bitcoin_tx **ours, struct bitcoin_tx **theirs)
{
	struct channel_state their_cstate;

	*ours = create_commit_tx(ctx,
				 &peer->us.finalkey,
				 &peer->them.finalkey,
				 &peer->them.locktime,
				 &peer->anchor.txid,
				 peer->anchor.index,
				 peer->anchor.satoshis,
				 our_revocation_hash,
				 cstate);

	their_cstate = *cstate;
	invert_cstate(&their_cstate);
	*theirs = create_commit_tx(ctx,
				   &peer->them.finalkey,
				   &peer->us.finalkey,
				   &peer->us.locktime,
				   &peer->anchor.txid,
				   peer->anchor.index,
				   peer->anchor.satoshis,
				   their_revocation_hash,
				   &their_cstate);
}

static void json_add_abstime(struct json_result *response,
			     const char *id,
			     const struct abs_locktime *t)
{
	json_object_start(response, id);
	if (abs_locktime_is_seconds(t))
		json_add_num(response, "second", abs_locktime_to_seconds(t));
	else
		json_add_num(response, "block", abs_locktime_to_blocks(t));
	json_object_end(response);
}

static void json_add_cstate(struct json_result *response,
			    const char *id,
			    const struct channel_oneside *side)
{
	size_t i;

	json_object_start(response, id);
	json_add_num(response, "pay", side->pay_msat);
	json_add_num(response, "fee", side->fee_msat);
	json_array_start(response, "htlcs");
	for (i = 0; i < tal_count(side->htlcs); i++) {
		json_object_start(response, NULL);
		json_add_u64(response, "msatoshis", side->htlcs[i].msatoshis);
		json_add_abstime(response, "expiry", &side->htlcs[i].expiry);
		json_add_hex(response, "rhash",
			     &side->htlcs[i].rhash,
			     sizeof(side->htlcs[i].rhash));
		json_object_end(response);
	}
	json_array_end(response);
	json_object_end(response);
}

/* FIXME: Somehow we should show running DNS lookups! */
/* FIXME: Show status of peers! */
static void json_getpeers(struct command *cmd,
			  const char *buffer, const jsmntok_t *params)
{
	struct peer *p;
	struct json_result *response = new_json_result(cmd);	

	json_object_start(response, NULL);
	json_array_start(response, "peers");
	list_for_each(&cmd->dstate->peers, p, list) {
		json_object_start(response, NULL);
		json_add_string(response, "name", log_prefix(p->log));
		json_add_string(response, "state", state_name(p->state));
		json_add_string(response, "cmd", input_name(p->curr_cmd.cmd));

		/* This is only valid after crypto setup. */
		if (p->state != STATE_INIT)
			json_add_hex(response, "peerid",
				     p->id.der, pubkey_derlen(&p->id));

		if (p->cstate) {
			json_object_start(response, "channel");
			json_add_cstate(response, "us", &p->cstate->a);
			json_add_cstate(response, "them", &p->cstate->b);
			json_object_end(response);
		}
		json_object_end(response);
	}
	json_array_end(response);
	json_object_end(response);
	command_success(cmd, response);
}

const struct json_command getpeers_command = {
	"getpeers",
	json_getpeers,
	"List the current peers",
	"Returns a 'peers' array"
};

static void set_htlc_command(struct peer *peer,
			     struct channel_state *cstate,
			     struct command *jsoncmd,
			     enum state_input cmd,
			     const union htlc_staging *stage)
{
	assert(!peer->current_htlc);

	peer->current_htlc = tal(peer, struct htlc_progress);
	peer->current_htlc->cstate = tal_steal(peer->current_htlc, cstate);
	peer->current_htlc->stage = *stage;

	peer_get_revocation_hash(peer, peer->commit_tx_counter+1,
				 &peer->current_htlc->our_revocation_hash);

	/* FIXME: Do we need current_htlc as idata arg? */
	set_current_command(peer, cmd, peer->current_htlc, jsoncmd);
}
		
/* FIXME: Keep a timeout for each peer, in case they're unresponsive. */
	
static void check_htlc_expiry(struct peer *peer, void *unused)
{
	size_t i;
	union htlc_staging stage;

	stage.fail.fail = HTLC_FAIL;

	/* Check their htlcs for expiry. */
	for (i = 0; i < tal_count(peer->cstate->b.htlcs); i++) {
		struct channel_htlc *htlc = &peer->cstate->b.htlcs[i];
		struct channel_state *cstate;

		/* Not a seconds-based expiry? */
		if (!abs_locktime_is_seconds(&htlc->expiry))
			continue;

		/* Not well-expired? */
		if (controlled_time().ts.tv_sec - 30
		    < abs_locktime_to_seconds(&htlc->expiry))
			continue;

		cstate = copy_funding(peer, peer->cstate);

		/* This should never fail! */
		if (!funding_delta(peer->anchor.satoshis,
				   0,
				   -htlc->msatoshis,
				   &cstate->b, &cstate->a)) {
			fatal("Unexpected failure expirint HTLC of %"PRIu64
			      " milli-satoshis", htlc->msatoshis);
		}
		funding_remove_htlc(&cstate->b, i);
		stage.fail.index = i;
		set_htlc_command(peer, cstate, NULL, CMD_SEND_HTLC_FAIL,
				 &stage);
		return;
	}
}

static void htlc_expiry_timeout(struct peer *peer)
{
	log_debug(peer->log, "Expiry timedout!");
	queue_cmd(peer, check_htlc_expiry, NULL);
}

void peer_add_htlc_expiry(struct peer *peer,
			  const struct abs_locktime *expiry)
{
	time_t when;

	/* Add 30 seconds to be sure peers agree on timeout. */
	when = abs_locktime_to_seconds(expiry) - controlled_time().ts.tv_sec;
	when += 30;

	oneshot_timeout(peer->dstate, peer, when, htlc_expiry_timeout, peer);
}

struct newhtlc {
	struct channel_htlc htlc;
	struct command *jsoncmd;
};

/* We do final checks just before we start command, as things may have
 * changed. */
static void do_newhtlc(struct peer *peer, struct newhtlc *newhtlc)
{
	struct channel_state *cstate;
	union htlc_staging stage;

	stage.add.add = HTLC_ADD;
	stage.add.htlc = newhtlc->htlc;

	/* Can we even offer this much?  We check now, just before we
	 * execute. */
	cstate = copy_funding(newhtlc, peer->cstate);
	if (!funding_delta(peer->anchor.satoshis,
			   0, newhtlc->htlc.msatoshis,
			   &cstate->a, &cstate->b)) {
		command_fail(newhtlc->jsoncmd,
			     "Cannot afford %"PRIu64" milli-satoshis",
			     newhtlc->htlc.msatoshis);
		return;
	}

	/* FIXME: Never propose duplicate rvalues? */

	/* Add the htlc to our side of channel. */
	funding_add_htlc(&cstate->a, newhtlc->htlc.msatoshis,
			 &newhtlc->htlc.expiry, &newhtlc->htlc.rhash);
	peer_add_htlc_expiry(peer, &newhtlc->htlc.expiry);

	set_htlc_command(peer, cstate, newhtlc->jsoncmd,
			 CMD_SEND_HTLC_ADD, &stage);
}

static void json_newhtlc(struct command *cmd,
			 const char *buffer, const jsmntok_t *params)
{
	struct peer *peer;
	jsmntok_t *peeridtok, *msatoshistok, *expirytok, *rhashtok;
	unsigned int expiry;
	struct newhtlc *newhtlc;

	if (!json_get_params(buffer, params,
			     "peerid", &peeridtok,
			     "msatoshis", &msatoshistok,
			     "expiry", &expirytok,
			     "rhash", &rhashtok,
			     NULL)) {
		command_fail(cmd, "Need peerid, msatoshis, expiry and rhash");
		return;
	}

	peer = find_peer(cmd->dstate, buffer, peeridtok);
	if (!peer) {
		command_fail(cmd, "Could not find peer with that peerid");
		return;
	}

	/* Attach to cmd until it's complete. */
	newhtlc = tal(cmd, struct newhtlc);
	newhtlc->jsoncmd = cmd;

	if (!json_tok_u64(buffer, msatoshistok, &newhtlc->htlc.msatoshis)) {
		command_fail(cmd, "'%.*s' is not a valid number",
			     (int)(msatoshistok->end - msatoshistok->start),
			     buffer + msatoshistok->start);
		return;
	}
	if (!json_tok_number(buffer, expirytok, &expiry)) {
		command_fail(cmd, "'%.*s' is not a valid number",
			     (int)(expirytok->end - expirytok->start),
			     buffer + expirytok->start);
		return;
	}

	if (!seconds_to_abs_locktime(expiry, &newhtlc->htlc.expiry)) {
		command_fail(cmd, "'%.*s' is not a valid number",
			     (int)(expirytok->end - expirytok->start),
			     buffer + expirytok->start);
		return;
	}

	if (abs_locktime_to_seconds(&newhtlc->htlc.expiry) <
	    controlled_time().ts.tv_sec + peer->dstate->config.min_expiry) {
		command_fail(cmd, "HTLC expiry too soon!");
		return;
	}

	if (abs_locktime_to_seconds(&newhtlc->htlc.expiry) >
	    controlled_time().ts.tv_sec + peer->dstate->config.max_expiry) {
		command_fail(cmd, "HTLC expiry too far!");
		return;
	}

	if (!hex_decode(buffer + rhashtok->start,
			rhashtok->end - rhashtok->start,
			&newhtlc->htlc.rhash,
			sizeof(newhtlc->htlc.rhash))) {
		command_fail(cmd, "'%.*s' is not a valid sha256 hash",
			     (int)(rhashtok->end - rhashtok->start),
			     buffer + rhashtok->start);
		return;
	}

	queue_cmd(peer, do_newhtlc, newhtlc);
	try_command(peer);
}

const struct json_command newhtlc_command = {
	"newhtlc",
	json_newhtlc,
	"Offer {peerid} an HTLC worth {msatoshis} in {expiry} (in seconds since Jan 1 1970) with {rhash}",
	"Returns an empty result on success"
};

struct fulfillhtlc {
	struct command *jsoncmd;
	struct sha256 r;
};

static void do_fullfill(struct peer *peer,
			struct fulfillhtlc *fulfillhtlc)
{
	struct channel_state *cstate;
	struct sha256 rhash;
	size_t i;
	struct channel_htlc *htlc;
	union htlc_staging stage;

	stage.fulfill.fulfill = HTLC_FULFILL;
	stage.fulfill.r = fulfillhtlc->r;

	sha256(&rhash, &fulfillhtlc->r, sizeof(fulfillhtlc->r));

	i = funding_find_htlc(&peer->cstate->b, &rhash);
	if (i == tal_count(peer->cstate->b.htlcs)) {
		command_fail(fulfillhtlc->jsoncmd,
			     "preimage htlc not found");
		return;
	}
	stage.fulfill.index = i;
	/* Point at current one, since we remove from new cstate. */
	htlc = &peer->cstate->b.htlcs[i];

	cstate = copy_funding(fulfillhtlc, peer->cstate);
	/* This should never fail! */
	if (!funding_delta(peer->anchor.satoshis,
			   -htlc->msatoshis,
			   -htlc->msatoshis,
			   &cstate->b, &cstate->a)) {
		fatal("Unexpected failure fulfilling HTLC of %"PRIu64
		      " milli-satoshis", htlc->msatoshis);
		return;
	}
	funding_remove_htlc(&cstate->b, i);

	set_htlc_command(peer, cstate, fulfillhtlc->jsoncmd,
			 CMD_SEND_HTLC_FULFILL, &stage);
}

static void json_fulfillhtlc(struct command *cmd,
			     const char *buffer, const jsmntok_t *params)
{
	struct peer *peer;
	jsmntok_t *peeridtok, *rtok;
	struct fulfillhtlc *fulfillhtlc;

	if (!json_get_params(buffer, params,
			     "peerid", &peeridtok,
			     "r", &rtok,
			     NULL)) {
		command_fail(cmd, "Need peerid and r");
		return;
	}

	peer = find_peer(cmd->dstate, buffer, peeridtok);
	if (!peer) {
		command_fail(cmd, "Could not find peer with that peerid");
		return;
	}

	fulfillhtlc = tal(cmd, struct fulfillhtlc);
	fulfillhtlc->jsoncmd = cmd;

	if (!hex_decode(buffer + rtok->start,
			rtok->end - rtok->start,
			&fulfillhtlc->r, sizeof(fulfillhtlc->r))) {
		command_fail(cmd, "'%.*s' is not a valid sha256 preimage",
			     (int)(rtok->end - rtok->start),
			     buffer + rtok->start);
		return;
	}

	queue_cmd(peer, do_fullfill, fulfillhtlc);
	try_command(peer);
}
	
const struct json_command fulfillhtlc_command = {
	"fulfillhtlc",
	json_fulfillhtlc,
	"Redeem htlc proposed by {peerid} using {r}",
	"Returns an empty result on success"
};

struct failhtlc {
	struct command *jsoncmd;
	struct sha256 rhash;
};

static void do_failhtlc(struct peer *peer,
			struct failhtlc *failhtlc)
{
	struct channel_state *cstate;
	size_t i;
	struct channel_htlc *htlc;
	union htlc_staging stage;

	stage.fail.fail = HTLC_FAIL;

	i = funding_find_htlc(&peer->cstate->b, &failhtlc->rhash);
	if (i == tal_count(peer->cstate->b.htlcs)) {
		command_fail(failhtlc->jsoncmd, "htlc not found");
		return;
	}
	stage.fail.index = i;
	/* Point to current one, since we remove from new cstate. */
	htlc = &peer->cstate->b.htlcs[i];

	cstate = copy_funding(failhtlc, peer->cstate);

	/* This should never fail! */
	if (!funding_delta(peer->anchor.satoshis,
			   0,
			   -htlc->msatoshis,
			   &cstate->b, &cstate->a)) {
		fatal("Unexpected failure routefailing HTLC of %"PRIu64
		      " milli-satoshis", htlc->msatoshis);
		return;
	}
	funding_remove_htlc(&cstate->b, i);

	set_htlc_command(peer, cstate, failhtlc->jsoncmd,
			 CMD_SEND_HTLC_FAIL, &stage);
}

static void json_failhtlc(struct command *cmd,
			  const char *buffer, const jsmntok_t *params)
{
	struct peer *peer;
	jsmntok_t *peeridtok, *rhashtok;
	struct failhtlc *failhtlc;

	if (!json_get_params(buffer, params,
			     "peerid", &peeridtok,
			     "rhash", &rhashtok,
			     NULL)) {
		command_fail(cmd, "Need peerid and rhash");
		return;
	}

	peer = find_peer(cmd->dstate, buffer, peeridtok);
	if (!peer) {
		command_fail(cmd, "Could not find peer with that peerid");
		return;
	}

	failhtlc = tal(cmd, struct failhtlc);
	failhtlc->jsoncmd = cmd;

	if (!hex_decode(buffer + rhashtok->start,
			rhashtok->end - rhashtok->start,
			&failhtlc->rhash, sizeof(failhtlc->rhash))) {
		command_fail(cmd, "'%.*s' is not a valid sha256 preimage",
			     (int)(rhashtok->end - rhashtok->start),
			     buffer + rhashtok->start);
		return;
	}

	queue_cmd(peer, do_failhtlc, failhtlc);
	try_command(peer);
}
	
const struct json_command failhtlc_command = {
	"failhtlc",
	json_failhtlc,
	"Fail htlc proposed by {peerid} which has redeem hash {rhash}",
	"Returns an empty result on success"
};

static void json_close(struct command *cmd,
		       const char *buffer, const jsmntok_t *params)
{
	struct peer *peer;
	jsmntok_t *peeridtok;

	if (!json_get_params(buffer, params,
			     "peerid", &peeridtok,
			     NULL)) {
		command_fail(cmd, "Need peerid");
		return;
	}

	peer = find_peer(cmd->dstate, buffer, peeridtok);
	if (!peer) {
		command_fail(cmd, "Could not find peer with that peerid");
		return;
	}
	if (peer->cond == PEER_CLOSING) {
		command_fail(cmd, "Peer is already closing");
		return;
	}

	/* Unlike other things, CMD_CLOSE is always valid. */
	log_debug(peer->log, "Sending CMD_CLOSE");
	state_event(peer, CMD_CLOSE, NULL);
	command_success(cmd, null_response(cmd));
}
	
const struct json_command close_command = {
	"close",
	json_close,
	"Close the channel with peer {peerid}",
	"Returns an empty result on success"
};
