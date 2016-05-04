#include "bitcoind.h"
#include "chaintopology.h"
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
#include "pseudorand.h"
#include "secrets.h"
#include "state.h"
#include "timeout.h"
#include "wallet.h"
#include <bitcoin/base58.h>
#include <bitcoin/script.h>
#include <bitcoin/tx.h>
#include <ccan/array_size/array_size.h>
#include <ccan/cast/cast.h>
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
	struct anchor_input *input;
};

struct pending_cmd {
	struct list_node list;
	void (*dequeue)(struct peer *, void *arg);
	void *arg;
};

struct pending_input {
	struct list_node list;
	enum state_input input;
	union input idata;
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
	const struct bitcoin_tx *broadcast;
	size_t old_outpkts = tal_count(peer->outpkt);
	
	status = state(peer, input, idata, &broadcast);
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

	if (tal_count(peer->outpkt) > old_outpkts) {
		Pkt *outpkt = peer->outpkt[old_outpkts].pkt;
		log_add(peer->log, " (out %s)", input_name(outpkt->pkt_case));
	}
	if (broadcast)
		broadcast_tx(peer, broadcast);

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
	if (peer->state == STATE_CLOSED && !peer->conn)
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

static void queue_input(struct peer *peer,
			enum state_input input,
			const union input *idata)
{
	struct pending_input *pend = tal(peer, struct pending_input);

	pend->input = input;
	if (idata)
		pend->idata = *idata;
	list_add_tail(&peer->pending_input, &pend->list);
}
	
/* All unrevoked commit txs must have no HTLCs in them. */
bool committed_to_htlcs(const struct peer *peer)
{
	const struct commit_info *i;

	/* Before anchor exchange, we don't even have cstate. */
	if (!peer->us.commit || !peer->us.commit->cstate)
		return false;
	
	i = peer->us.commit;
	while (i && !i->revocation_preimage) {
		if (tal_count(i->cstate->a.htlcs))
			return true;
		if (tal_count(i->cstate->b.htlcs))
			return true;
		i = i->prev;
	}

	i = peer->them.commit;
	while (i && !i->revocation_preimage) {
		if (tal_count(i->cstate->a.htlcs))
			return true;
		if (tal_count(i->cstate->b.htlcs))
			return true;
		i = i->prev;
	}

	return false;
}

static void state_event(struct peer *peer, 
			const enum state_input input,
			const union input *idata)
{
	struct pending_input *pend;

	state_single(peer, input, idata);

	pend = list_pop(&peer->pending_input, struct pending_input, list);
	if (pend) {
		state_event(peer, pend->input, &pend->idata);
		tal_free(pend);
	}

	try_command(peer);
}

void peer_check_if_cleared(struct peer *peer)
{
	if (peer->cleared == INPUT_NONE)
		return;

	if (committed_to_htlcs(peer))
		return;

	queue_input(peer, peer->cleared, NULL);
	peer->cleared = INPUT_NONE;
}

static struct io_plan *pkt_out(struct io_conn *conn, struct peer *peer)
{
	struct out_pkt out;
	size_t n = tal_count(peer->outpkt);

	if (n == 0) {
		/* We close the connection once we've sent everything. */
		if (!peer->fake_close && peer->cond == PEER_CLOSED)
			return io_close(conn);
		return io_out_wait(conn, peer, pkt_out, peer);
	}

	out = peer->outpkt[0];
	memmove(peer->outpkt, peer->outpkt + 1, (sizeof(*peer->outpkt)*(n-1)));
	tal_resize(&peer->outpkt, n-1);
	return peer_write_packet(conn, peer, out.pkt, out.ack_cb, out.ack_arg,
				 pkt_out);
}

static struct io_plan *pkt_in(struct io_conn *conn, struct peer *peer)
{
	union input idata;
	const tal_t *ctx = tal(peer, char);

	idata.pkt = tal_steal(ctx, peer->inpkt);

	/* We ignore packets if they tell us to. */
	if (!peer->fake_close && peer->cond != PEER_CLOSED) {
		/* These two packets contain acknowledgements. */
		if (idata.pkt->pkt_case == PKT__PKT_UPDATE_COMMIT)
			peer_process_acks(peer,
					  idata.pkt->update_commit->ack);
		else if (idata.pkt->pkt_case == PKT__PKT_UPDATE_REVOCATION)
			peer_process_acks(peer,
					  idata.pkt->update_revocation->ack);

		state_event(peer, peer->inpkt->pkt_case, &idata);
	}

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

	peer_get_revocation_hash(peer, 0, &peer->us.next_revocation_hash);

	assert(peer->state == STATE_INIT);

	/* Using queue_cmd is overkill here, but it works. */
	queue_cmd(peer, do_anchor_offer, NULL);

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
	log_info(peer->log, "Disconnected");

	/* No longer connected. */
	peer->conn = NULL;

	/* Not even set up yet?  Simply free.*/
	if (peer->state == STATE_INIT) {
		tal_free(peer);
		return;
	}

	/* Completely dead?  Free it now. */
	if (peer->state == STATE_CLOSED) {
		io_break(peer);
		return;
	}
	
	/* FIXME: Try to reconnect. */
	/* This is an expected close. */
	if (peer->cond == PEER_CLOSED)
		return;

	state_single(peer, INPUT_CONNECTION_LOST, NULL);
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
	peer->outpkt = tal_arr(peer, struct out_pkt, 0);
	peer->curr_cmd.cmd = INPUT_NONE;
	list_head_init(&peer->pending_cmd);
	list_head_init(&peer->pending_input);
	list_head_init(&peer->outgoing_txs);
	peer->commit_tx_counter = 0;
	peer->close_watch_timeout = NULL;
	peer->anchor.watches = NULL;
	peer->cur_commit.watch = NULL;
	peer->closing.their_sig = NULL;
	peer->closing.our_script = NULL;
	peer->closing.their_script = NULL;
	peer->cleared = INPUT_NONE;
	/* Make it different from other node (to catch bugs!), but a
	 * round number for simple eyeballing. */
	peer->htlc_id_counter = pseudorand(1ULL << 32) * 1000;

	/* If we free peer, conn should be closed, but can't be freed
	 * immediately so don't make peer a parent. */
	peer->conn = conn;
	peer->fake_close = false;
	io_set_finish(conn, peer_disconnect, peer);
	
	peer->us.offer_anchor = offer_anchor;
	if (!seconds_to_rel_locktime(dstate->config.rel_locktime,
				     &peer->us.locktime))
		fatal("Invalid locktime configuration %u",
		      dstate->config.rel_locktime);
	peer->us.mindepth = dstate->config.anchor_confirms;
	peer->us.commit_fee_rate = dstate->config.commitment_fee_rate;

	peer->us.commit = peer->them.commit = NULL;
	peer->us.staging_cstate = peer->them.staging_cstate = NULL;
		
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

	peer->anchor.input = tal_steal(peer, connect->input);

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
	jsmntok_t *host, *port, *txtok;
	struct bitcoin_tx *tx;
	int output;
	size_t txhexlen;

	if (!json_get_params(buffer, params,
			     "host", &host,
			     "port", &port,
			     "tx", &txtok,
			     NULL)) {
		command_fail(cmd, "Need host, port and tx to a wallet address");
		return;
	}

	connect = tal(cmd, struct json_connecting);
	connect->cmd = cmd;
	connect->name = tal_strndup(connect, buffer + host->start,
				    host->end - host->start);
	connect->port = tal_strndup(connect, buffer + port->start,
				    port->end - port->start);
	connect->input = tal(connect, struct anchor_input);

	txhexlen = txtok->end - txtok->start;
	tx = bitcoin_tx_from_hex(connect->input, buffer + txtok->start,
				 txhexlen);
	if (!tx) {
		command_fail(cmd, "'%.*s' is not a valid transaction",
			     txtok->end - txtok->start,
			     buffer + txtok->start);
		return;
	}

	bitcoin_txid(tx, &connect->input->txid);

	/* Find an output we know how to spend. */
	connect->input->w = NULL;
	for (output = 0; output < tx->output_count; output++) {
		connect->input->w
			= wallet_can_spend(cmd->dstate, &tx->output[output]);
		if (connect->input->w)
			break;
	}
	if (!connect->input->w) {
		command_fail(cmd, "Tx doesn't send to wallet address");
		return;
	}

	connect->input->index = output;
	connect->input->amount = tx->output[output].amount;
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

static void anchor_depthchange(struct peer *peer, unsigned int depth,
			       const struct sha256_double *txid,
			       void *unused)
{
	struct anchor_watch *w = peer->anchor.watches;
	/* Still waiting for it to reach depth? */
	if (w->depthok != INPUT_NONE) {
		if (depth >= peer->us.mindepth) {
			enum state_input in = w->depthok;
			w->depthok = INPUT_NONE;
			/* We don't need the timeout timer any more. */
			w->timer = tal_free(w->timer);
			state_event(peer, in, NULL);
		}
	} else {
		if (depth == 0 && w->unspent != INPUT_NONE) {
			enum state_input in = w->unspent;
			w->unspent = INPUT_NONE;
			state_event(peer, in, NULL);
		}
	}
}

/* Yay, segwit!  We can just compare txids, even though we don't have both
 * signatures. */
static bool txidmatch(const struct bitcoin_tx *tx,
		      const struct sha256_double *txid)
{
	struct sha256_double tx_txid;

	bitcoin_txid(tx, &tx_txid);
	return structeq(txid, &tx_txid);
}

static struct commit_info *find_commit(struct commit_info *ci,
				       const struct sha256_double *txid)
{
	while (ci) {
		if (txidmatch(ci->tx, txid))
			return ci;
		ci = ci->prev;
	}
	return NULL;
}

static bool is_mutual_close(const struct peer *peer,
			    const struct bitcoin_tx *tx)
{
	const u8 *ours, *theirs;

	ours = peer->closing.our_script;
	theirs = peer->closing.their_script;
	/* If we don't know the closing scripts, can't have signed them. */
	if (!ours || !theirs)
		return false;

	if (tx->output_count != 2)
		return false;

	/* Without knowing fee amounts, can't determine order.  Check both. */
	if (scripteq(tx->output[0].script, tx->output[0].script_length,
		     ours, tal_count(ours))
	    && scripteq(tx->output[1].script, tx->output[1].script_length,
			theirs, tal_count(theirs)))
		return true;

	if (scripteq(tx->output[0].script, tx->output[0].script_length,
		     theirs, tal_count(theirs))
	    && scripteq(tx->output[1].script, tx->output[1].script_length,
			ours, tal_count(ours)))
		return true;

	return false;
}

static void close_depth_cb(struct peer *peer, unsigned int depth,
			   const struct sha256_double *txid,
			   void *unused)
{
	if (depth >= peer->dstate->config.forever_confirms) {
		state_event(peer, BITCOIN_CLOSE_DONE, NULL);
	}
}

static struct channel_htlc *htlc_by_index(const struct commit_info *ci,
					  size_t index)
{
	if (ci->map[index] == -1)
		return NULL;

	/* First two are non-HTLC outputs to us, them. */
	assert(index >= 2);
	index -= 2;

	if (index < tal_count(ci->cstate->a.htlcs))
		return cast_const(struct channel_htlc *, ci->cstate->a.htlcs)
			+ index;
	index -= tal_count(ci->cstate->a.htlcs);
	assert(index < tal_count(ci->cstate->b.htlcs));
	return cast_const(struct channel_htlc *, ci->cstate->b.htlcs) + index;
}

static UNNEEDED bool htlc_a_offered(struct commit_info *ci, size_t index)
{
	assert(index >= 2);
	index -= 2;

	return index < tal_count(ci->cstate->a.htlcs);
}

/* Create a HTLC refund collection */
static UNNEEDED const struct bitcoin_tx *htlc_timeout_tx(const struct peer *peer,
						const struct commit_info *ci,
						unsigned int i)
{
	u8 *wscript;
	struct channel_htlc *htlc;
	struct bitcoin_tx *tx = bitcoin_tx(peer, 1, 1);
	struct bitcoin_signature sig;
	u64 fee, satoshis;

	htlc = htlc_by_index(ci, i);

	wscript = bitcoin_redeem_htlc_send(peer,
					   &peer->us.finalkey,
					   &peer->them.finalkey,
					   &htlc->expiry,
					   &peer->them.locktime,
					   &ci->revocation_hash,
					   &htlc->rhash);

	/* We must set locktime so HTLC expiry can OP_CHECKLOCKTIMEVERIFY */
	tx->lock_time = htlc->expiry.locktime;
	tx->input[0].index = 0;
	bitcoin_txid(ci->tx, &tx->input[0].txid);
	satoshis = htlc->msatoshis / 1000;
	tx->input[0].amount = tal_dup(tx->input, u64, &satoshis);
	tx->input[0].sequence_number = bitcoin_nsequence(&peer->them.locktime);

	/* Using a new output address here would be useless: they can tell
	 * it's our HTLC, and that we collected it via timeout. */
	tx->output[0].script = scriptpubkey_p2sh(tx,
				 bitcoin_redeem_single(tx, &peer->us.finalkey));
	tx->output[0].script_length = tal_count(tx->output[0].script);

	log_unusual(peer->log, "Pre-witness txlen = %zu\n",
		    measure_tx_cost(tx) / 4);

	assert(measure_tx_cost(tx) == 83 * 4);

	/* Witness length can vary, due to DER encoding of sigs, but we
	 * use 539 from an example run. */
	/* FIXME: Dynamic fees! */
	fee = fee_by_feerate(83 + 539 / 4,
			     peer->dstate->config.closing_fee_rate);

	/* FIXME: Fail gracefully in these cases (not worth collecting) */
	if (fee > satoshis || is_dust_amount(satoshis - fee))
		fatal("HTLC refund amount of %"PRIu64" won't cover fee %"PRIu64,
		      satoshis, fee);

	tx->output[0].amount = satoshis - fee;

	sig.stype = SIGHASH_ALL;
	peer_sign_htlc_refund(peer, tx, wscript, &sig.sig);

	tx->input[0].witness = bitcoin_witness_htlc(tx, NULL, &sig, wscript);

	log_unusual(peer->log, "tx cost for htlc timeout tx: %zu",
		    measure_tx_cost(tx));

	return tx;
}

/* We assume the tx is valid!  Don't do a blockchain.info and feed this
 * invalid transactions! */
static void anchor_spent(struct peer *peer,
			 const struct bitcoin_tx *tx,
			 size_t input_num,
			 void *unused)
{
	struct anchor_watch *w = peer->anchor.watches;
	union input idata;
	struct sha256_double txid;
	
	assert(input_num < tx->input_count);

	/* We only ever sign single-input txs. */
	if (input_num != 0)
		fatal("Anchor spend by non-single input tx");
	
	bitcoin_txid(tx, &txid);

	idata.ci = find_commit(peer->them.commit, &txid);
	if (idata.ci) {
		if (idata.ci->revocation_preimage)
			state_event(peer, w->otherspent, &idata);
		else {
			idata.tx = idata.ci->tx;
			state_event(peer, w->theyspent, &idata);
		}
	} else if (is_mutual_close(peer, tx)) {
		watch_tx(peer, peer, tx, close_depth_cb, NULL);
	} else {
		if (!txidmatch(peer->us.commit->tx, &txid))
			fatal("Unknown tx spend!");
	}
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

	watch_txid(w, peer, &peer->anchor.txid, anchor_depthchange, NULL);
	watch_txo(w, peer, &peer->anchor.txid, 0, anchor_spent, NULL);

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

static void commit_tx_depth(struct peer *peer, unsigned int depth,
			    const struct sha256_double *txid,
			    ptrint_t *canspend)
{
	u32 mediantime;

	log_debug(peer->log, "Commit tx reached depth %i", depth);
	/* FIXME: Handle locktime in blocks, as well as seconds! */

	/* Fell out of a block? */
	if (depth == 0)
		return;

	mediantime = get_tx_mediantime(peer->dstate, txid);
	assert(mediantime);

	if (get_tip_mediantime(peer->dstate) > mediantime
	    + rel_locktime_to_seconds(&peer->them.locktime)) {
		/* Free this watch; we're done */
		peer->cur_commit.watch = tal_free(peer->cur_commit.watch);
		state_event(peer, ptr2int(canspend), NULL);
	} else
		log_debug(peer->log, "... still CSV locked (mediantime %u, need %u + %u)",
			  get_tip_mediantime(peer->dstate),
			  mediantime,
			  rel_locktime_to_seconds(&peer->them.locktime));
}

/* We should map back from commit_tx permutation to figure out what happened. */
static void our_commit_spent(struct peer *peer,
			     const struct bitcoin_tx *commit_tx,
			     size_t input_num,
			     struct commit_info *info)
{
	/* FIXME: do something useful here, if HTLCs spent */
}

/* FIXME: We tell bitcoind to watch all the outputs, which is overkill */
static void watch_commit_outputs(struct peer *peer, const struct bitcoin_tx *tx)
{
	varint_t i;
	struct sha256_double txid;

	bitcoin_txid(tx, &txid);
	for (i = 0; i < tx->output_count; i++) {
		watch_txo(peer, peer, &txid, i, our_commit_spent,
			  peer->us.commit);
	}
}

/* Watch the commit tx until our side is spendable. */
void peer_watch_delayed(struct peer *peer,
			const struct bitcoin_tx *tx,
			enum state_input canspend)
{
	/* We only ever spend the last one. */
	assert(tx == peer->us.commit->tx);
	peer->cur_commit.watch = watch_tx(tx, peer, tx, commit_tx_depth,
					  int2ptr(canspend));

	watch_commit_outputs(peer, tx);
}

static void spend_tx_done(struct peer *peer, unsigned int depth,
			  const struct sha256_double *txid,
			  ptrint_t *done)
{
	log_debug(peer->log, "tx reached depth %u", depth);
	if (depth >= peer->dstate->config.forever_confirms)
		state_event(peer, ptr2int(done), NULL);
}

uint64_t commit_tx_fee(const struct bitcoin_tx *commit, uint64_t anchor_satoshis)
{
	uint64_t i, total = 0;

	for (i = 0; i < commit->output_count; i++)
		total += commit->output[i].amount;

	assert(anchor_satoshis >= total);
	return anchor_satoshis - total;
}

/* Watch this tx until it's buried enough to be forgotten. */
void peer_watch_tx(struct peer *peer,
		   const struct bitcoin_tx *tx,
		   enum state_input done)
{
	watch_tx(tx, peer, tx, spend_tx_done, int2ptr(done));
}

struct bitcoin_tx *peer_create_close_tx(struct peer *peer, u64 fee)
{
	struct channel_state cstate;

	/* We don't need a deep copy here, just fee levels. */
	cstate = *peer->us.staging_cstate;
	if (!force_fee(&cstate, fee)) {
		log_unusual(peer->log,
			    "peer_create_close_tx: can't afford fee %"PRIu64,
			    fee);
		return NULL;
	}

	log_debug(peer->log,
		  "creating close-tx with fee %"PRIu64": to %02x%02x%02x%02x/%02x%02x%02x%02x, amounts %u/%u",
		  fee,
		  peer->us.finalkey.der[0], peer->us.finalkey.der[1],
		  peer->us.finalkey.der[2], peer->us.finalkey.der[3],
		  peer->them.finalkey.der[0], peer->them.finalkey.der[1],
		  peer->them.finalkey.der[2], peer->them.finalkey.der[3],
		  cstate.a.pay_msat / 1000,
		  cstate.b.pay_msat / 1000);

 	return create_close_tx(peer->dstate->secpctx, peer,
			       peer->closing.our_script,
			       peer->closing.their_script,
			       &peer->anchor.txid,
			       peer->anchor.index,
			       peer->anchor.satoshis,
			       cstate.a.pay_msat / 1000,
			       cstate.b.pay_msat / 1000);
}

void peer_calculate_close_fee(struct peer *peer)
{
	/* Use actual worst-case length of close tx: based on BOLT#02's
	 * commitment tx numbers, but only 1 byte for output count */
	const uint64_t txsize = 41 + 221 + 10 + 32 + 32;
	uint64_t maxfee;

	/* FIXME: Dynamic fee */
	peer->closing.our_fee
		= fee_by_feerate(txsize, peer->dstate->config.closing_fee_rate);

	/* BOLT #2:
	 * The sender MUST set `close_fee` lower than or equal to the
	 * fee of the final commitment transaction, and MUST set
	 * `close_fee` to an even number of satoshis.
	 */
	maxfee = commit_tx_fee(peer->us.commit->tx, peer->anchor.satoshis);
	if (peer->closing.our_fee > maxfee) {
		/* This shouldn't happen: we never accept a commit fee
		 * less than the min_rate, which is greater than the
		 * closing_fee_rate.  Also, our txsize estimate for
		 * the closing tx is 2 bytes smaller than the commitment tx. */
		log_unusual(peer->log,
			    "Closing fee %"PRIu64" exceeded commit fee %"PRIu64", reducing.",
			    peer->closing.our_fee, maxfee);
		peer->closing.our_fee = maxfee;

		/* This can happen if actual commit txfee is odd. */
		if (peer->closing.our_fee & 1)
			peer->closing.our_fee--;
	}
	assert(!(peer->closing.our_fee & 1));
}

bool peer_has_close_sig(const struct peer *peer)
{
	return peer->closing.their_sig;
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
	if (committed_to_htlcs(peer))
		FIXME_STUB(peer);
	return false;
}
bool peer_watch_their_htlc_outputs(struct peer *peer,
				   const struct bitcoin_tx *tx,
				   enum state_input tous_timeout,
				   enum state_input tothem_spent,
				   enum state_input tothem_timeout)
{
	FIXME_STUB(peer);
}
void peer_unwatch_htlc_output(struct peer *peer,
			      const struct htlc_onchain *htlc_onchain,
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
			   const struct htlc_onchain *htlc_onchain,
			   enum state_input done)
{
	/* FIXME! */
}
void peer_unwatch_htlc_spend(struct peer *peer,
			     const struct htlc_onchain *htlc_onchain,
			     enum state_input all_done)
{
	FIXME_STUB(peer);
}
void peer_unexpected_pkt(struct peer *peer, const Pkt *pkt)
{
	FIXME_STUB(peer);
}

/* An on-chain transaction revealed an R value. */
void peer_tx_revealed_r_value(struct peer *peer, const struct htlc_onchain *htlc_onchain)
{
	FIXME_STUB(peer);
}

void peer_watch_htlcs_cleared(struct peer *peer,
			      enum state_input all_done)
{
	assert(peer->cleared == INPUT_NONE);
	assert(all_done != INPUT_NONE);
	peer->cleared = all_done;

	peer_check_if_cleared(peer);
}

/* Create a bitcoin close tx, using last signature they sent. */
const struct bitcoin_tx *bitcoin_close(struct peer *peer)
{
	struct bitcoin_tx *close_tx;
	struct bitcoin_signature our_close_sig;

	close_tx = peer_create_close_tx(peer, peer->closing.their_fee);

	our_close_sig.stype = SIGHASH_ALL;
	peer_sign_mutual_close(peer, close_tx, &our_close_sig.sig);

	close_tx->input[0].witness
		= bitcoin_witness_2of2(close_tx->input,
				       peer->closing.their_sig,
				       &our_close_sig,
				       &peer->them.commitkey,
				       &peer->us.commitkey);

	return close_tx;
}

/* Create a bitcoin spend tx (to spend our commit's outputs) */
const struct bitcoin_tx *bitcoin_spend_ours(struct peer *peer)
{
	u8 *witnessscript;
	const struct bitcoin_tx *commit = peer->us.commit->tx;
	struct bitcoin_signature sig;
	struct bitcoin_tx *tx;
	unsigned int p2wsh_out;
	uint64_t fee;

	/* The redeemscript for a commit tx is fairly complex. */
	witnessscript = bitcoin_redeem_secret_or_delay(peer,
						      &peer->us.finalkey,
						      &peer->them.locktime,
						      &peer->them.finalkey,
						      &peer->us.commit->revocation_hash);

	/* Now, create transaction to spend it. */
	tx = bitcoin_tx(peer, 1, 1);
	bitcoin_txid(commit, &tx->input[0].txid);
	p2wsh_out = find_p2wsh_out(commit, witnessscript);
	tx->input[0].index = p2wsh_out;
	tx->input[0].sequence_number = bitcoin_nsequence(&peer->them.locktime);
	tx->input[0].amount = tal_dup(tx->input, u64,
				      &commit->output[p2wsh_out].amount);

	tx->output[0].script = scriptpubkey_p2sh(tx,
				 bitcoin_redeem_single(tx, &peer->us.finalkey));
	tx->output[0].script_length = tal_count(tx->output[0].script);

	/* Witness length can vary, due to DER encoding of sigs, but we
	 * use 176 from an example run. */
	assert(measure_tx_cost(tx) == 83 * 4);

	/* FIXME: Dynamic fees! */
	fee = fee_by_feerate(83 + 176 / 4,
			     peer->dstate->config.closing_fee_rate);

	/* FIXME: Fail gracefully in these cases (not worth collecting) */
	if (fee > commit->output[p2wsh_out].amount
	    || is_dust_amount(commit->output[p2wsh_out].amount - fee))
		fatal("Amount of %"PRIu64" won't cover fee %"PRIu64,
		      commit->output[p2wsh_out].amount, fee);

	tx->output[0].amount = commit->output[p2wsh_out].amount - fee;

	sig.stype = SIGHASH_ALL;
	peer_sign_spend(peer, tx, witnessscript, &sig.sig);

	tx->input[0].witness = bitcoin_witness_secret(tx, NULL, 0, &sig,
						      witnessscript);

	return tx;
}

/* Create a bitcoin steal tx (to steal all their commit's outputs) */
const struct bitcoin_tx *bitcoin_steal(const struct peer *peer,
				       struct commit_info *ci)
{
	FIXME_STUB(peer);
}

/* Sign and return our commit tx */
const struct bitcoin_tx *bitcoin_commit(struct peer *peer)
{
	struct bitcoin_signature sig;

	/* Can't be signed already, and can't have scriptsig! */
	assert(peer->us.commit->tx->input[0].script_length == 0);
	assert(!peer->us.commit->tx->input[0].witness);

	sig.stype = SIGHASH_ALL;
	peer_sign_ourcommit(peer, peer->us.commit->tx, &sig.sig);

	peer->us.commit->tx->input[0].witness
		= bitcoin_witness_2of2(peer->us.commit->tx->input,
				       &peer->us.commit->sig,
				       &sig,
				       &peer->them.commitkey,
				       &peer->us.commitkey);

	return peer->us.commit->tx;
}

/* Create a HTLC refund collection */
const struct bitcoin_tx *bitcoin_htlc_timeout(const struct peer *peer,
					      const struct htlc_onchain *htlc_onchain)
{
	FIXME_STUB(peer);
}

/* Create a HTLC collection */
const struct bitcoin_tx *bitcoin_htlc_spend(const struct peer *peer,
					    const struct htlc_onchain *htlc_onchain)
{
	FIXME_STUB(peer);
}

/* Now we can create anchor tx. */ 
static void got_feerate(struct lightningd_state *dstate,
			u64 rate, struct peer *peer)
{
	u64 fee;
	struct bitcoin_tx *tx = bitcoin_tx(peer, 1, 1);
	size_t i;

	tx->output[0].script = scriptpubkey_p2wsh(tx, peer->anchor.witnessscript);
	tx->output[0].script_length = tal_count(tx->output[0].script);

	/* Add input script length.  FIXME: This is normal case, not exact. */
	fee = fee_by_feerate(measure_tx_cost(tx)/4 + 1+73 + 1+33 + 1, rate);
	if (fee >= peer->anchor.input->amount)
		/* FIXME: Report an error here!
		 * We really should set this when they do command, but
		 * we need to modify state to allow immediate anchor
		 * creation: using estimate_fee is a convenient workaround. */
		fatal("Amount %"PRIu64" below fee %"PRIu64,
		      peer->anchor.input->amount, fee);

	tx->output[0].amount = peer->anchor.input->amount - fee;

	tx->input[0].txid = peer->anchor.input->txid;
	tx->input[0].index = peer->anchor.input->index;
	tx->input[0].amount = tal_dup(tx->input, u64,
				      &peer->anchor.input->amount);

	wallet_add_signed_input(peer->dstate, peer->anchor.input->w, tx, 0);

	bitcoin_txid(tx, &peer->anchor.txid);
	peer->anchor.tx = tx;
	peer->anchor.index = 0;
	/* We'll need this later, when we're told to broadcast it. */
	peer->anchor.satoshis = tx->output[0].amount;

	/* To avoid malleation, all inputs must be segwit! */
	for (i = 0; i < tx->input_count; i++)
		assert(tx->input[i].witness);
	
	state_event(peer, BITCOIN_ANCHOR_CREATED, NULL);
}

/* Creation the bitcoin anchor tx, spending output user provided. */
void bitcoin_create_anchor(struct peer *peer, enum state_input done)
{
	/* We must be offering anchor for us to try creating it */
	assert(peer->us.offer_anchor);

	assert(done == BITCOIN_ANCHOR_CREATED);
	bitcoind_estimate_fee(peer->dstate, got_feerate, peer);
}

/* We didn't end up broadcasting the anchor: release the utxos.
 * If done != INPUT_NONE, remove existing create_anchor too. */
void bitcoin_release_anchor(struct peer *peer, enum state_input done)
{
	
	/* FIXME: stop bitcoind command  */
	log_unusual(peer->log, "Anchor not spent, please -zapwallettxs");
}

/* Get the bitcoin anchor tx. */
const struct bitcoin_tx *bitcoin_anchor(struct peer *peer)
{
	return peer->anchor.tx;
}

/* Sets up the initial cstate and commit tx for both nodes: false if
 * insufficient funds. */
bool setup_first_commit(struct peer *peer)
{
	assert(!peer->us.commit->tx);
	assert(!peer->them.commit->tx);

	/* Revocation hashes already filled in, from pkt_open */
	peer->us.commit->cstate = initial_funding(peer,
						  peer->us.offer_anchor
						  == CMD_OPEN_WITH_ANCHOR,
						  peer->anchor.satoshis,
						  peer->us.commit_fee_rate);
	if (!peer->us.commit->cstate)
		return false;

	peer->them.commit->cstate = initial_funding(peer,
						    peer->them.offer_anchor
						    == CMD_OPEN_WITH_ANCHOR,
						    peer->anchor.satoshis,
						    peer->them.commit_fee_rate);
	if (!peer->them.commit->cstate)
		return false;

	peer->us.commit->tx = create_commit_tx(peer->us.commit,
					       &peer->us.finalkey,
					       &peer->them.finalkey,
					       &peer->them.locktime,
					       &peer->anchor.txid,
					       peer->anchor.index,
					       peer->anchor.satoshis,
					       &peer->us.commit->revocation_hash,
					       peer->us.commit->cstate,
					       &peer->us.commit->map);

	peer->them.commit->tx = create_commit_tx(peer->them.commit,
						 &peer->them.finalkey,
						 &peer->us.finalkey,
						 &peer->us.locktime,
						 &peer->anchor.txid,
						 peer->anchor.index,
						 peer->anchor.satoshis,
						 &peer->them.commit->revocation_hash,
						 peer->them.commit->cstate,
						 &peer->them.commit->map);

	peer->us.staging_cstate = copy_funding(peer, peer->us.commit->cstate);
	peer->them.staging_cstate = copy_funding(peer, peer->them.commit->cstate);
	return true;
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

static void json_add_htlcs(struct json_result *response,
			   const char *id,
			   const struct channel_oneside *side)
{
	size_t i;

	json_array_start(response, id);
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
}

/* FIXME: add history command which shows all prior and current commit txs */

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
		const struct channel_state *last;

		json_object_start(response, NULL);
		json_add_string(response, "name", log_prefix(p->log));
		json_add_string(response, "state", state_name(p->state));
		json_add_string(response, "cmd", input_name(p->curr_cmd.cmd));

		/* This is only valid after crypto setup. */
		if (p->state != STATE_INIT)
			json_add_hex(response, "peerid",
				     p->id.der, sizeof(p->id.der));

		/* FIXME: Report anchor. */

		if (!p->us.commit) {
			json_object_end(response);
			continue;
		}
		last = p->us.commit->cstate;

		json_add_num(response, "our_amount", last->a.pay_msat);
		json_add_num(response, "our_fee", last->a.fee_msat);
		json_add_num(response, "their_amount", last->b.pay_msat);
		json_add_num(response, "their_fee", last->b.fee_msat);
		json_add_htlcs(response, "our_htlcs", &last->a);
		json_add_htlcs(response, "their_htlcs", &last->b);

		/* Any changes since then? */
		if (p->us.staging_cstate->changes != last->changes)
			json_add_num(response, "staged_changes",
				     p->us.staging_cstate->changes
				     - last->changes);
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
			     struct command *jsoncmd,
			     enum state_input cmd,
			     const union htlc_staging *stage)
{
	/* FIXME: memleak! */
	/* FIXME: Get rid of struct htlc_progress */
	struct htlc_progress *progress = tal(peer, struct htlc_progress);

	progress->stage = *stage;
	set_current_command(peer, cmd, progress, jsoncmd);
}
		
/* FIXME: Keep a timeout for each peer, in case they're unresponsive. */

/* FIXME: Make sure no HTLCs in any unrevoked commit tx are live. */

static void check_htlc_expiry(struct peer *peer, void *unused)
{
	size_t i;
	union htlc_staging stage;

	stage.fail.fail = HTLC_FAIL;

	/* Check their currently still-existing htlcs for expiry:
	 * We eliminate them from staging as we go. */
	for (i = 0; i < tal_count(peer->them.staging_cstate->a.htlcs); i++) {
		struct channel_htlc *htlc = &peer->them.staging_cstate->a.htlcs[i];

		/* Not a seconds-based expiry? */
		if (!abs_locktime_is_seconds(&htlc->expiry))
			continue;

		/* Not well-expired? */
		if (controlled_time().ts.tv_sec - 30
		    < abs_locktime_to_seconds(&htlc->expiry))
			continue;

		stage.fail.id = htlc->id;
		set_htlc_command(peer, NULL, CMD_SEND_HTLC_FAIL, &stage);
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

	/* Now we can assign counter and guarantee uniqueness. */
	newhtlc->htlc.id = peer->htlc_id_counter;
	stage.add.add = HTLC_ADD;
	stage.add.htlc = newhtlc->htlc;
		
	/* BOLT #2:
	 *
	 * A node MUST NOT add a HTLC if it would result in it
	 * offering more than 1500 HTLCs in either commitment transaction.
	 */
	if (tal_count(peer->us.staging_cstate->a.htlcs) == 1500
	    || tal_count(peer->them.staging_cstate->b.htlcs) == 1500) {
		command_fail(newhtlc->jsoncmd, "Too many HTLCs");
	}


	/* BOLT #2:
	 *
	 * A node MUST NOT offer `amount_msat` it cannot pay for in
	 * both commitment transactions at the current `fee_rate`
	 */
	cstate = copy_funding(newhtlc, peer->them.staging_cstate);
	if (!funding_b_add_htlc(cstate, newhtlc->htlc.msatoshis,
				&newhtlc->htlc.expiry, &newhtlc->htlc.rhash,
				newhtlc->htlc.id)) {
		command_fail(newhtlc->jsoncmd,
			     "Cannot afford %"PRIu64
			     " milli-satoshis in their commit tx",
			     newhtlc->htlc.msatoshis);
		return;
	}

	cstate = copy_funding(newhtlc, peer->us.staging_cstate);
	if (!funding_a_add_htlc(cstate, newhtlc->htlc.msatoshis,
				&newhtlc->htlc.expiry, &newhtlc->htlc.rhash,
				newhtlc->htlc.id)) {
		command_fail(newhtlc->jsoncmd,
			     "Cannot afford %"PRIu64
			     " milli-satoshis in our commit tx",
			     newhtlc->htlc.msatoshis);
		return;
	}

	/* Make sure we never offer the same one twice. */
	peer->htlc_id_counter++;	

	/* FIXME: Never propose duplicate rvalues? */
	set_htlc_command(peer, newhtlc->jsoncmd, CMD_SEND_HTLC_ADD, &stage);
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

	if (!peer->them.commit || !peer->them.commit->cstate) {
		command_fail(cmd, "peer not fully established");
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
}

/* FIXME: Use HTLC ids, not r values! */
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
	struct sha256 rhash;
	size_t i;
	union htlc_staging stage;

	stage.fulfill.fulfill = HTLC_FULFILL;
	stage.fulfill.r = fulfillhtlc->r;

	sha256(&rhash, &fulfillhtlc->r, sizeof(fulfillhtlc->r));

	i = funding_find_htlc(&peer->them.staging_cstate->a, &rhash);
	if (i == tal_count(peer->them.staging_cstate->a.htlcs)) {
		command_fail(fulfillhtlc->jsoncmd, "preimage htlc not found");
		return;
	}
	stage.fulfill.id = peer->them.staging_cstate->a.htlcs[i].id;
	set_htlc_command(peer, fulfillhtlc->jsoncmd,
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

	if (!peer->them.commit || !peer->them.commit->cstate) {
		command_fail(cmd, "peer not fully established");
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
	size_t i;
	union htlc_staging stage;

	stage.fail.fail = HTLC_FAIL;

	/* Look in peer->them.staging_cstate->a, as that's where we'll 
	 * immediately remove it from: avoids double-handling. */
	/* FIXME: Make sure it's also committed in previous commit tx! */
	i = funding_find_htlc(&peer->them.staging_cstate->a, &failhtlc->rhash);
	if (i == tal_count(peer->them.staging_cstate->a.htlcs)) {
		command_fail(failhtlc->jsoncmd, "htlc not found");
		return;
	}
	stage.fail.id = peer->them.staging_cstate->a.htlcs[i].id;

	set_htlc_command(peer, failhtlc->jsoncmd, CMD_SEND_HTLC_FAIL, &stage);
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

	if (!peer->them.commit || !peer->them.commit->cstate) {
		command_fail(cmd, "peer not fully established");
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
}
	
const struct json_command failhtlc_command = {
	"failhtlc",
	json_failhtlc,
	"Fail htlc proposed by {peerid} which has redeem hash {rhash}",
	"Returns an empty result on success"
};

static void do_commit(struct peer *peer, struct command *jsoncmd)
{
	/* We can have changes we suggested, or changes they suggested. */
	if (peer->them.staging_cstate->changes == peer->them.commit->cstate->changes) {
		command_fail(jsoncmd, "no changes to commit");
		return;
	}

	set_current_command(peer, CMD_SEND_COMMIT, NULL, jsoncmd);
}

static void json_commit(struct command *cmd,
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

	if (!peer->them.commit || !peer->them.commit->cstate) {
		command_fail(cmd, "peer not fully established");
		return;
	}

	queue_cmd(peer, do_commit, cmd);
}
	
const struct json_command commit_command = {
	"commit",
	json_commit,
	"Commit all staged HTLC changes with {peerid}",
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

static void json_disconnect(struct command *cmd,
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

	if (!peer->conn) {
		command_fail(cmd, "Peer is already disconnected");
		return;
	}

	/* We don't actually close it, since for testing we want only
	 * one side to freak out.  We just ensure we ignore it. */
	log_debug(peer->log, "Pretending connection is closed");
	peer->fake_close = true;
	state_single(peer, INPUT_CONNECTION_LOST, NULL);

	command_success(cmd, null_response(cmd));
}

const struct json_command disconnect_command = {
	"dev-disconnect",
	json_disconnect,
	"Force a disconned with peer {peerid}",
	"Returns an empty result on success"
};
