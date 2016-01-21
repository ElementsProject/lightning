#include "bitcoind.h"
#include "close_tx.h"
#include "commit_tx.h"
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

static struct peer *find_peer(struct lightningd_state *dstate,
			      const struct pubkey *id)
{
	struct peer *peer;
	list_for_each(&dstate->peers, peer, list) {
		if (peer->state != STATE_INIT && pubkey_eq(&peer->id, id))
			return peer;
	}
	return NULL;
}

static void queue_output_pkt(struct peer *peer, Pkt *pkt)
{
	peer->outpkt[peer->num_outpkt++] = pkt;
	assert(peer->num_outpkt < ARRAY_SIZE(peer->outpkt));

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
	assert(peer->cmd != INPUT_NONE);

	if (peer->jsoncmd) {
		if (status == CMD_FAIL)
			/* FIXME: y'know, details. */
			command_fail(peer->jsoncmd, "Failed");
		else {
			assert(status == CMD_SUCCESS);
			command_success(peer->jsoncmd,
					null_response(peer->jsoncmd));
		}
		peer->jsoncmd = NULL;
	}
	peer->cmd = INPUT_NONE;
}

static void update_state(struct peer *peer,
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
}

static struct io_plan *pkt_out(struct io_conn *conn, struct peer *peer)
{
	Pkt *out;

	if (peer->num_outpkt == 0)
		return io_out_wait(conn, peer, pkt_out, peer);

	out = peer->outpkt[--peer->num_outpkt];
	return peer_write_packet(conn, peer, out, pkt_out);
}

static void try_command(struct peer *peer)
{
	while (peer->cond == PEER_CMD_OK && peer->cmd != INPUT_NONE)
		update_state(peer, peer->cmd, &peer->cmddata);

	if (peer->cond == PEER_CLOSED)
		io_close(peer->conn);
}
	
static struct io_plan *pkt_in(struct io_conn *conn, struct peer *peer)
{
	union input idata;
	const tal_t *ctx = tal(peer, char);

	idata.pkt = tal_steal(ctx, peer->inpkt);
	update_state(peer, peer->inpkt->pkt_case, &idata);

	/* Free peer->inpkt unless stolen above. */
	tal_free(ctx);

	if (peer->cond == PEER_CLOSED)
		return io_close(conn);

	/* Ready for command? */
	if (peer->cond == PEER_CMD_OK)
		try_command(peer);

	return peer_read_packet(conn, peer, pkt_in);
}

/* Crypto is on, we are live. */
static struct io_plan *peer_crypto_on(struct io_conn *conn, struct peer *peer)
{
	peer_secrets_init(peer);
	peer_get_revocation_hash(peer, 0, &peer->us.revocation_hash);

	assert(peer->state == STATE_INIT);
	peer->cmd = peer->us.offer_anchor;
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
	peer->num_outpkt = 0;
	peer->cmd = INPUT_NONE;
	peer->current_htlc = NULL;
	peer->num_htlcs = 0;
	peer->close_tx = NULL;

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

	peer->jsoncmd = NULL;
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
	peer->jsoncmd = NULL;
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

	json_get_params(buffer, params,
			"host", &host,
			"port", &port,
			"satoshis", &satoshis,
			NULL);

	if (!host || !port || !satoshis) {
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
	enum state_input depthok;
	enum state_input timeout;
	enum state_input unspent;
	enum state_input theyspent;
	enum state_input otherspent;
};

static void anchor_depthchange(struct peer *peer, int depth,
			       struct anchor_watch *w)
{
	/* Still waiting for it to reach depth? */
	if (w->depthok != INPUT_NONE) {
		/* Beware sign! */
		if (depth >= (int)peer->us.mindepth) {
			enum state_input in = w->depthok;
			w->depthok = INPUT_NONE;
			update_state(peer, in, NULL);
		}
	} else {
		if (depth < 0 && w->unspent != INPUT_NONE) {
			enum state_input in = w->unspent;
			w->unspent = INPUT_NONE;
			update_state(peer, in, NULL);
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
		update_state(peer, w->theyspent, &idata);
	else
		update_state(peer, w->otherspent, &idata);
}

void peer_watch_anchor(struct peer *peer,
		       enum state_input depthok,
		       enum state_input timeout,
		       enum state_input unspent,
		       enum state_input theyspent,
		       enum state_input otherspent)
{
	struct anchor_watch *w = tal(peer, struct anchor_watch);

	w->depthok = depthok;
	w->timeout = timeout;
	w->unspent = unspent;
	w->theyspent = theyspent;
	w->otherspent = otherspent;

	add_anchor_watch(peer, &peer->anchor.txid, peer->anchor.index,
			 anchor_depthchange,
			 anchor_spent,
			 w);

	/* FIXME: add timeout */
}

void peer_unwatch_anchor_depth(struct peer *peer,
			       enum state_input depthok,
			       enum state_input timeout)
{
	FIXME_STUB(peer);
}

void peer_watch_delayed(struct peer *peer,
			const struct bitcoin_tx *tx,
			enum state_input canspend)
{
	FIXME_STUB(peer);
}
void peer_watch_tx(struct peer *peer,
		   const struct bitcoin_tx *tx,
		   enum state_input done)
{
	FIXME_STUB(peer);
}

static void send_close_timeout(struct peer *peer)
{
	update_state(peer, INPUT_CLOSE_COMPLETE_TIMEOUT, NULL);
}

void peer_watch_close(struct peer *peer,
		      enum state_input done, enum state_input timedout)
{
	/* We save some work by assuming this. */
	assert(timedout == INPUT_CLOSE_COMPLETE_TIMEOUT);

	/* FIXME: We didn't send CLOSE, so timeout immediately */
	if (!peer->conn) {
		(void)send_close_timeout;
		/* FIXME: oneshot_timeout(peer->dstate, peer, 0, send_close_timeout, peer); */
		return;
	}

	FIXME_STUB(peer);
}
void peer_unwatch_close_timeout(struct peer *peer, enum state_input timedout)
{
	FIXME_STUB(peer);
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
	FIXME_STUB(peer);
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
const struct bitcoin_tx *bitcoin_close(const tal_t *ctx,
				       const struct peer *peer)
{
#if 0
	struct bitcoin_tx *close_tx;
	u8 *redeemscript;

	close_tx = create_close_tx(ctx, peer->us.openpkt, peer->them.openpkt,
				   peer->anchorpkt, 
				   peer->cstate.a.pay_msat / 1000,
				   peer->cstate.b.pay_msat / 1000);

	/* This is what the anchor pays to. */
	redeemscript = bitcoin_redeem_2of2(close_tx, &peer->us.commitkey,
					   &peer->them.commitkey);
	
	/* Combined signatures must validate correctly. */
	if (!check_2of2_sig(close_tx, 0, redeemscript, tal_count(redeemscript),
			    &peer->us.finalkey, &peer->them.finalkey,
			    &peer->us.closesig, &peer->them.closesig))
		fatal("bitcoin_close signature failed");

	/* Create p2sh input for close_tx */
	close_tx->input[0].script = scriptsig_p2sh_2of2(close_tx,
							&peer->us.closesig,
							&peer->them.closesig,
							&peer->us.finalkey,
							&peer->them.finalkey);
	close_tx->input[0].script_length = tal_count(close_tx->input[0].script);

	return close_tx;
#endif
	FIXME_STUB(peer);
}

/* Create a bitcoin spend tx (to spend our commit's outputs) */
const struct bitcoin_tx *bitcoin_spend_ours(const tal_t *ctx,
					    const struct peer *peer)
{
#if 0
	u8 *redeemscript;

	redeemscript = bitcoin_redeem_secret_or_delay(ctx,
						      &peer->us.commitkey,
						      &peer->them.locktime,
						      &peer->them.commitkey,
						      &peer->revocation_hash);

	/* Now, create transaction to spend it. */
	tx = bitcoin_tx(ctx, 1, 1);
	bitcoin_txid(commit, &tx->input[0].txid);
	p2sh_out = find_p2sh_out(commit, redeemscript);
	tx->input[0].index = p2sh_out;
	tx->input[0].input_amount = commit->output[p2sh_out].amount;
	tx->fee = fee;

	tx->input[0].sequence_number = bitcoin_nsequence(locktime);

	if (commit->output[p2sh_out].amount <= fee)
		errx(1, "Amount of %llu won't exceed fee",
		     (unsigned long long)commit->output[p2sh_out].amount);

	tx->output[0].amount = commit->output[p2sh_out].amount - fee;
	tx->output[0].script = scriptpubkey_p2sh(tx,
						 bitcoin_redeem_single(tx, &outpubkey));
	tx->output[0].script_length = tal_count(tx->output[0].script);

	/* Now get signature, to set up input script. */
	if (!sign_tx_input(tx, 0, redeemscript, tal_count(redeemscript),
			   &privkey, &pubkey1, &sig.sig))
		errx(1, "Could not sign tx");
	sig.stype = SIGHASH_ALL;
	tx->input[0].script = scriptsig_p2sh_secret(tx, NULL, 0, &sig,
						    redeemscript,
						    tal_count(redeemscript));
	tx->input[0].script_length = tal_count(tx->input[0].script);
#endif
	FIXME_STUB(peer);
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

/* Create our commit tx */
const struct bitcoin_tx *bitcoin_commit(const tal_t *ctx, struct peer *peer)
{
	FIXME_STUB(peer);
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

	update_state(peer, BITCOIN_ANCHOR_CREATED, NULL);
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
		json_add_string(response, "cmd", input_name(p->cmd));

		/* This is only valid after crypto setup. */
		if (p->state != STATE_INIT)
			json_add_hex(response, "id",
				     p->id.der, pubkey_derlen(&p->id));
		
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

static void json_newhtlc(struct command *cmd,
			 const char *buffer, const jsmntok_t *params)
{
	struct peer *peer;
	jsmntok_t *idtok, *msatoshistok, *expirytok, *rhashtok;
	struct pubkey id;
	unsigned int expiry;
	struct htlc_progress *cur;

	json_get_params(buffer, params,
			"id", &idtok,
			"msatoshis", &msatoshistok,
			"expiry", &expirytok,
			"rhash", &rhashtok,
			NULL);

	if (!idtok || !msatoshistok || !expirytok || !rhashtok) {
		command_fail(cmd, "Need id, msatoshis, expiry and rhash");
		return;
	}

	if (!pubkey_from_hexstr(cmd->dstate->secpctx,
				buffer + idtok->start,
				idtok->end - idtok->start, &id)) {
		command_fail(cmd, "Not a valid id");
		return;
	}
	peer = find_peer(cmd->dstate, &id);
	if (!peer) {
		command_fail(cmd, "Could not find peer with that id");
		return;
	}

	/* Attach to cmd until it's complete. */
	cur = tal(cmd, struct htlc_progress);
	cur->htlc = tal(cur, struct channel_htlc);
	if (!json_tok_u64(buffer, msatoshistok, &cur->htlc->msatoshis)) {
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

	if (!seconds_to_abs_locktime(expiry, &cur->htlc->expiry)) {
		command_fail(cmd, "'%.*s' is not a valid number",
			     (int)(expirytok->end - expirytok->start),
			     buffer + expirytok->start);
		return;
	}
	if (!hex_decode(buffer + rhashtok->start,
			rhashtok->end - rhashtok->start,
			&cur->htlc->rhash, sizeof(cur->htlc->rhash))) {
		command_fail(cmd, "'%.*s' is not a valid sha256 hash",
			     (int)(rhashtok->end - rhashtok->start),
			     buffer + rhashtok->start);
		return;
	}
	peer_get_revocation_hash(peer, peer->num_htlcs+1,
				 &cur->our_revocation_hash);

	/* Can we even offer this much? */
	cur->cstate = copy_funding(cur, peer->cstate);
	if (!funding_delta(peer->us.offer_anchor == CMD_OPEN_WITH_ANCHOR,
			   peer->anchor.satoshis,
			   0, cur->htlc->msatoshis,
			   &cur->cstate->a, &cur->cstate->b)) {
		command_fail(cmd, "Cannot afford %"PRIu64" milli-satoshis",
			     cur->htlc->msatoshis);
		return;
	}
	/* Add the htlc to our side of channel. */
	funding_add_htlc(&cur->cstate->a, cur->htlc->msatoshis,
			 &cur->htlc->expiry, &cur->htlc->rhash);

	peer->current_htlc = tal_steal(peer, cur);
	peer->jsoncmd = cmd;

	/* FIXME: do we need this? */
	peer->cmddata.htlc_prog = peer->current_htlc;
	peer->cmd = CMD_SEND_HTLC_UPDATE;
	try_command(peer);
}

const struct json_command newhtlc_command = {
	"newhtlc",
	json_newhtlc,
	"Offer {id} an HTLC worth {msatoshis} in {expiry} (in seconds since Jan 1 1970) with {rhash}",
	"Returns an empty result on success"
};
