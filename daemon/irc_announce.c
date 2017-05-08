#include "bitcoin/privkey.h"
#include "bitcoin/signature.h"
#include "daemon/chaintopology.h"
#include "daemon/irc_announce.h"
#include "daemon/lightningd.h"
#include "daemon/log.h"
#include "daemon/peer.h"
#include "daemon/peer_internal.h"
#include "daemon/routing.h"
#include "daemon/secrets.h"
#include "daemon/timeout.h"
#include "utils.h"

#include <ccan/list/list.h>
#include <ccan/str/hex/hex.h>

/* Sign a privmsg by prepending the signature to the message */
static void sign_privmsg(struct ircstate *state, struct privmsg *msg)
{
	int siglen;
	u8 der[72];
	secp256k1_ecdsa_signature sig;
	privkey_sign(state->dstate, msg->msg, strlen(msg->msg), &sig);
	siglen = signature_to_der(der, &sig);
	msg->msg = tal_fmt(msg, "%s %s", tal_hexstr(msg, der, siglen), msg->msg);
}

static bool announce_channel(const tal_t *ctx, struct ircstate *state, struct peer *p)
{
	char txid[65];
	struct privmsg *msg = talz(ctx, struct privmsg);
	struct txlocator *loc = locate_tx(ctx, state->dstate->topology, &p->anchor.txid);

	if (loc == NULL)
		return false;

	bitcoin_txid_to_hex(&p->anchor.txid, txid, sizeof(txid));
	msg->channel = "#lightning-nodes";
	msg->msg = tal_fmt(
		msg, "CHAN %s %s %s %d %d %d %d %d",
		pubkey_to_hexstr(msg, &state->dstate->id),
		pubkey_to_hexstr(msg, p->id),
		txid,
		loc->blkheight,
		loc->index,
		state->dstate->config.fee_base,
		state->dstate->config.fee_per_satoshi,
		state->dstate->config.min_htlc_expiry
		);
	sign_privmsg(state, msg);
	irc_send_msg(state, msg);
	return true;
}

/* Send an announcement for this node to the channel, including its
 * hostname, port and ID */
static void announce_node(const tal_t *ctx, struct ircstate *state)
{
	char *hostname = state->dstate->external_ip;
	int port = state->dstate->portnum;
	struct privmsg *msg = talz(ctx, struct privmsg);

	if (hostname == NULL) {
		//FIXME: log that we don't know our IP yet.
		return;
	}

	msg->channel = "#lightning-nodes";
	msg->msg = tal_fmt(
		msg, "NODE %s %s %d",
		pubkey_to_hexstr(msg, &state->dstate->id),
		hostname,
		port
		);

	sign_privmsg(state, msg);
	irc_send_msg(state, msg);
}

/* Announce the node's contact information and all of its channels */
static void announce(struct ircstate *state)
{

	tal_t *ctx = tal(state, tal_t);
	struct peer *p;

	announce_node(ctx, state);

	list_for_each(&state->dstate->peers, p, list) {

		if (!state_is_normal(p->state))
			continue;
		announce_channel(ctx, state, p);
	}
	tal_free(ctx);

	/* By default we announce every 6 hours, otherwise when someone joins */
	log_debug(state->log, "Setting long announce time: 6 hours");
	state->dstate->announce = new_reltimer(&state->dstate->timers, state,
					       time_from_sec(3600 * 6),
					       announce, state);
}

/* Reconnect to IRC server upon disconnection. */
static void handle_irc_disconnect(struct ircstate *state)
{
	/* Stop announcing. */
	state->dstate->announce = tal_free(state->dstate->announce);
	new_reltimer(&state->dstate->timers, state, state->reconnect_timeout,
		     irc_connect, state);
}

/* Verify a signed privmsg */
static bool verify_signed_privmsg(
	struct ircstate *istate,
	const struct pubkey *pk,
	const struct privmsg *msg)
{
	secp256k1_ecdsa_signature sig;
	struct sha256_double hash;
	const char *m = msg->msg + 1;
	int siglen = strchr(m, ' ') - m;
	const char *content = m + siglen + 1;
	u8 *der = tal_hexdata(msg, m, siglen);

	siglen = hex_data_size(siglen);
	if (der == NULL)
		return false;

	if (!signature_from_der(der, siglen, &sig))
		return false;
	sha256_double(&hash, content, strlen(content));
	return check_signed_hash(&hash, &sig, pk);
}

static void handle_irc_channel_announcement(
	struct ircstate *istate,
	const struct privmsg *msg,
	char **splits)
{
	struct pubkey *pk1 = talz(msg, struct pubkey);
	struct pubkey *pk2 = talz(msg, struct pubkey);
	struct sha256_double *txid = talz(msg, struct sha256_double);
	int index;
	bool ok = true;
	int blkheight;

	ok &= pubkey_from_hexstr(splits[1], strlen(splits[1]), pk1);
	ok &= pubkey_from_hexstr(splits[2], strlen(splits[2]), pk2);
	ok &= bitcoin_txid_from_hex(splits[3], strlen(splits[3]), txid);
	blkheight = atoi(splits[4]);
	index = atoi(splits[5]);
	if (!ok || index < 0 || blkheight < 0) {
		log_debug(istate->dstate->base_log, "Unable to parse channel announcent.");
		return;
	}

	if (!verify_signed_privmsg(istate, pk1, msg)) {
		log_debug(istate->log,
			  "Ignoring announcement from %s, signature check failed.",
			  splits[1]);
		return;
	}

	/*
	 * FIXME Check in topology that the tx is in the block and
	 * that the endpoints match.
	 */

	add_connection(istate->dstate->rstate, pk1, pk2, atoi(splits[6]),
		       atoi(splits[7]), atoi(splits[8]), 6);
}

static void handle_irc_node_announcement(
	struct ircstate *istate,
	const struct privmsg *msg,
	char **splits)
{
	struct pubkey *pk = talz(msg, struct pubkey);
	if (!pubkey_from_hexstr(splits[1], strlen(splits[1]), pk))
		return;

	if (!verify_signed_privmsg(istate, pk, msg)) {
		log_debug(istate->log, "Ignoring node announcement from %s, signature check failed.",
			  splits[1]);
		return;
	} else if(splits[4] != NULL && strlen(splits[4]) > 64) {
		log_debug(istate->log, "Ignoring node announcement from %s, alias too long",
			splits[1]);
	}

	struct node *node = add_node(istate->dstate->rstate, pk);
	if (splits[4] != NULL){
		tal_free(node->alias);
		node->alias = tal_hexdata(node, splits[4], strlen(splits[4]));
	}
}

/*
 * Handle an incoming message by checking if it is a channel
 * announcement, parse it and add the channel to the topology if yes.
 *
 * The format for a valid announcement is:
 * <sig> CHAN <pk1> <pk2> <anchor txid> <block height> <tx position> <base_fee>
 * <proportional_fee> <locktime>
 */
static void handle_irc_privmsg(struct ircstate *istate, const struct privmsg *msg)
{
	char **splits = tal_strsplit(msg, msg->msg + 1, " ", STR_NO_EMPTY);
	int splitcount = tal_count(splits) - 1;

	if (splitcount < 2)
		return;

	char *type = splits[1];

	if (splitcount == 10 && streq(type, "CHAN"))
		handle_irc_channel_announcement(istate, msg, splits + 1);
	else if (splitcount >= 5 && streq(type, "NODE"))
		handle_irc_node_announcement(istate, msg, splits + 1);
}

static void handle_irc_command(struct ircstate *istate, const struct irccommand *cmd)
{
	struct lightningd_state *dstate = istate->dstate;
	char **params = tal_strsplit(cmd, cmd->params, " ", STR_NO_EMPTY);

	if (streq(cmd->command, "338") && tal_count(params) >= 4) {
		dstate->external_ip = tal_strdup(
			istate->dstate, params[3]);
		log_debug(dstate->base_log, "Detected my own IP as %s", dstate->external_ip);

		// Add our node to the node_map for completeness
		add_node(istate->dstate->rstate, &dstate->id);
	} else if (streq(cmd->command, "JOIN")) {
		unsigned int delay;

		/* Throw away any existing announce timer, and announce within
		 * 60 seconds. */
		dstate->announce = tal_free(dstate->announce);

		delay = pseudorand(60000000);
		log_debug(istate->log, "Setting new announce time %u sec",
			  delay / 1000000);
		dstate->announce = new_reltimer(&dstate->timers, istate,
						time_from_usec(delay),
						announce, istate);
	}
}

static void handle_irc_connected(struct ircstate *istate)
{
	irc_send(istate, "JOIN", "#lightning-nodes");
	irc_send(istate, "WHOIS", "%s", istate->nick);
}

void setup_irc_connection(struct lightningd_state *dstate)
{
	// Register callback
	irc_privmsg_cb = *handle_irc_privmsg;
	irc_connect_cb = *handle_irc_connected;
	irc_disconnect_cb = *handle_irc_disconnect;
	irc_command_cb = *handle_irc_command;

	struct ircstate *state = talz(dstate, struct ircstate);
	state->dstate = dstate;
	state->server = "irc.lfnet.org";
	state->reconnect_timeout = time_from_sec(15);
	state->log = new_log(state, state->dstate->log_book, "%s:irc",
			     log_prefix(state->dstate->base_log));

	/* Truncate nick at 13 bytes, would be imposed by freenode anyway */
	state->nick = tal_fmt(
		state,
		"N%.12s",
		pubkey_to_hexstr(state, &dstate->id) + 1);

	/* We will see our own JOIN message, which will trigger announce */
	irc_connect(state);
}
