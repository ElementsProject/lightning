#include "bitcoin/privkey.h"
#include "bitcoin/signature.h"
#include "daemon/chaintopology.h"
#include "daemon/irc_announce.h"
#include "daemon/lightningd.h"
#include "daemon/log.h"
#include "daemon/peer.h"
#include "daemon/routing.h"
#include "daemon/secrets.h"
#include "daemon/timeout.h"
#include "utils.h"

#include <ccan/list/list.h>
#include <ccan/str/hex/hex.h>

static bool announce_channel(const tal_t *ctx, struct ircstate *state, struct peer *p)
{
	char txid[65];
	int siglen;
	u8 der[72];
	struct signature sig;
	struct privmsg *msg = talz(ctx, struct privmsg);
	struct txlocator *loc = locate_tx(ctx, state->dstate, &p->anchor.txid);

	if (loc == NULL)
		return false;

	bitcoin_txid_to_hex(&p->anchor.txid, txid, sizeof(txid));
	msg->channel = "#lightning-nodes";
	msg->msg = tal_fmt(
		msg, "CHAN %s %s %s %d %d %d %d %d",
		pubkey_to_hexstr(msg, state->dstate->secpctx, &state->dstate->id),
		pubkey_to_hexstr(msg, state->dstate->secpctx, p->id),
		txid,
		loc->blkheight,
		loc->index,
		state->dstate->config.fee_base,
		state->dstate->config.fee_per_satoshi,
		p->remote.locktime.locktime
		);

	privkey_sign(state->dstate, msg->msg, strlen(msg->msg), &sig);
	siglen = signature_to_der(state->dstate->secpctx, der, &sig);
	msg->msg = tal_fmt(msg, "%s %s", tal_hexstr(ctx, der, siglen), msg->msg);

	irc_send_msg(state, msg);
	return true;
}

static void announce_channels(struct ircstate *state)
{
	tal_t *ctx = tal(state, tal_t);
	struct peer *p;

	list_for_each(&state->dstate->peers, p, list) {

		if (!state_is_normal(p->state))
			continue;
		announce_channel(ctx, state, p);
	}
	tal_free(ctx);

	new_reltimer(state->dstate, state, time_from_sec(60), announce_channels, state);
}

/* Reconnect to IRC server upon disconnection. */
static void handle_irc_disconnect(struct ircstate *state)
{
	new_reltimer(state->dstate, state, state->reconnect_timeout, irc_connect, state);
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
	int blkheight;
	char **splits = tal_strsplit(msg, msg->msg + 1, " ", STR_NO_EMPTY);

	if (tal_count(splits) != 11 || !streq(splits[1], "CHAN"))
		return;

	int siglen = hex_data_size(strlen(splits[0]));
	u8 *der = tal_hexdata(msg, splits[0], strlen(splits[0]));
	if (der == NULL)
		return;

	struct signature sig;
	struct sha256_double hash;
	char *content = strchr(msg->msg, ' ') + 1;
	if (!signature_from_der(istate->dstate->secpctx, der, siglen, &sig))
		return;

	sha256_double(&hash, content, strlen(content));
	splits++;

	struct pubkey *pk1 = talz(msg, struct pubkey);
	struct pubkey *pk2 = talz(msg, struct pubkey);
	struct sha256_double *txid = talz(msg, struct sha256_double);
	int index;

	bool ok = true;
	ok &= pubkey_from_hexstr(istate->dstate->secpctx, splits[1], strlen(splits[1]), pk1);
	ok &= pubkey_from_hexstr(istate->dstate->secpctx, splits[2], strlen(splits[2]), pk2);
	ok &= bitcoin_txid_from_hex(splits[3], strlen(splits[3]), txid);
	blkheight = atoi(splits[4]);
	index = atoi(splits[5]);
	if (!ok || index < 0 || blkheight < 0) {
		log_debug(istate->dstate->base_log, "Unable to parse channel announcent.");
		return;
	}

	if (!check_signed_hash(istate->dstate->secpctx, &hash, &sig, pk1)) {
		log_debug(istate->log,
			  "Ignoring announcement from %s, signature check failed.",
			  splits[1]);
		return;
	}

	/*
	 * FIXME Check in topology that the tx is in the block and
	 * that the endpoints match.
	 */

	add_connection(istate->dstate, pk1, pk2, atoi(splits[6]),
		       atoi(splits[7]), atoi(splits[8]), 6);
}

void setup_irc_connection(struct lightningd_state *dstate)
{
	// Register callback
	irc_privmsg_cb = *handle_irc_privmsg;
	irc_disconnect_cb = *handle_irc_disconnect;

	struct ircstate *state = talz(dstate, struct ircstate);
	state->dstate = dstate;
	state->server = "irc.freenode.net";
	state->reconnect_timeout = time_from_sec(15);
	state->log = new_log(state, state->dstate->log_record, "%s:irc",
			     log_prefix(state->dstate->base_log));

	/* Truncate nick at 13 bytes, would be imposed by freenode anyway */
	state->nick = tal_fmt(
		state,
		"N%.12s",
		pubkey_to_hexstr(state, dstate->secpctx, &dstate->id) + 1);

	irc_connect(state);
	announce_channels(state);
}
