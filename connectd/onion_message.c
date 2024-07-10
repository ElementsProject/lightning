/*~ This contains all the code to handle onion messages. */
#include "config.h"
#include <ccan/cast/cast.h>
#include <ccan/tal/str/str.h>
#include <common/blindedpath.h>
#include <common/blinding.h>
#include <common/daemon_conn.h>
#include <common/ecdh_hsmd.h>
#include <common/features.h>
#include <common/onion_message_parse.h>
#include <common/sphinx.h>
#include <common/status.h>
#include <common/wire_error.h>
#include <connectd/connectd.h>
#include <connectd/connectd_wiregen.h>
#include <connectd/multiplex.h>
#include <connectd/onion_message.h>
#include <wire/peer_wire.h>

void onionmsg_req(struct daemon *daemon, const u8 *msg)
{
	struct node_id id;
	u8 *onionmsg;
	struct pubkey blinding;
	struct peer *peer;

	if (!fromwire_connectd_send_onionmsg(msg, msg, &id, &onionmsg, &blinding))
		master_badmsg(WIRE_CONNECTD_SEND_ONIONMSG, msg);

	/* Even though lightningd checks for valid ids, there's a race
	 * where it might vanish before we read this command. */
	peer = peer_htable_get(daemon->peers, &id);
	if (peer) {
		u8 *omsg = towire_onion_message(NULL, &blinding, onionmsg);
		inject_peer_msg(peer, take(omsg));
	}
}

static const char *handle_onion(const tal_t *ctx,
				struct daemon *daemon,
				const struct pubkey *blinding,
				const u8 *onion)
{
	u8 *next_onion_msg;
	struct pubkey next_node;
	struct tlv_onionmsg_tlv *final_om;
	struct pubkey final_alias;
	struct secret *final_path_id;
	const char *err;

	err = onion_message_parse(tmpctx, onion, blinding,
				  &daemon->mykey,
				  &next_onion_msg, &next_node,
				  &final_om, &final_alias, &final_path_id);
	if (err) {
		return tal_steal(ctx, err);
	}

	if (final_om) {
		u8 *omsg;

		/* We re-marshall here by policy, before handing to lightningd */
		omsg = tal_arr(tmpctx, u8, 0);
		towire_tlvstream_raw(&omsg, final_om->fields);
		daemon_conn_send(daemon->master,
				 take(towire_connectd_got_onionmsg_to_us(NULL,
							final_path_id,
							final_om->reply_path,
							omsg)));
	} else {
		struct node_id next_node_id;
		struct peer *next_peer;

		assert(next_onion_msg);

		/* FIXME: Handle short_channel_id! */
		node_id_from_pubkey(&next_node_id, &next_node);
		next_peer = peer_htable_get(daemon->peers, &next_node_id);
		if (!next_peer) {
			return tal_fmt(ctx, "onion msg: unknown next peer %s",
				       fmt_pubkey(tmpctx, &next_node));
		}
		inject_peer_msg(next_peer, take(next_onion_msg));
	}
	return NULL;
}


/* Peer sends an onion msg, or (if peer NULL) lightningd injects one. */
void handle_onion_message(struct daemon *daemon,
			  struct peer *peer, const u8 *msg)
{
	struct pubkey blinding;
	u8 *onion;

	/* Ignore unless explicitly turned on. */
	if (!feature_offered(daemon->our_features->bits[NODE_ANNOUNCE_FEATURE],
			     OPT_ONION_MESSAGES))
		return;

	/* FIXME: ratelimit! */
	if (!fromwire_onion_message(msg, msg, &blinding, &onion)) {
		inject_peer_msg(peer,
				towire_warningfmt(NULL, NULL,
						  "Bad onion_message"));
		return;
	}

	handle_onion(tmpctx, daemon, &blinding, onion);
}

void inject_onionmsg_req(struct daemon *daemon, const u8 *msg)
{
	u8 *onionmsg;
	struct pubkey blinding;
	const char *err;

	if (!fromwire_connectd_inject_onionmsg(msg, msg, &blinding, &onionmsg))
		master_badmsg(WIRE_CONNECTD_INJECT_ONIONMSG, msg);

	err = handle_onion(tmpctx, daemon, &blinding, onionmsg);
	daemon_conn_send(daemon->master,
			 take(towire_connectd_inject_onionmsg_reply(NULL, err ? err : "")));
}


