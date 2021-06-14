#include "bitcoind.h"
#include "chaintopology.h"
#include "gossip_control.h"
#include "lightningd.h"
#include "peer_control.h"
#include "subd.h"
#include <ccan/array_size/array_size.h>
#include <ccan/crypto/siphash24/siphash24.h>
#include <ccan/err/err.h>
#include <ccan/fdpass/fdpass.h>
#include <ccan/json_escape/json_escape.h>
#include <ccan/take/take.h>
#include <ccan/tal/str/str.h>
#include <common/amount.h>
#include <common/features.h>
#include <common/json_command.h>
#include <common/json_helpers.h>
#include <common/jsonrpc_errors.h>
#include <common/param.h>
#include <common/type_to_string.h>
#include <common/utils.h>
#include <errno.h>
#include <gossipd/gossipd_wiregen.h>
#include <hsmd/capabilities.h>
#include <inttypes.h>
#include <lightningd/connect_control.h>
#include <lightningd/gossip_msg.h>
#include <lightningd/hsm_control.h>
#include <lightningd/json.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/log.h>
#include <lightningd/onion_message.h>
#include <lightningd/options.h>
#include <lightningd/ping.h>
#include <sodium/randombytes.h>
#include <string.h>
#include <wire/peer_wire.h>
#include <wire/wire_sync.h>

static void got_txout(struct bitcoind *bitcoind,
		      const struct bitcoin_tx_output *output,
		      struct short_channel_id *scid)
{
	const u8 *script;
	struct amount_sat sat;

	/* output will be NULL if it wasn't found */
	if (output) {
		script = output->script;
		sat = output->amount;
	} else {
		script = NULL;
		sat = AMOUNT_SAT(0);
	}

	subd_send_msg(
	    bitcoind->ld->gossip,
	    towire_gossipd_get_txout_reply(scid, scid, sat, script));
	tal_free(scid);
}

static void got_filteredblock(struct bitcoind *bitcoind,
		      const struct filteredblock *fb,
		      struct short_channel_id *scid)
{
	struct filteredblock_outpoint *fbo = NULL, *o;
	struct bitcoin_tx_output txo;

	/* If we failed to the filtered block we report the failure to
	 * got_txout. */
	if (fb == NULL)
		return got_txout(bitcoind, NULL, scid);

	/* Only fill in blocks that we are not going to scan later. */
	if (bitcoind->ld->topology->max_blockheight > fb->height)
		wallet_filteredblock_add(bitcoind->ld->wallet, fb);

	u32 outnum = short_channel_id_outnum(scid);
	u32 txindex = short_channel_id_txnum(scid);
	for (size_t i=0; i<tal_count(fb->outpoints); i++) {
		o = fb->outpoints[i];
		if (o->txindex == txindex && o->outnum == outnum) {
			fbo = o;
			break;
		}
	}

	if (fbo) {
		txo.amount = fbo->amount;
		txo.script = (u8 *)fbo->scriptPubKey;
		got_txout(bitcoind, &txo, scid);
	} else
		got_txout(bitcoind, NULL, scid);
}

static void get_txout(struct subd *gossip, const u8 *msg)
{
	struct short_channel_id *scid = tal(gossip, struct short_channel_id);
	struct outpoint *op;
	u32 blockheight;
	struct chain_topology *topo = gossip->ld->topology;

	if (!fromwire_gossipd_get_txout(msg, scid))
		fatal("Gossip gave bad GOSSIP_GET_TXOUT message %s",
		      tal_hex(msg, msg));

	/* FIXME: Block less than 6 deep? */
	blockheight = short_channel_id_blocknum(scid);

	op = wallet_outpoint_for_scid(gossip->ld->wallet, scid, scid);

	if (op) {
		subd_send_msg(gossip,
			      towire_gossipd_get_txout_reply(
				  scid, scid, op->sat, op->scriptpubkey));
		tal_free(scid);
	} else if (wallet_have_block(gossip->ld->wallet, blockheight)) {
		/* We should have known about this outpoint since its header
		 * is in the DB. The fact that we don't means that this is
		 * either a spent outpoint or an invalid one. Return a
		 * failure. */
		subd_send_msg(gossip, take(towire_gossipd_get_txout_reply(
						   NULL, scid, AMOUNT_SAT(0), NULL)));
		tal_free(scid);
	} else {
		bitcoind_getfilteredblock(topo->bitcoind, short_channel_id_blocknum(scid), got_filteredblock, scid);
	}
}

static unsigned gossip_msg(struct subd *gossip, const u8 *msg, const int *fds)
{
	enum gossipd_wire t = fromwire_peektype(msg);

	switch (t) {
	/* These are messages we send, not them. */
	case WIRE_GOSSIPD_INIT:
	case WIRE_GOSSIPD_PING:
	case WIRE_GOSSIPD_GET_STRIPPED_CUPDATE:
	case WIRE_GOSSIPD_GET_TXOUT_REPLY:
	case WIRE_GOSSIPD_OUTPOINT_SPENT:
	case WIRE_GOSSIPD_DEV_SET_MAX_SCIDS_ENCODE_SIZE:
	case WIRE_GOSSIPD_DEV_SUPPRESS:
	case WIRE_GOSSIPD_LOCAL_CHANNEL_CLOSE:
	case WIRE_GOSSIPD_DEV_MEMLEAK:
	case WIRE_GOSSIPD_DEV_COMPACT_STORE:
	case WIRE_GOSSIPD_DEV_SET_TIME:
	case WIRE_GOSSIPD_NEW_BLOCKHEIGHT:
	case WIRE_GOSSIPD_SEND_ONIONMSG:
	case WIRE_GOSSIPD_ADDGOSSIP:
	/* This is a reply, so never gets through to here. */
	case WIRE_GOSSIPD_INIT_REPLY:
	case WIRE_GOSSIPD_DEV_MEMLEAK_REPLY:
	case WIRE_GOSSIPD_DEV_COMPACT_STORE_REPLY:
	case WIRE_GOSSIPD_GET_STRIPPED_CUPDATE_REPLY:
	case WIRE_GOSSIPD_ADDGOSSIP_REPLY:
		break;

	case WIRE_GOSSIPD_GOT_ONIONMSG_TO_US:
		handle_onionmsg_to_us(gossip->ld, msg);
		break;
	case WIRE_GOSSIPD_GOT_ONIONMSG_FORWARD:
		handle_onionmsg_forward(gossip->ld, msg);
		break;
	case WIRE_GOSSIPD_PING_REPLY:
		ping_reply(gossip, msg);
		break;

	case WIRE_GOSSIPD_GET_TXOUT:
		get_txout(gossip, msg);
		break;
	}
	return 0;
}

void gossip_notify_new_block(struct lightningd *ld, u32 blockheight)
{
	/* Only notify gossipd once we're synced. */
	if (!topology_synced(ld->topology))
		return;

	subd_send_msg(ld->gossip,
		      take(towire_gossipd_new_blockheight(NULL, blockheight)));
}

static void gossip_topology_synced(struct chain_topology *topo, void *unused)
{
	/* Now we start telling gossipd about blocks. */
	gossip_notify_new_block(topo->ld, get_block_height(topo));
}

/* We make sure gossipd is started before plugins (which may want gossip_map) */
static void gossipd_init_done(struct subd *gossipd,
			      const u8 *msg,
			      const int *fds,
			      void *unused)
{
	/* Break out of loop, so we can begin */
	io_break(gossipd);
}

/* Create the `gossipd` subdaemon and send the initialization
 * message */
void gossip_init(struct lightningd *ld, int connectd_fd)
{
	u8 *msg;
	int hsmfd;

	hsmfd = hsm_get_global_fd(ld, HSM_CAP_ECDH|HSM_CAP_SIGN_GOSSIP);

	ld->gossip = new_global_subd(ld, "lightning_gossipd",
				     gossipd_wire_name, gossip_msg,
				     take(&hsmfd), take(&connectd_fd), NULL);
	if (!ld->gossip)
		err(1, "Could not subdaemon gossip");

	/* We haven't started topology yet, so tell us when we're synced. */
	topology_add_sync_waiter(ld->gossip, ld->topology,
				 gossip_topology_synced, NULL);

	msg = towire_gossipd_init(
	    NULL,
	    chainparams,
	    ld->our_features,
	    &ld->id,
	    ld->rgb,
	    ld->alias,
	    ld->announcable,
	    IFDEV(ld->dev_gossip_time ? &ld->dev_gossip_time: NULL, NULL),
	    IFDEV(ld->dev_fast_gossip, false),
	    IFDEV(ld->dev_fast_gossip_prune, false));

	subd_req(ld->gossip, ld->gossip, take(msg), -1, 0,
		 gossipd_init_done, NULL);

	/* Wait for gossipd_init_reply */
	io_loop(NULL, NULL);
}

void gossipd_notify_spend(struct lightningd *ld,
			  const struct short_channel_id *scid)
{
	u8 *msg = towire_gossipd_outpoint_spent(tmpctx, scid);
	subd_send_msg(ld->gossip, msg);
}

/* Called upon receiving a addgossip_reply from `gossipd` */
static void json_addgossip_reply(struct subd *gossip UNUSED, const u8 *reply,
				 const int *fds UNUSED,
				 struct command *cmd)
{
	char *err;

	if (!fromwire_gossipd_addgossip_reply(reply, reply, &err)) {
		/* Shouldn't happen: just end json stream. */
		log_broken(cmd->ld->log,
			   "Invalid addgossip_reply from gossipd: %s",
			   tal_hex(tmpctx, reply));
		was_pending(command_fail(cmd, LIGHTNINGD,
					 "Invalid reply from gossipd"));
		return;
	}

	if (strlen(err))
		was_pending(command_fail(cmd, LIGHTNINGD, "%s", err));
	else
		was_pending(command_success(cmd, json_stream_success(cmd)));
}

static struct command_result *json_addgossip(struct command *cmd,
					     const char *buffer,
					     const jsmntok_t *obj UNNEEDED,
					     const jsmntok_t *params)
{
	u8 *req, *gossip_msg;
	if (!param(cmd, buffer, params,
		   p_req("message", param_bin_from_hex, &gossip_msg),
		   NULL))
		return command_param_failed();

	req = towire_gossipd_addgossip(cmd, gossip_msg);
	subd_req(cmd->ld->gossip, cmd->ld->gossip,
		 req, -1, 0, json_addgossip_reply, cmd);

	return command_still_pending(cmd);
}

static const struct json_command addgossip_command = {
	"addgossip",
	"utility",
	json_addgossip,
	"Inject gossip {message} into gossipd"
};
AUTODATA(json_command, &addgossip_command);

#if DEVELOPER
static struct command_result *
json_dev_set_max_scids_encode_size(struct command *cmd,
				   const char *buffer,
				   const jsmntok_t *obj UNNEEDED,
				   const jsmntok_t *params)
{
	u8 *msg;
	u32 *max;

	if (!param(cmd, buffer, params,
		   p_req("max", param_number, &max),
		   NULL))
		return command_param_failed();

	msg = towire_gossipd_dev_set_max_scids_encode_size(NULL, *max);
	subd_send_msg(cmd->ld->gossip, take(msg));

	return command_success(cmd, json_stream_success(cmd));
}

static const struct json_command dev_set_max_scids_encode_size = {
	"dev-set-max-scids-encode-size",
	"developer",
	json_dev_set_max_scids_encode_size,
	"Set {max} bytes of short_channel_ids per reply_channel_range"
};
AUTODATA(json_command, &dev_set_max_scids_encode_size);

static struct command_result *json_dev_suppress_gossip(struct command *cmd,
						       const char *buffer,
						       const jsmntok_t *obj UNNEEDED,
						       const jsmntok_t *params)
{
	if (!param(cmd, buffer, params, NULL))
		return command_param_failed();

	subd_send_msg(cmd->ld->gossip, take(towire_gossipd_dev_suppress(NULL)));

	return command_success(cmd, json_stream_success(cmd));
}

static const struct json_command dev_suppress_gossip = {
	"dev-suppress-gossip",
	"developer",
	json_dev_suppress_gossip,
	"Stop this node from sending any more gossip."
};
AUTODATA(json_command, &dev_suppress_gossip);

static void dev_compact_gossip_store_reply(struct subd *gossip UNUSED,
					   const u8 *reply,
					   const int *fds UNUSED,
					   struct command *cmd)
{
	bool success;

	if (!fromwire_gossipd_dev_compact_store_reply(reply, &success)) {
		was_pending(command_fail(cmd, LIGHTNINGD,
					 "Gossip gave bad dev_gossip_compact_store_reply"));
		return;
	}

	if (!success)
		was_pending(command_fail(cmd, LIGHTNINGD,
					 "gossip_compact_store failed"));
	else
		was_pending(command_success(cmd, json_stream_success(cmd)));
}

static struct command_result *json_dev_compact_gossip_store(struct command *cmd,
							    const char *buffer,
							    const jsmntok_t *obj UNNEEDED,
							    const jsmntok_t *params)
{
	u8 *msg;
	if (!param(cmd, buffer, params, NULL))
		return command_param_failed();

	msg = towire_gossipd_dev_compact_store(NULL);
	subd_req(cmd->ld->gossip, cmd->ld->gossip,
		 take(msg), -1, 0, dev_compact_gossip_store_reply, cmd);
	return command_still_pending(cmd);
}

static const struct json_command dev_compact_gossip_store = {
	"dev-compact-gossip-store",
	"developer",
	json_dev_compact_gossip_store,
	"Ask gossipd to rewrite the gossip store."
};
AUTODATA(json_command, &dev_compact_gossip_store);

static struct command_result *json_dev_gossip_set_time(struct command *cmd,
						       const char *buffer,
						       const jsmntok_t *obj UNNEEDED,
						       const jsmntok_t *params)
{
	u8 *msg;
	u32 *time;

	if (!param(cmd, buffer, params,
		   p_req("time", param_number, &time),
		   NULL))
		return command_param_failed();

	msg = towire_gossipd_dev_set_time(NULL, *time);
	subd_send_msg(cmd->ld->gossip, take(msg));

	return command_success(cmd, json_stream_success(cmd));
}

static const struct json_command dev_gossip_set_time = {
	"dev-gossip-set-time",
	"developer",
	json_dev_gossip_set_time,
	"Ask gossipd to update the current time."
};
AUTODATA(json_command, &dev_gossip_set_time);
#endif /* DEVELOPER */
