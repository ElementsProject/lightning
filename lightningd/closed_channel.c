#include "config.h"
#include <common/json_channel_type.h>
#include <common/json_command.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <lightningd/channel.h>
#include <lightningd/closed_channel.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/lightningd.h>
#include <lightningd/peer_control.h>
#include <wallet/wallet.h>

static void json_add_closed_channel(struct json_stream *response,
				    const char *fieldname,
				    const struct closed_channel *channel)
{
	json_object_start(response, fieldname);
	if (channel->peer_id)
		json_add_node_id(response, "peer_id", channel->peer_id);
	json_add_channel_id(response, "channel_id", &channel->cid);
	if (channel->scid)
		json_add_short_channel_id(response, "short_channel_id",
					  *channel->scid);
	if (channel->alias[LOCAL] || channel->alias[REMOTE]) {
		json_object_start(response, "alias");
		if (channel->alias[LOCAL])
			json_add_short_channel_id(response, "local",
						  *channel->alias[LOCAL]);
		if (channel->alias[REMOTE])
			json_add_short_channel_id(response, "remote",
						  *channel->alias[REMOTE]);
		json_object_end(response);
	}
	json_add_string(response, "opener",
			channel->opener == LOCAL ? "local" : "remote");
	if (channel->closer != NUM_SIDES)
		json_add_string(response, "closer", channel->closer == LOCAL ?
						    "local" : "remote");

	json_add_bool(response, "private",
		      !(channel->channel_flags & CHANNEL_FLAGS_ANNOUNCE_CHANNEL));

	json_add_channel_type(response, "channel_type", channel->type);
	json_add_u64(response, "total_local_commitments",
		     channel->next_index[LOCAL] - 1);
	json_add_u64(response, "total_remote_commitments",
		     channel->next_index[REMOTE] - 1);
	json_add_u64(response, "total_htlcs_sent", channel->next_htlc_id);
	json_add_txid(response, "funding_txid", &channel->funding.txid);
	json_add_num(response, "funding_outnum", channel->funding.n);
	json_add_bool(response, "leased", channel->leased);
	if (channel->leased) {
		if (channel->opener == LOCAL)
			json_add_amount_msat(response, "funding_fee_paid_msat",
					     channel->push);
		else
			json_add_amount_msat(response, "funding_fee_rcvd_msat",
					     channel->push);
	} else if (!amount_msat_eq(channel->push, AMOUNT_MSAT(0)))
		json_add_amount_msat(response, "funding_pushed_msat",
				     channel->push);

	json_add_amount_sat_msat(response, "total_msat", channel->funding_sats);
	json_add_amount_msat(response, "final_to_us_msat", channel->our_msat);
	json_add_amount_msat(response, "min_to_us_msat",
			     channel->msat_to_us_min);
	json_add_amount_msat(response, "max_to_us_msat",
			     channel->msat_to_us_max);
	if (channel->last_tx && !invalid_last_tx(channel->last_tx)) {
		struct bitcoin_txid txid;
		bitcoin_txid(channel->last_tx, &txid);

		json_add_txid(response, "last_commitment_txid", &txid);
		json_add_amount_sat_msat(response, "last_commitment_fee_msat",
					 bitcoin_tx_compute_fee(channel->last_tx));
	}
	json_add_string(response, "close_cause",
			channel_change_state_reason_str(channel->state_change_cause));
	if (channel->last_stable_connection != 0) {
		json_add_u64(response, "last_stable_connection",
			     channel->last_stable_connection);
	}
	json_object_end(response);
}

static struct command_result *json_listclosedchannels(struct command *cmd,
						      const char *buffer,
						      const jsmntok_t *obj UNNEEDED,
						      const jsmntok_t *params)
{
	struct node_id *peer_id;
	struct json_stream *response;
	struct closed_channel **chans;

	if (!param(cmd, buffer, params,
		   p_opt("id", param_node_id, &peer_id),
		   NULL))
		return command_param_failed();

	response = json_stream_success(cmd);
	json_array_start(response, "closedchannels");

	chans = wallet_load_closed_channels(cmd, cmd->ld->wallet);
	for (size_t i = 0; i < tal_count(chans); i++) {
		if (peer_id) {
			if (!chans[i]->peer_id)
				continue;
			if (!node_id_eq(chans[i]->peer_id, peer_id))
				continue;
		}
		json_add_closed_channel(response, NULL, chans[i]);
	}
	json_array_end(response);

	return command_success(cmd, response);
}

static const struct json_command listclosedchannels_command = {
	"listclosedchannels",
	json_listclosedchannels,
	"Show historical (dead) channels."
};
AUTODATA(json_command, &listclosedchannels_command);
