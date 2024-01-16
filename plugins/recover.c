#include "config.h"
#include <ccan/array_size/array_size.h>
#include <common/features.h>
#include <common/gossmap.h>
#include <common/hsm_encryption.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <common/type_to_string.h>
#include <errno.h>
#include <plugins/libplugin.h>
#include <unistd.h>

static struct plugin *plugin;
static struct plugin_timer *lost_state_timer;
/* This tells if we are already in the process of recovery. */
static bool recovery, already_has_peers;
static void do_check_lost_peer (void *unused);
static struct node_id local_id;

/* List of most connected nodes on the network */
static const char *nodes_for_gossip[] = {
	"03864ef025fde8fb587d989186ce6a4a186895ee44a926bfc370e2c366597a3f8f@3.33.236.230", //ACINQ
	"035e4ff418fc8b5554c5d9eea66396c227bd429a3251c8cbc711002ba215bfc226@170.75.163.209", //WalletOfSatoshi
	"0217890e3aad8d35bc054f43acc00084b25229ecff0ab68debd82883ad65ee8266@23.237.77.11", //1ML.com node ALPHA
	"0242a4ae0c5bef18048fbecf995094b74bfb0f7391418d71ed394784373f41e4f3@3.124.63.44", //CoinGate
	"0364913d18a19c671bb36dd04d6ad5be0fe8f2894314c36a9db3f03c2d414907e1@192.243.215.102", //LQwD-Canada
	"02f1a8c87607f415c8f22c00593002775941dea48869ce23096af27b0cfdcc0b69@52.13.118.208", //Kraken ≡ƒÉÖΓÜí
	"037659a0ac8eb3b8d0a720114efc861d3a940382dcfa1403746b4f8f6b2e8810ba@34.78.139.195" //nicehash-ln1
	"024b9a1fa8e006f1e3937f65f66c408e6da8e1ca728ea43222a7381df1cc449605@165.232.168.69", //BLUEIRON-v23.08.1
	"034ea80f8b148c750463546bd999bf7321a0e6dfc60aaf84bd0400a2e8d376c0d5@213.174.156.66", //LNBiG Hub-1
	"026165850492521f4ac8abd9bd8088123446d126f648ca35e60f88177dc149ceb2@45.86.229.190", //Boltz
};


static struct command_result *connect_success(struct command *cmd,
					      const char *buf,
					      const jsmntok_t *params,
					      void *cb_arg UNUSED)
{
        plugin_log(plugin, LOG_DBG, "Connected sucessfully!");
	return command_still_pending(cmd);
}

static struct command_result *connect_fail(struct command *cmd,
					   const char *buf,
					   const jsmntok_t *params,
					   void *cb_arg UNUSED)
{
        plugin_log(plugin, LOG_DBG, "Failed to connect!");
	return command_still_pending(cmd);
}

static struct command_result *after_emergency_recover(struct command *cmd,
					   	      const char *buf,
					   	      const jsmntok_t *params,
					   	      void *cb_arg UNUSED)
{
	/* TODO: CREATE GOSSMAP, connect to old peers and fetch peer storage */
	plugin_log(plugin, LOG_DBG, "emergencyrecover called");
	return command_still_pending(cmd);
}


static void entering_recovery_mode(struct command *cmd)
{
	if(!already_has_peers) {
		for (size_t i = 0; i < ARRAY_SIZE(nodes_for_gossip); i++) {
			struct out_req *req;
			req = jsonrpc_request_start(plugin,
						    cmd,
						    "connect",
						    connect_success,
						    connect_fail,
						    NULL);
			plugin_log (plugin, LOG_DBG, "Connecting to %s", nodes_for_gossip[i]);
			json_add_string(req->js, "id", nodes_for_gossip[i]);
			send_outreq(plugin, req);
		}
	}

	struct out_req *req_emer_recovery;

	/* Let's try to recover whatever we have in the emergencyrecover file. */
	req_emer_recovery = jsonrpc_request_start(plugin,
						  cmd,
						  "emergencyrecover",
						  after_emergency_recover,
						  &forward_error,
						  NULL);

	send_outreq(plugin, req_emer_recovery);
	return;
}

static struct command_result *after_listpeerchannels(struct command *cmd,
					             const char *buf,
					             const jsmntok_t *params,
					             void *cb_arg UNUSED)
{
	plugin_log(plugin, LOG_DBG, "Listpeerchannels called");
	const jsmntok_t *iter, *lost_statetok;
	const jsmntok_t *channelstok = json_get_member(buf, params, "channels");
	size_t i;
	bool lost_state;

	json_for_each_arr(i, iter, channelstok) {
		lost_statetok = json_get_member(buf, iter, "lost_state");
		if (lost_statetok) {
			json_to_bool(buf, lost_statetok, &lost_state);

			if (lost_state) {
				plugin_log(plugin, LOG_DBG, "Detected a channel with lost state, Entering Recovery mode!");
				recovery = true;
				break;
			}
		}
	}

	if (recovery) {
		entering_recovery_mode(cmd);
		return command_still_pending(cmd);
	}

	lost_state_timer = plugin_timer(plugin, time_from_sec(2), do_check_lost_peer, NULL);
	return command_still_pending(cmd);
}

static struct command_result *check_lost_peer(void *unused)
{
	struct out_req *req;
	req = jsonrpc_request_start(plugin, NULL, "listpeerchannels",
					after_listpeerchannels,
					&forward_error, NULL);

	return send_outreq(plugin, req);
}

static void do_check_lost_peer (void *unused)
{

	/* Set to NULL when already in progress. */
	lost_state_timer = NULL;

	if (recovery) {
		return;
	}

	check_lost_peer(unused);
}

static const char *init(struct plugin *p,
			const char *buf UNUSED,
			const jsmntok_t *config UNUSED)
{
	plugin = p;
	plugin_log(p, LOG_DBG, "Recover Plugin Initialised!");
	recovery = false;
	lost_state_timer = plugin_timer(plugin, time_from_sec(2), do_check_lost_peer, NULL);
	u32 num_peers;

	/* Find number of peers */
	rpc_scan(p, "getinfo",
		 take(json_out_obj(NULL, NULL, NULL)),
		 "{id:%,num_peers:%}",
		 JSON_SCAN(json_to_node_id, &local_id),
		 JSON_SCAN(json_to_u32, &num_peers));

	already_has_peers = num_peers > 1 ? 1: 0;

	return NULL;
}


int main(int argc, char *argv[])
{
        setup_locale();

	plugin_main(argv, init, PLUGIN_STATIC, true, NULL,
		    NULL, 0,
		    NULL, 0, NULL, 0,
		    NULL, 0,  /* Notification topics we publish */
		    NULL);
}

