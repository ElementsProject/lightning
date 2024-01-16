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

static void entering_recovery_mode(struct command *cmd) {
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

static struct command_result *check_lost_peer(void *unused) {
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

	already_has_peers = num_peers > 2 ? 1: 0;

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

