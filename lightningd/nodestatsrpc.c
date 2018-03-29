#include <ccan/autodata/autodata.h>
#include <common/json.h>
#include <lightningd/json.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/lightningd.h>
#include <wallet/wallet.h>

static void
json_add_nodestats(struct json_result *result, char const *field,
		   const struct nodestats_detail *detail)
{
	json_object_start(result, field);
	json_add_u64(result, "index", detail->index);
	json_add_pubkey(result, "nodeid", &detail->nodeid);
	json_add_u64(result, "time_first_seen", detail->time_first_seen);
	json_add_u64(result, "time_last_seen", detail->time_last_seen);
	json_add_num(result, "forwarding_failures", detail->forwarding_failures);
	json_add_num(result, "connect_failures", detail->connect_failures);
	json_add_num(result, "channel_failures", detail->channel_failures);
	json_object_end(result);
}

static void
json_listnodestats(struct command *cmd,
		   const char *buffer,
		   const jsmntok_t *params)
{
	struct wallet *wallet = cmd->ld->wallet;
	jsmntok_t *idtok;
	struct pubkey id;
	struct json_result *result;
	struct nodestats_detail detail;
	u64 it;

	if (!json_get_params(cmd, buffer, params,
			     "?id", &idtok,
			     NULL)) {
		return;
	}

	if (idtok && !json_tok_pubkey(buffer, idtok, &id)) {
		command_fail(cmd, "id is not a public key: '%.*s'",
			     idtok->end - idtok->start,
			     buffer + idtok->start);
		return;
	}

	result = new_json_result(cmd);

	json_object_start(result, NULL);
	json_array_start(result, "nodestats");
	if (idtok) {
		if (wallet_nodestats_get_by_pubkey(wallet, &detail, &id))
			json_add_nodestats(result, NULL, &detail);
		else {
			command_fail(cmd, "No statistics for node");
			return;
		}
	} else {
		for (it = wallet_nodestats_iterate(wallet, 0);
		     it != 0;
		     it = wallet_nodestats_iterate(wallet, it)) {
			wallet_nodestats_get_by_index(wallet, &detail, it);
			json_add_nodestats(result, NULL, &detail);
		}
	}
	json_array_end(result);
	json_object_end(result);

	command_success(cmd, result);
}
static const struct json_command listnodestats_command = {
	"listnodestats",
	&json_listnodestats,
	"List node statistics; show single item if given node pubkey {id}"
};
AUTODATA(json_command, &listnodestats_command);
