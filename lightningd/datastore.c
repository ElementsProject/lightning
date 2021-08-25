#include <common/param.h>
#include <lightningd/json.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/lightningd.h>
#include <wallet/wallet.h>

static void json_add_datastore(struct json_stream *response,
			       const char *key, const u8 *data)
{
	json_add_string(response, "key", key);
	json_add_hex(response, "hex", data, tal_bytelen(data));
}

static struct command_result *json_datastore(struct command *cmd,
					     const char *buffer,
					     const jsmntok_t *obj UNNEEDED,
					     const jsmntok_t *params)
{
	struct json_stream *response;
	const char *key;
	u8 *data;

	if (!param(cmd, buffer, params,
		   p_req("key", param_string, &key),
		   p_req("hex", param_bin_from_hex, &data),
		   NULL))
		return command_param_failed();

	if (!wallet_datastore_add(cmd->ld->wallet, key, data))
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Key already exists");

	response = json_stream_success(cmd);
	json_add_datastore(response, key, data);
	return command_success(cmd, response);
}

static struct command_result *json_listdatastore(struct command *cmd,
						 const char *buffer,
						 const jsmntok_t *obj UNNEEDED,
						 const jsmntok_t *params)
{
	struct json_stream *response;
	const char *key;
	const u8 *data;

	if (!param(cmd, buffer, params,
		   p_opt("key", param_string, &key),
		   NULL))
		return command_param_failed();

	response = json_stream_success(cmd);
	json_array_start(response, "datastore");
	if (key) {
		data = wallet_datastore_fetch(cmd, cmd->ld->wallet, key);
		if (data) {
			json_object_start(response, NULL);
			json_add_datastore(response, key, data);
			json_object_end(response);
		}
	} else {
		struct db_stmt *stmt;

		for (stmt = wallet_datastore_first(cmd, cmd->ld->wallet,
						   &key, &data);
		     stmt;
		     stmt = wallet_datastore_next(cmd, cmd->ld->wallet,
						  stmt, &key, &data)) {
			json_object_start(response, NULL);
			json_add_datastore(response, key, data);
			json_object_end(response);
		}
	}
	json_array_end(response);
	return command_success(cmd, response);
}

static struct command_result *json_deldatastore(struct command *cmd,
						 const char *buffer,
						 const jsmntok_t *obj UNNEEDED,
						 const jsmntok_t *params)
{
	struct json_stream *response;
	const char *key;
	u8 *data;

	if (!param(cmd, buffer, params,
		   p_req("key", param_string, &key),
		   NULL))
		return command_param_failed();

	data = wallet_datastore_remove(cmd, cmd->ld->wallet, key);
	if (!data)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Key does not exist");

	response = json_stream_success(cmd);
	json_add_datastore(response, key, data);
	return command_success(cmd, response);
}

static const struct json_command datastore_command = {
	"datastore",
	"utility",
	json_datastore,
	"Add a {key} and {hex} data to the data store",
};
AUTODATA(json_command, &datastore_command);

static const struct json_command deldatastore_command = {
	"deldatastore",
	"utility",
	json_deldatastore,
	"Remove a {key} from the data store",
};
AUTODATA(json_command, &deldatastore_command);

static const struct json_command listdatastore_command = {
	"listdatastore",
	"utility",
	json_listdatastore,
	"List the datastore, optionally only {key}",
};
AUTODATA(json_command, &listdatastore_command);
