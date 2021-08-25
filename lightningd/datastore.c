#include <common/param.h>
#include <lightningd/json.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/lightningd.h>
#include <wallet/wallet.h>

static void json_add_datastore(struct json_stream *response,
			       const char *key, const u8 *data)
{
	const char *str;
	json_add_string(response, "key", key);
	json_add_hex(response, "hex", data, tal_bytelen(data));
	str = utf8_str(response, data, tal_bytelen(data));
	if (str)
		json_add_string(response, "string", str);
}

enum ds_mode {
	DS_MUST_EXIST = 1,
	DS_MUST_NOT_EXIST = 2,
	DS_APPEND = 4
};

static struct command_result *param_mode(struct command *cmd,
					 const char *name,
					 const char *buffer,
					 const jsmntok_t *tok,
					 enum ds_mode **mode)
{
	*mode = tal(cmd, enum ds_mode);
	if (json_tok_streq(buffer, tok, "must-create"))
		**mode = DS_MUST_NOT_EXIST;
	else if (json_tok_streq(buffer, tok, "must-replace"))
		**mode = DS_MUST_EXIST;
	else if (json_tok_streq(buffer, tok, "create-or-replace"))
		**mode = 0;
	else if (json_tok_streq(buffer, tok, "must-append"))
		**mode = DS_MUST_EXIST | DS_APPEND;
	else if (json_tok_streq(buffer, tok, "create-or-append"))
		**mode = DS_APPEND;
	else
		return command_fail_badparam(cmd, name, buffer, tok,
					     "should be 'must-create',"
					     " 'must-replace',"
					     " 'create-or-replace',"
					     " 'must-append',"
					     " or 'create-or-append'");

	return NULL;
}

static struct command_result *json_datastore(struct command *cmd,
					     const char *buffer,
					     const jsmntok_t *obj UNNEEDED,
					     const jsmntok_t *params)
{
	struct json_stream *response;
	const char *key, *strdata;
	u8 *data, *prevdata;
	enum ds_mode *mode;

	if (!param(cmd, buffer, params,
		   p_req("key", param_string, &key),
		   p_opt("string", param_string, &strdata),
		   p_opt("hex", param_bin_from_hex, &data),
		   p_opt_def("mode", param_mode, &mode, DS_MUST_NOT_EXIST),
		   NULL))
		return command_param_failed();

	if (strdata) {
		if (data)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Cannot have both hex and string");
		data = tal_dup_arr(cmd, u8, (u8 *)strdata, strlen(strdata), 0);
	} else {
		if (!data)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Must have either hex or string");
	}

	prevdata = wallet_datastore_fetch(cmd, cmd->ld->wallet, key);
	if ((*mode & DS_MUST_NOT_EXIST) && prevdata)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Key already exists");

	if ((*mode & DS_MUST_EXIST) && !prevdata)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Key does not exist");

	if ((*mode & DS_APPEND) && prevdata) {
		size_t prevlen = tal_bytelen(prevdata);
		tal_resize(&prevdata, prevlen + tal_bytelen(data));
		memcpy(prevdata + prevlen, data, tal_bytelen(data));
		data = prevdata;
	}

	if (prevdata)
		wallet_datastore_update(cmd->ld->wallet, key, data);
	else
		wallet_datastore_create(cmd->ld->wallet, key, data);

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
	"Add a {key} and {hex}/{string} data to the data store",
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
