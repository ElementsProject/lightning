#include "config.h"
#include <ccan/tal/str/str.h>
#include <common/json_command.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/lightningd.h>

static void json_add_datastore(struct json_stream *response,
			       const char **key, const u8 *data,
			       u64 generation)
{
	json_array_start(response, "key");
	for (size_t i = 0; i < tal_count(key); i++)
		json_add_string(response, NULL, key[i]);
	json_array_end(response);

	if (data) {
		const char *str;

		json_add_u64(response, "generation", generation);
		json_add_hex(response, "hex", data, tal_bytelen(data));
		str = utf8_str(response, data, tal_bytelen(data));
		if (str)
			json_add_string(response, "string", str);
	}
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

static struct command_result *param_list_or_string(struct command *cmd,
						   const char *name,
						   const char *buffer,
						   const jsmntok_t *tok,
						   const char ***str)
{
	if (tok->type == JSMN_ARRAY && tok->size <= 0) {
		return command_fail_badparam(cmd, name,
								buffer, tok,
								"should not be empty");
	} else if (tok->type == JSMN_ARRAY) {
		size_t i;
		const jsmntok_t *t;
		*str = tal_arr(cmd, const char *, tok->size);
		json_for_each_arr(i, t, tok) {
			if (t->type != JSMN_STRING && t->type != JSMN_PRIMITIVE)
				return command_fail_badparam(cmd, name,
							     buffer, t,
							     "should be string");
			(*str)[i] = json_strdup(*str, buffer, t);
		}
	} else if (tok->type == JSMN_STRING || tok->type == JSMN_PRIMITIVE) {
		*str = tal_arr(cmd, const char *, 1);
		(*str)[0] = json_strdup(*str, buffer, tok);
	} else
		return command_fail_badparam(cmd, name,
					     buffer, tok,
					     "should be string or array");
	return NULL;
}

static char *datastore_key_fmt(const tal_t *ctx, const char **key)
{
	char *ret = tal_strdup(ctx, "[");
	for (size_t i = 0; i < tal_count(key); i++)
		tal_append_fmt(&ret, "%s%s", i ? "," : "", key[i]);
	tal_append_fmt(&ret, "]");
	return ret;
}

static struct command_result *json_datastore(struct command *cmd,
					     const char *buffer,
					     const jsmntok_t *obj UNNEEDED,
					     const jsmntok_t *params)
{
	struct json_stream *response;
	const char **key, *strdata, **k;
	u8 *data;
	const u8 *prevdata;
	enum ds_mode *mode;
	u64 *generation, actual_gen;
	struct db_stmt *stmt;

	if (!param(cmd, buffer, params,
		   p_req("key", param_list_or_string, &key),
		   p_opt("string", param_escaped_string, &strdata),
		   p_opt("hex", param_bin_from_hex, &data),
		   p_opt_def("mode", param_mode, &mode, DS_MUST_NOT_EXIST),
		   p_opt("generation", param_u64, &generation),
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

	if (generation && !(*mode & DS_MUST_EXIST))
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "generation only valid with must-replace"
				    " or must-append");

	/* Fetch, and make sure we don't have children! */
	stmt = wallet_datastore_first(cmd, cmd->ld->wallet, key,
				      &k, &prevdata, &actual_gen);
	tal_free(stmt);

	/* We use prevdata as a "does it exist?" flag */
	if (!stmt)
		prevdata = NULL;
	else if (!datastore_key_eq(k, key)) {
		prevdata = tal_free(prevdata);
		/* Make sure we don't have a child! */
		if (datastore_key_startswith(k, key))
			return command_fail(cmd, DATASTORE_UPDATE_HAS_CHILDREN,
					    "Key has children already");
	}

	/* We have to make sure that parents don't exist. */
	if (!prevdata) {
		for (size_t i = 1; i < tal_count(key); i++) {
			const char **parent;
			parent = tal_dup_arr(cmd, const char *, key, i, 0);
			if (wallet_datastore_get(cmd, cmd->ld->wallet, parent,
						 NULL)) {
				return command_fail(cmd,
						    DATASTORE_UPDATE_NO_CHILDREN,
						    "Parent key %s exists",
						    datastore_key_fmt(tmpctx,
								      parent));
			}
		}
	}

	if ((*mode & DS_MUST_NOT_EXIST) && prevdata)
		return command_fail(cmd, DATASTORE_UPDATE_ALREADY_EXISTS,
				    "Key already exists");

	if ((*mode & DS_MUST_EXIST) && !prevdata)
		return command_fail(cmd, DATASTORE_UPDATE_DOES_NOT_EXIST,
				    "Key does not exist");

	if (generation && actual_gen != *generation)
		return command_fail(cmd, DATASTORE_UPDATE_WRONG_GENERATION,
				    "generation is different");

	if ((*mode & DS_APPEND) && prevdata) {
		size_t prevlen = tal_bytelen(prevdata);
		u8 *newdata = tal_arr(cmd, u8, prevlen + tal_bytelen(data));
		memcpy(newdata, prevdata, prevlen);
		memcpy(newdata + prevlen, data, tal_bytelen(data));
		data = newdata;
	}

	if (prevdata) {
		wallet_datastore_update(cmd->ld->wallet, key, data);
		actual_gen++;
	} else {
		wallet_datastore_create(cmd->ld->wallet, key, data);
		actual_gen = 0;
	}

	response = json_stream_success(cmd);
	json_add_datastore(response, key, data, actual_gen);
	return command_success(cmd, response);
}

static struct command_result *json_listdatastore(struct command *cmd,
						 const char *buffer,
						 const jsmntok_t *obj UNNEEDED,
						 const jsmntok_t *params)
{
	struct json_stream *response;
	const char **key, **k, **prev_k = NULL;
	const u8 *data;
	u64 generation;
	struct db_stmt *stmt;

	if (!param(cmd, buffer, params,
		   p_opt("key", param_list_or_string, &key),
		   NULL))
		return command_param_failed();

	if (key)
		log_debug(cmd->ld->log, "Looking for %s",
			  datastore_key_fmt(tmpctx, key));

	response = json_stream_success(cmd);
	json_array_start(response, "datastore");

	for (stmt = wallet_datastore_first(cmd, cmd->ld->wallet, key,
					   &k, &data, &generation);
	     stmt;
	     stmt = wallet_datastore_next(cmd, key,
					  stmt, &k, &data,
					  &generation)) {
		log_debug(cmd->ld->log, "Got %s",
			  datastore_key_fmt(tmpctx, k));

		/* Don't list sub-children, except as summary to show it exists. */
		if (tal_count(k) > tal_count(key) + 1) {
			log_debug(cmd->ld->log, "Too long");
			if (!prev_k || !datastore_key_startswith(k, prev_k)) {
				prev_k = tal_dup_arr(cmd, const char *, k,
						     tal_count(key) + 1, 0);
				json_object_start(response, NULL);
				json_add_datastore(response, prev_k, NULL, 0);
				json_object_end(response);
			}
		} else {
			log_debug(cmd->ld->log, "Printing");
			json_object_start(response, NULL);
			json_add_datastore(response, k, data, generation);
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
	const char **key;
	const u8 *data;
	u64 *generation;
	u64 actual_gen;

	if (!param(cmd, buffer, params,
		   p_req("key", param_list_or_string, &key),
		   p_opt("generation", param_u64, &generation),
		   NULL))
		return command_param_failed();

	data = wallet_datastore_get(cmd, cmd->ld->wallet, key, &actual_gen);
	if (!data) {
		return command_fail(cmd, DATASTORE_DEL_DOES_NOT_EXIST,
				    "Key does not exist");
	}
	if (generation && actual_gen != *generation)
		return command_fail(cmd, DATASTORE_DEL_WRONG_GENERATION,
				    "generation is different");

	wallet_datastore_remove(cmd->ld->wallet, key);

	response = json_stream_success(cmd);
	json_add_datastore(response, key, data, actual_gen);
	return command_success(cmd, response);
}

static struct command_result *json_datastoreusage(struct command *cmd,
						 const char *buffer,
						 const jsmntok_t *obj UNNEEDED,
						 const jsmntok_t *params)
{
	struct json_stream *response;
	const char **k, **key;
	struct db_stmt *stmt;
	const u8 *data;
	u64 gen, total_bytes = 0;

	if (!param(cmd, buffer, params,
		   p_opt("key", param_list_or_string, &key),
		   NULL))
		return command_param_failed();

	// We ignore an empty key string or key array.
	if (key && *key[0] == '\0')
		key = NULL;

	response = json_stream_success(cmd);
	json_object_start(response, "datastoreusage");
	json_add_string(response, "key", datastore_key_fmt(tmpctx, key));

	for (stmt = wallet_datastore_first(cmd, cmd->ld->wallet, key,
					   &k, &data, &gen);
	     stmt;
	     stmt = wallet_datastore_next(cmd, key, stmt,
	     				  &k, &data, &gen)) {

		u64 self_bytes = tal_bytelen(data);
		/* The key is stored as a binary blob where each string is separated by
		 * a '\0'. Therefore we add an additional `len(k) - 1`. k is the primary
		 * key of the table and can not be NULL */
		self_bytes += tal_count(k) - 1;
		for (size_t i = 0; i < tal_count(k); i++) {
			self_bytes += strlen(k[i]);
		};
		total_bytes += self_bytes;
	};
	tal_free(stmt);

	json_add_u64(response, "total_bytes", total_bytes);
	json_object_end(response);

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

static const struct json_command datastoreusage_command = {
	"datastoreusage",
	"utility",
	json_datastoreusage,
	"List the datastore usage, starting from an optional {key}",
};
AUTODATA(json_command, &datastoreusage_command);
