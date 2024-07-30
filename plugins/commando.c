#include "config.h"
#include <ccan/array_size/array_size.h>
#include <ccan/cast/cast.h>
#include <ccan/crypto/siphash24/siphash24.h>
#include <ccan/htable/htable_type.h>
#include <ccan/json_escape/json_escape.h>
#include <ccan/json_out/json_out.h>
#include <ccan/mem/mem.h>
#include <ccan/rune/rune.h>
#include <ccan/tal/str/str.h>
#include <ccan/time/time.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <common/memleak.h>
#include <common/pseudorand.h>
#include <plugins/libplugin.h>

/* We (as your local commando command) detected an error. */
#define COMMANDO_ERROR_LOCAL 0x4c4f
/* Remote (as executing your commando command) detected an error. */
#define COMMANDO_ERROR_REMOTE 0x4c50
/* Specifically: bad/missing rune */
#define COMMANDO_ERROR_REMOTE_AUTH 0x4c51

enum commando_msgtype {
	/* Requests are split across multiple CONTINUES, then TERM. */
	COMMANDO_MSG_CMD_CONTINUES = 0x4c4d,
	COMMANDO_MSG_CMD_TERM = 0x4c4f,
	/* Replies are split across multiple CONTINUES, then TERM. */
	COMMANDO_MSG_REPLY_CONTINUES = 0x594b,
	COMMANDO_MSG_REPLY_TERM = 0x594d,
};

struct commando {
	struct command *cmd;
	struct node_id peer;
	u64 id;

	/* This is set to NULL if they seem to be spamming us! */
	u8 *contents;

	/* Literal JSON token containing JSON id (including "") */
	const char *json_id;
};

static struct plugin *plugin;
static struct commando **outgoing_commands;
static struct commando **incoming_commands;

/* The minimum fields required to respond. */
static struct commando *new_commando(const tal_t *ctx,
				     struct command *cmd,
				     const struct node_id *peer,
				     u64 id)
{
	struct commando *commando = tal(ctx, struct commando);

	commando->cmd = cmd;
	commando->peer = *peer;
	commando->id = id;

	commando->contents = NULL;
	commando->json_id = NULL;

	return commando;
}

/* NULL peer: don't care about peer.  NULL id: don't care about id */
static struct commando *find_commando(struct commando **arr,
				      const struct node_id *peer,
				      const u64 *id)
{
	for (size_t i = 0; i < tal_count(arr); i++) {
		if (id && arr[i]->id != *id)
			continue;
		if (peer && !node_id_eq(&arr[i]->peer, peer))
			continue;
		return arr[i];
	}
	return NULL;
}

static void destroy_commando(struct commando *commando, struct commando ***arr)
{
	for (size_t i = 0; i < tal_count(*arr); i++) {
		if ((*arr)[i] == commando) {
			tal_arr_remove(arr, i);
			return;
		}
	}
	abort();
}

/* Append to commando->contents: set to NULL if we've over max. */
static void append_contents(struct commando *commando, const u8 *msg, size_t msglen,
			    size_t maxlen)
{
	size_t len = tal_count(commando->contents);

	if (!commando->contents)
		return;

	if (len + msglen > maxlen) {
		commando->contents = tal_free(commando->contents);
		return;
	}

	tal_resize(&commando->contents, len + msglen);
	memcpy(commando->contents + len, msg, msglen);
}

struct reply {
	struct commando *incoming;
	char *buf;
	size_t off, len;
};

/* Calls itself repeatedly: first time, result is NULL */
static struct command_result *send_response(struct command *command UNUSED,
					    const char *buf UNUSED,
					    const jsmntok_t *result,
					    struct reply *reply)
{
	size_t msglen = reply->len - reply->off;
	u8 *cmd_msg;
	enum commando_msgtype msgtype;
	struct out_req *req;

	/* Limit is 64k, but there's a little overhead */
	if (msglen > 65000) {
		msglen = 65000;
		msgtype = COMMANDO_MSG_REPLY_CONTINUES;
	} else {
		if (msglen == 0) {
			tal_free(reply);
			return command_done();
		}
		msgtype = COMMANDO_MSG_REPLY_TERM;
	}

	cmd_msg = tal_arr(NULL, u8, 0);
	towire_u16(&cmd_msg, msgtype);
	towire_u64(&cmd_msg, reply->incoming->id);
	towire(&cmd_msg, reply->buf + reply->off, msglen);
	reply->off += msglen;

	req = jsonrpc_request_start(plugin, NULL, "sendcustommsg",
				    send_response, send_response,
				    reply);
	json_add_node_id(req->js, "node_id", &reply->incoming->peer);
	json_add_hex_talarr(req->js, "msg", cmd_msg);
	tal_free(cmd_msg);
	send_outreq(plugin, req);

	return command_done();
}

static struct command_result *cmd_done(struct command *command,
				       const char *buf,
				       const jsmntok_t *obj,
				       struct commando *incoming)
{
	struct reply *reply = tal(plugin, struct reply);
	reply->incoming = tal_steal(reply, incoming);

	/* We make a copy, but substititing the original id! */
	if (incoming->json_id) {
		const char *id_start, *id_end;
		const jsmntok_t *id = json_get_member(buf, obj, "id");
		size_t off;

		/* Old id we're going to omit */
		id_start = json_tok_full(buf, id);
		id_end = id_start + json_tok_full_len(id);

		reply->len = obj->end - obj->start
			- (id_end - id_start)
			+ strlen(incoming->json_id);
		reply->buf = tal_arr(reply, char, reply->len);
		memcpy(reply->buf, buf + obj->start,
		       id_start - (buf + obj->start));
		off = id_start - (buf + obj->start);
		memcpy(reply->buf + off, incoming->json_id, strlen(incoming->json_id));
		off += strlen(incoming->json_id);
		memcpy(reply->buf + off, id_end, (buf + obj->end) - id_end);
	} else {
		reply->len = obj->end - obj->start;
		reply->buf = tal_strndup(reply, buf + obj->start, reply->len);
	}
	reply->off = 0;

	return send_response(command, NULL, NULL, reply);
}

static void commando_error(struct commando *incoming,
			   int ecode,
			   const char *fmt, ...)
	PRINTF_FMT(3,4);

static void commando_error(struct commando *incoming,
			   int ecode,
			   const char *fmt, ...)
{
	struct reply *reply = tal(plugin, struct reply);
	va_list ap;

	reply->incoming = tal_steal(reply, incoming);
	reply->buf = tal_fmt(reply, "{\"error\":{\"code\":%i,\"message\":\"", ecode);
	va_start(ap, fmt);
	tal_append_vfmt(&reply->buf, fmt, ap);
	va_end(ap);
	tal_append_fmt(&reply->buf, "\"}}");
	reply->off = 0;
	reply->len = tal_bytelen(reply->buf) - 1;

	send_response(NULL, NULL, NULL, reply);
}

struct cond_info {
	/* The commando message (and our parent!) */
	struct commando *incoming;

	/* Convenience pointer into incoming->contents */
	const char *buf;

	/* Array of tokens in buf */
	const jsmntok_t *toks;

	/* Method they asked for. */
	const jsmntok_t *method;

	/* Optional params and filter args. */
	const jsmntok_t *params;
	const jsmntok_t *filter;

	/* Prefix for commands we execute */
	const char *cmdid_prefix;
};

static struct cond_info *new_cond_info(const tal_t *ctx,
				       struct commando *incoming,
				       const jsmntok_t *toks STEALS,
				       const jsmntok_t *method,
				       const jsmntok_t *params,
				       const jsmntok_t *id,
				       const jsmntok_t *filter)
{
	struct cond_info *cinfo = tal(ctx, struct cond_info);

	cinfo->incoming = incoming;
	/* Convenience pointer, since contents is u8 */
	cinfo->buf = cast_signed(const char *, incoming->contents);
	cinfo->toks = tal_steal(cinfo, toks);
	cinfo->method = method;
	cinfo->params = params;
	cinfo->filter = filter;

	if (!id) {
		cinfo->cmdid_prefix = NULL;
		incoming->json_id = NULL;
	} else {
		cinfo->cmdid_prefix = tal_fmt(cinfo, "%.*s/",
					      id->end - id->start,
					      cinfo->buf + id->start);
		/* Includes quotes, if any! */
		incoming->json_id = tal_strndup(incoming,
						json_tok_full(cinfo->buf, id),
						json_tok_full_len(id));
	}
	return cinfo;
}

static struct command_result *execute_command(struct cond_info *cinfo)
{
	struct out_req *req;

	/* We handle success and failure the same */
	req = jsonrpc_request_whole_object_start(plugin, NULL,
						 json_strdup(tmpctx, cinfo->buf, cinfo->method),
						 cinfo->cmdid_prefix,
						 cmd_done, cinfo->incoming);
	if (cinfo->params) {
		size_t i;
		const jsmntok_t *t;

		/* FIXME: This is ugly! */
		if (cinfo->params->type == JSMN_OBJECT) {
			json_object_start(req->js, "params");
			json_for_each_obj(i, t, cinfo->params) {
				json_add_jsonstr(req->js,
						 json_strdup(tmpctx, cinfo->buf, t),
						 json_tok_full(cinfo->buf, t+1),
						 json_tok_full_len(t+1));
			}
			json_object_end(req->js);
		} else {
			assert(cinfo->params->type == JSMN_ARRAY);
			json_array_start(req->js, "params");
			json_for_each_arr(i, t, cinfo->params) {
				json_add_jsonstr(req->js,
						 NULL,
						 json_tok_full(cinfo->buf, t),
						 json_tok_full_len(t));
			}
			json_array_end(req->js);
		}
	} else {
		json_object_start(req->js, "params");
		json_object_end(req->js);
	}

	if (cinfo->filter) {
		json_add_jsonstr(req->js, "filter",
				 json_tok_full(cinfo->buf, cinfo->filter),
				 json_tok_full_len(cinfo->filter));
	}
	return send_outreq(plugin, req);
}

static struct command_result *checkrune_done(struct command *cmd,
					     const char *buf,
					     const jsmntok_t *result,
					     struct cond_info *cinfo)
{
	bool valid;
	const char *err;

	err = json_scan(cmd, buf, result, "{valid:%}",
			JSON_SCAN(json_to_bool, &valid));
	if (err) {
		plugin_err(plugin, "Invalid checkrune response (%s) %.*s",
			   err,
			   json_tok_full_len(result),
			   json_tok_full(buf, result));
	}

	/* Shouldn't happen! */
	if (!valid) {
		commando_error(cinfo->incoming, COMMANDO_ERROR_REMOTE,
			       "Invalid rune");
		return command_done();
	}

	return execute_command(cinfo);
}

static struct command_result *checkrune_failed(struct command *cmd,
					       const char *buf,
					       const jsmntok_t *result,
					       struct cond_info *cinfo)
{
	const jsmntok_t *msg = json_get_member(buf, result, "message");

	if (!msg) {
		plugin_err(plugin, "Invalid checkrune error %.*s",
			   json_tok_full_len(result),
			   json_tok_full(buf, result));
	}

	commando_error(cinfo->incoming, COMMANDO_ERROR_REMOTE_AUTH,
		       "Invalid rune: %.*s",
		       msg->end - msg->start, buf + msg->start);
	return command_done();
}

static void try_command(struct commando *incoming STEALS)
{
	const jsmntok_t *toks, *method, *params, *runetok, *id, *filter;
	const char *buf = (const char *)incoming->contents;
	struct cond_info *cinfo;
	struct rune *rune;
	struct out_req *req;

	toks = json_parse_simple(incoming, buf, tal_bytelen(buf));
	if (!toks) {
		commando_error(incoming, COMMANDO_ERROR_REMOTE,
			       "Invalid JSON");
		return;
	}

	if (toks[0].type != JSMN_OBJECT) {
		commando_error(incoming, COMMANDO_ERROR_REMOTE,
			       "Not a JSON object");
		return;
	}
	method = json_get_member(buf, toks, "method");
	if (!method) {
		commando_error(incoming, COMMANDO_ERROR_REMOTE,
			       "No method");
		return;
	}
	params = json_get_member(buf, toks, "params");
	if (params && (params->type != JSMN_OBJECT && params->type != JSMN_ARRAY)) {
		commando_error(incoming, COMMANDO_ERROR_REMOTE,
			       "Params must be object or array");
		return;
	}
	filter = json_get_member(buf, toks, "filter");
	id = json_get_member(buf, toks, "id");
	if (!id) {
		commando_error(incoming, COMMANDO_ERROR_REMOTE,
			       "missing id field");
		return;
	}
	runetok = json_get_member(buf, toks, "rune");
	if (!runetok) {
		commando_error(incoming, COMMANDO_ERROR_REMOTE, "Missing rune");
		return;
	}
	rune = rune_from_base64n(tmpctx, buf + runetok->start,
				 runetok->end - runetok->start);
	if (!rune) {
		commando_error(incoming, COMMANDO_ERROR_REMOTE, "Invalid rune");
		return;
	}
	/* Gather all the info we need to execute this command (steals toks). */
	cinfo = new_cond_info(incoming, incoming, toks, method, params, id, filter);

	/* Don't count this towards incomings anymore */
	destroy_commando(incoming, &incoming_commands);
	tal_del_destructor2(incoming, destroy_commando, &incoming_commands);

	req = jsonrpc_request_start(plugin, NULL, "checkrune",
				    checkrune_done, checkrune_failed,
				    cinfo);
	json_add_node_id(req->js, "nodeid", &incoming->peer);
	json_add_tok(req->js, "rune", runetok, cinfo->buf);
	json_add_tok(req->js, "method", method, cinfo->buf);
	if (params)
		json_add_tok(req->js, "params", params, cinfo->buf);
	send_outreq(plugin, req);
}

static void handle_incmd(struct command *cmd,
			 struct node_id *peer,
			 u64 idnum,
			 const u8 *msg, size_t msglen,
			 bool terminal)
{
	struct commando *incmd;

	incmd = find_commando(incoming_commands, peer, NULL);
	/* Don't let them buffer multiple commands: discard old. */
	if (incmd && incmd->id != idnum) {
		plugin_log(plugin, LOG_DBG, "New cmd from %s, replacing old",
			   fmt_node_id(tmpctx, peer));
		incmd = tal_free(incmd);
	}

	if (!incmd) {
		incmd = new_commando(plugin, NULL, peer, idnum);
		incmd->contents = tal_arr(incmd, u8, 0);
		tal_arr_expand(&incoming_commands, incmd);
		tal_add_destructor2(incmd, destroy_commando, &incoming_commands);

		/* More than 16 partial commands at once?  Free oldest */
		if (tal_count(incoming_commands) > 16)
			tal_free(incoming_commands[0]);
	}

	/* 1MB should be enough for anybody! */
	append_contents(incmd, msg, msglen, 1024*1024);

	if (!terminal)
		return;

	if (!incmd->contents) {
		plugin_log(plugin, LOG_UNUSUAL, "%s: ignoring oversize request",
			   fmt_node_id(tmpctx, peer));
		return;
	}

	try_command(incmd);
}

static struct command_result *handle_reply(struct node_id *peer,
					   u64 idnum,
					   const u8 *msg, size_t msglen,
					   bool terminal)
{
	struct commando *ocmd;
	struct json_stream *res;
	const jsmntok_t *toks, *result, *err, *id;
	const char *replystr;
	size_t i;
	const jsmntok_t *t;

	ocmd = find_commando(outgoing_commands, peer, &idnum);
	if (!ocmd) {
		plugin_log(plugin, LOG_DBG,
			   "Ignoring unexpected %s reply from %s (id %"PRIu64")",
			   terminal ? "terminal" : "partial",
			   fmt_node_id(tmpctx, peer),
			   idnum);
		return NULL;
	}

	/* FIXME: We buffer, but ideally we would stream! */
	/* listchannels is 71MB, so we need to allow some headroom! */
	append_contents(ocmd, msg, msglen, 500*1024*1024);

	if (!terminal)
		return NULL;

	if (!ocmd->contents)
		return command_fail(ocmd->cmd, COMMANDO_ERROR_LOCAL, "Reply was oversize");

	replystr = (const char *)ocmd->contents;
	toks = json_parse_simple(ocmd, replystr, tal_bytelen(ocmd->contents));
	if (!toks || toks[0].type != JSMN_OBJECT)
		return command_fail(ocmd->cmd, COMMANDO_ERROR_LOCAL,
				    "Reply was unparsable: '%.*s'",
				    (int)tal_bytelen(ocmd->contents), replystr);

	id = json_get_member(replystr, toks, "id");

	/* Old commando didn't reply with id, but newer should get it right! */
	if (id && !memeq(json_tok_full(replystr, id), json_tok_full_len(id),
			 ocmd->json_id, strlen(ocmd->json_id))) {
		plugin_log(plugin, LOG_BROKEN, "Commando reply with wrong id:"
			   " I sent %s, they replied with %.*s!",
			   ocmd->json_id,
			   json_tok_full_len(id), json_tok_full(replystr, id));
	}

	err = json_get_member(replystr, toks, "error");
	if (err) {
		const jsmntok_t *code = json_get_member(replystr, err, "code");
		const jsmntok_t *message = json_get_member(replystr, err, "message");
		const jsmntok_t *datatok = json_get_member(replystr, err, "data");
		struct json_out *data;
		int ecode;
		if (!code || !json_to_int(replystr, code, &ecode)) {
			return command_fail(ocmd->cmd, COMMANDO_ERROR_LOCAL,
					    "Error '%.*s' had no valid code",
					    json_tok_full_len(err),
					    json_tok_full(replystr, err));
		}
		if (!message) {
			return command_fail(ocmd->cmd, COMMANDO_ERROR_LOCAL,
					    "Error had no message");
		}
		if (datatok) {
			data = json_out_new(ocmd->cmd);
			memcpy(json_out_direct(data, json_tok_full_len(datatok)),
			       json_tok_full(replystr, datatok),
			       json_tok_full_len(datatok));
		} else
			data = NULL;

		return command_done_err(ocmd->cmd, ecode,
					json_strdup(tmpctx, replystr, message),
					data);
	}

	result = json_get_member(replystr, toks, "result");
	if (!result)
		return command_fail(ocmd->cmd, COMMANDO_ERROR_LOCAL, "Reply had no result");

	res = jsonrpc_stream_success(ocmd->cmd);

	/* FIXME: This is ugly! */
	json_for_each_obj(i, t, result) {
		json_add_jsonstr(res,
				 json_strdup(tmpctx, replystr, t),
				 json_tok_full(replystr, t+1),
				 json_tok_full_len(t+1));
	}

	return command_finished(ocmd->cmd, res);
}

static struct command_result *handle_custommsg(struct command *cmd,
					      const char *buf,
					      const jsmntok_t *params)
{
	struct node_id peer;
	const u8 *msg;
	size_t len;
	enum commando_msgtype mtype;
	u64 idnum;

	json_to_node_id(buf, json_get_member(buf, params, "peer_id"), &peer);
	msg = json_tok_bin_from_hex(cmd, buf,
				    json_get_member(buf, params, "payload"));

	len = tal_bytelen(msg);
	mtype = fromwire_u16(&msg, &len);
	idnum = fromwire_u64(&msg, &len);

	if (msg) {
		switch (mtype) {
		case COMMANDO_MSG_CMD_CONTINUES:
		case COMMANDO_MSG_CMD_TERM:
			handle_incmd(cmd, &peer, idnum, msg, len,
				     mtype == COMMANDO_MSG_CMD_TERM);
			break;
		case COMMANDO_MSG_REPLY_CONTINUES:
		case COMMANDO_MSG_REPLY_TERM:
			handle_reply(&peer, idnum, msg, len,
				     mtype == COMMANDO_MSG_REPLY_TERM);
			break;
		}
	}

	return command_hook_success(cmd);
}

static const struct plugin_hook hooks[] = {
	{
		"custommsg",
		handle_custommsg
	},
};

struct outgoing {
	struct node_id peer;
	size_t msg_off;
	u8 **msgs;
};

static struct command_result *send_more_cmd(struct command *cmd,
					    const char *buf UNUSED,
					    const jsmntok_t *result UNUSED,
					    struct outgoing *outgoing)
{
	struct out_req *req;

	if (outgoing->msg_off == tal_count(outgoing->msgs)) {
		tal_free(outgoing);
		return command_still_pending(cmd);
	}

	req = jsonrpc_request_start(plugin, cmd, "sendcustommsg",
				    send_more_cmd, forward_error, outgoing);
	json_add_node_id(req->js, "node_id", &outgoing->peer);
	json_add_hex_talarr(req->js, "msg", outgoing->msgs[outgoing->msg_off++]);

	return send_outreq(plugin, req);
}

static struct command_result *json_commando(struct command *cmd,
					    const char *buffer,
					    const jsmntok_t *params)
{
	struct node_id *peer;
	const char *method, *cparams;
	const char *rune, *filter;
	struct commando	*ocmd;
	struct outgoing *outgoing;
	char *json;
	size_t jsonlen;
	u64 oid;

	if (!param(cmd, buffer, params,
		   p_req("peer_id", param_node_id, &peer),
		   p_req("method", param_string, &method),
		   p_opt("params", param_string, &cparams),
		   p_opt("rune", param_string, &rune),
		   p_opt("filter", param_string, &filter),
		   NULL))
		return command_param_failed();

	do {
		oid = pseudorand_u64();
	} while (find_commando(outgoing_commands, NULL, &oid));

	ocmd = new_commando(cmd, cmd, peer, oid);
	ocmd->contents = tal_arr(ocmd, u8, 0);
	ocmd->json_id = tal_strdup(ocmd, cmd->id);

	tal_arr_expand(&outgoing_commands, ocmd);
	tal_add_destructor2(ocmd, destroy_commando, &outgoing_commands);

	/* We pass through their JSON id untouched. */
	json = tal_fmt(tmpctx,
		       "{\"method\":\"%s\",\"id\":%s,\"params\":%s", method,
		       ocmd->json_id, cparams ? cparams : "{}");
	if (rune)
		tal_append_fmt(&json, ",\"rune\":\"%s\"", rune);
	if (filter)
		tal_append_fmt(&json, ",\"filter\":%s", filter);
	tal_append_fmt(&json, "}");

	outgoing = tal(cmd, struct outgoing);
	outgoing->peer = *peer;
	outgoing->msg_off = 0;
	/* 65000 per message gives sufficient headroom. */
	jsonlen = tal_bytelen(json)-1;
	outgoing->msgs = tal_arr(cmd, u8 *, (jsonlen + 64999) / 65000);
	for (size_t i = 0; i < tal_count(outgoing->msgs); i++) {
		u8 *cmd_msg = tal_arr(outgoing, u8, 0);
		bool terminal = (i == tal_count(outgoing->msgs) - 1);
		size_t off = i * 65000, len;

		if (terminal)
			len = jsonlen - off;
		else
			len = 65000;

		towire_u16(&cmd_msg,
			   terminal ? COMMANDO_MSG_CMD_TERM
			   : COMMANDO_MSG_CMD_CONTINUES);
		towire_u64(&cmd_msg, ocmd->id);
		towire(&cmd_msg, json + off, len);
		outgoing->msgs[i] = cmd_msg;
	}

	return send_more_cmd(cmd, NULL, NULL, outgoing);
}

/* Handles error or success */
static struct command_result *forward_reply(struct command *cmd,
					    const char *buf,
					    const jsmntok_t *result,
					    void *arg)
{
	const jsmntok_t *err = json_get_member(buf, result, "error");
	if (err)
		return forward_error(cmd, buf, err, arg);
	return forward_result(cmd, buf, json_get_member(buf, result, "result"), arg);
}

static struct command_result *forward_command(struct command *cmd,
					      const char *buffer,
					      const jsmntok_t *params,
					      const char *method)
{
	/* params could be an array, so use low-level helper */
	struct out_req *req;

	req = jsonrpc_request_whole_object_start(plugin, cmd, method,
						 json_id_prefix(tmpctx, cmd),
						 forward_reply, NULL);
	json_add_tok(req->js, "params", params, buffer);
	return send_outreq(plugin, req);
}

static struct command_result *json_commando_rune(struct command *cmd,
						 const char *buffer,
						 const jsmntok_t *params)
{
	const char *unused1, *unused2;

	/* param call needed to generate help messages */
	if (!param(cmd, buffer, params,
		   p_opt("rune", param_string, &unused1),
		   p_opt("restrictions", param_string, &unused2),
		   NULL))
		return command_param_failed();

	return forward_command(cmd, buffer, params, "createrune");
}

static struct command_result *json_commando_blacklist(struct command *cmd,
						 const char *buffer,
						 const jsmntok_t *params)
{
	const char *unused1, *unused2;

	/* param call needed to generate help messages */
	if (!param(cmd, buffer, params,
		   p_opt("start", param_string, &unused1),
		   p_opt("end", param_string, &unused2),
		   NULL))
		return command_param_failed();

	return forward_command(cmd, buffer, params, "blacklistrune");
}

static struct command_result *json_commando_listrunes(struct command *cmd,
						 const char *buffer,
						 const jsmntok_t *params)
{
	const char *unused;

	/* param call needed to generate help messages */
	if (!param(cmd, buffer, params,
		   p_opt("rune", param_string, &unused), NULL))
		return command_param_failed();

	return forward_command(cmd, buffer, params, "showrunes");
}

static void memleak_mark_globals(struct plugin *p, struct htable *memtable)
{
	memleak_scan_obj(memtable, outgoing_commands);
	memleak_scan_obj(memtable, incoming_commands);
}

static const char *init(struct plugin *p,
			const char *buf UNUSED, const jsmntok_t *config UNUSED)
{
	outgoing_commands = tal_arr(p, struct commando *, 0);
	incoming_commands = tal_arr(p, struct commando *, 0);
	plugin = p;
	plugin_set_memleak_handler(p, memleak_mark_globals);

	return NULL;
}

static const struct plugin_command commands[] = { {
	"commando",
	json_commando,
	}, {
	"commando-rune",
	json_commando_rune,
	"v23.08",
	"v25.02",
	},
	{
	"commando-listrunes",
	json_commando_listrunes,
	"v23.08",
	"v25.02",
	},
	{
	"commando-blacklist",
	json_commando_blacklist,
	"v23.08",
	"v25.02",
	},
};

int main(int argc, char *argv[])
{
	setup_locale();
	plugin_main(argv, init, PLUGIN_STATIC, true, NULL,
		    commands, ARRAY_SIZE(commands),
	            NULL, 0,
		    hooks, ARRAY_SIZE(hooks),
		    NULL, 0,
		    NULL);
}
