#include "config.h"
#include <ccan/array_size/array_size.h>
#include <ccan/tal/str/str.h>
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
};

static struct plugin *plugin;
static struct commando **outgoing_commands;
static struct commando **incoming_commands;

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
		/* We need to make a copy first time before we call back, since
		 * plugin will reuse it! */
		if (!result)
			reply->buf = tal_dup_talarr(reply, char, reply->buf);
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
	reply->buf = (char *)buf;

	/* result is contents of "error" or "response": we want top-leve
	 * object */
	reply->off = obj->start;
	reply->len = obj->end;

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

static const char *check_rune(struct commando *incoming,
			      const char *buf,
			      const jsmntok_t *method,
			      const jsmntok_t *params,
			      const jsmntok_t *rune)
{
	/* FIXME! */
	return NULL;
}

static void try_command(struct node_id *peer,
			u64 idnum,
			const u8 *msg, size_t msglen)
{
	struct commando *incoming = tal(plugin, struct commando);
	const jsmntok_t *toks, *method, *params, *rune;
	const char *buf = (const char *)msg, *failmsg;
	struct out_req *req;

	incoming->peer = *peer;
	incoming->id = idnum;

	toks = json_parse_simple(incoming, buf, msglen);
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
	if (params && params->type != JSMN_OBJECT) {
		commando_error(incoming, COMMANDO_ERROR_REMOTE,
			       "Params must be object");
		return;
	}
	rune = json_get_member(buf, toks, "rune");

	failmsg = check_rune(incoming, buf, method, params, rune);
	if (failmsg) {
		commando_error(incoming, COMMANDO_ERROR_REMOTE_AUTH,
			       "Not authorized: %s", failmsg);
		return;
	}

	/* We handle success and failure the same */
	req = jsonrpc_request_whole_object_start(plugin, NULL,
						 json_strdup(tmpctx, buf,
							     method),
						 cmd_done, incoming);
	if (params) {
		size_t i;
		const jsmntok_t *t;

		json_object_start(req->js, "params");
		/* FIXME: This is ugly! */
		json_for_each_obj(i, t, params) {
			json_add_jsonstr(req->js,
					 json_strdup(tmpctx, buf, t),
					 json_tok_full(buf, t+1),
					 json_tok_full_len(t+1));
		}
		json_object_end(req->js);
	} else {
		json_object_start(req->js, "params");
		json_object_end(req->js);
	}
	tal_free(toks);
	send_outreq(plugin, req);
}

static void handle_incmd(struct node_id *peer,
			 u64 idnum,
			 const u8 *msg, size_t msglen,
			 bool terminal)
{
	struct commando *incmd;

	incmd = find_commando(incoming_commands, peer, NULL);
	/* Don't let them buffer multiple commands: discard old. */
	if (incmd && incmd->id != idnum)
		incmd = tal_free(incmd);

	if (!incmd) {
		incmd = tal(plugin, struct commando);
		incmd->id = idnum;
		incmd->cmd = NULL;
		incmd->peer = *peer;
		incmd->contents = tal_arr(incmd, u8, 0);
		tal_arr_expand(&incoming_commands, incmd);
		tal_add_destructor2(incmd, destroy_commando, &incoming_commands);
	}

	/* 1MB should be enough for anybody! */
	append_contents(incmd, msg, msglen, 1024*1024);

	if (!terminal)
		return;

	if (!incmd->contents) {
		plugin_log(plugin, LOG_UNUSUAL, "%s: ignoring oversize request",
			   node_id_to_hexstr(tmpctx, peer));
		return;
	}

	try_command(peer, idnum, incmd->contents, tal_bytelen(incmd->contents));
}

static struct command_result *handle_reply(struct node_id *peer,
					   u64 idnum,
					   const u8 *msg, size_t msglen,
					   bool terminal)
{
	struct commando *ocmd;
	struct json_stream *res;
	const jsmntok_t *toks, *result, *err;
	const char *replystr;
	size_t i;
	const jsmntok_t *t;

	ocmd = find_commando(outgoing_commands, peer, &idnum);
	if (!ocmd) {
		plugin_log(plugin, LOG_DBG,
			   "Ignoring unexpected %s reply from %s (id %"PRIu64")",
			   terminal ? "terminal" : "partial",
			   node_id_to_hexstr(tmpctx, peer),
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

	err = json_get_member(replystr, toks, "error");
	if (err) {
		const jsmntok_t *code = json_get_member(replystr, err, "code");
		int ecode;
		const jsmntok_t *message = json_get_member(replystr, err, "message");
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
		/* FIXME: data! */
		return command_fail(ocmd->cmd, ecode, "%.*s",
				    message->end - message->start,
				    replystr + message->start);
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
			handle_incmd(&peer, idnum, msg, len,
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
	const char *rune;
	struct commando	*ocmd;
	struct outgoing *outgoing;
	char *json;
	size_t jsonlen;

	if (!param(cmd, buffer, params,
		   p_req("peer_id", param_node_id, &peer),
		   p_req("method", param_string, &method),
		   p_opt("params", param_string, &cparams),
		   p_opt("rune", param_string, &rune),
		   NULL))
		return command_param_failed();

	ocmd = tal(cmd, struct commando);
	ocmd->cmd = cmd;
	ocmd->peer = *peer;
	ocmd->contents = tal_arr(ocmd, u8, 0);
	do {
		ocmd->id = pseudorand_u64();
	} while (find_commando(outgoing_commands, NULL, &ocmd->id));
	tal_arr_expand(&outgoing_commands, ocmd);
	tal_add_destructor2(ocmd, destroy_commando, &outgoing_commands);

	json = tal_fmt(tmpctx,
		       "{\"method\":\"%s\",\"params\":%s", method,
		       cparams ? cparams : "{}");
	if (rune)
		tal_append_fmt(&json, ",\"rune\":\"%s\"", rune);
	tal_append_fmt(&json, "}");

	/* This is not a leak, but we don't keep a pointer. */
	outgoing = notleak(tal(cmd, struct outgoing));
	outgoing->peer = *peer;
	outgoing->msg_off = 0;
	/* 65000 per message gives sufficient headroom. */
	jsonlen = tal_bytelen(json)-1;
	outgoing->msgs = notleak(tal_arr(cmd, u8 *, (jsonlen + 64999) / 65000));
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

	/* Keep memleak code happy! */
	tal_free(peer);
	tal_free(method);
	tal_free(cparams);

	return send_more_cmd(cmd, NULL, NULL, outgoing);
}

#if DEVELOPER
static void memleak_mark_globals(struct plugin *p, struct htable *memtable)
{
	memleak_remove_region(memtable, outgoing_commands, tal_bytelen(outgoing_commands));
	memleak_remove_region(memtable, incoming_commands, tal_bytelen(incoming_commands));
}
#endif

static const char *init(struct plugin *p,
			const char *buf UNUSED, const jsmntok_t *config UNUSED)
{
	outgoing_commands = tal_arr(p, struct commando *, 0);
	incoming_commands = tal_arr(p, struct commando *, 0);
	plugin = p;
#if DEVELOPER
	plugin_set_memleak_handler(p, memleak_mark_globals);
#endif
	return NULL;
}

static const struct plugin_command commands[] = { {
	"commando",
	"utility",
	"Send a commando message to a direct peer, wait for response",
	"Sends {peer_id} {method} with optional {params} and {rune}",
	json_commando,
	}
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
