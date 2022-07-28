#include "config.h"
#include <ccan/array_size/array_size.h>
#include <ccan/crypto/siphash24/siphash24.h>
#include <ccan/htable/htable_type.h>
#include <ccan/json_escape/json_escape.h>
#include <ccan/json_out/json_out.h>
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
};

static struct plugin *plugin;
static struct commando **outgoing_commands;
static struct commando **incoming_commands;
static u64 *rune_counter;
static struct rune *master_rune;

struct usage {
	/* If you really issue more than 2^32 runes, they'll share ratelimit buckets */
	u32 id;
	u32 counter;
};

static u64 usage_id(const struct usage *u)
{
	return u->id;
}

static size_t id_hash(u64 id)
{
	return siphash24(siphash_seed(), &id, sizeof(id));
}

static bool usage_eq_id(const struct usage *u, u64 id)
{
	return u->id == id;
}
HTABLE_DEFINE_TYPE(struct usage, usage_id, id_hash, usage_eq_id, usage_table);
static struct usage_table usage_table;

/* Every minute we forget entries. */
static void flush_usage_table(void *unused)
{
	struct usage *u;
	struct usage_table_iter it;

	for (u = usage_table_first(&usage_table, &it);
	     u;
	     u = usage_table_next(&usage_table, &it)) {
		usage_table_delval(&usage_table, &it);
		tal_free(u);
	}

	notleak(plugin_timer(plugin, time_from_sec(60), flush_usage_table, NULL));
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

struct cond_info {
	const struct node_id *peer;
	const char *buf;
	const jsmntok_t *method;
	const jsmntok_t *params;
	STRMAP(const jsmntok_t *) cached_params;
	struct usage *usage;
};

static const char *rate_limit_check(const tal_t *ctx,
				    const struct rune *rune,
				    const struct rune_altern *alt,
				    struct cond_info *cinfo)
{
	unsigned long r;
	char *endp;
	if (alt->condition != '=')
		return "rate operator must be =";

	r = strtoul(alt->value, &endp, 10);
	if (endp == alt->value || *endp || r == 0 || r >= UINT32_MAX)
		return "malformed rate";

	/* We cache this: we only add usage counter if whole rune succeeds! */
	if (!cinfo->usage) {
		cinfo->usage = usage_table_get(&usage_table, atol(rune->unique_id));
		if (!cinfo->usage) {
			cinfo->usage = tal(plugin, struct usage);
			cinfo->usage->id = atol(rune->unique_id);
			cinfo->usage->counter = 0;
			usage_table_add(&usage_table, cinfo->usage);
		}
	}

	/* >= becuase if we allow this, counter will increment */
	if (cinfo->usage->counter >= r)
		return tal_fmt(ctx, "Rate of %lu per minute exceeded", r);
	return NULL;
}

static const char *check_condition(const tal_t *ctx,
				   const struct rune *rune,
				   const struct rune_altern *alt,
				   struct cond_info *cinfo)
{
	const jsmntok_t *ptok;

	if (streq(alt->fieldname, "time")) {
		return rune_alt_single_int(ctx, alt, time_now().ts.tv_sec);
	} else if (streq(alt->fieldname, "id")) {
		const char *id = node_id_to_hexstr(tmpctx, cinfo->peer);
		return rune_alt_single_str(ctx, alt, id, strlen(id));
	} else if (streq(alt->fieldname, "method")) {
		return rune_alt_single_str(ctx, alt,
					   cinfo->buf + cinfo->method->start,
					   cinfo->method->end - cinfo->method->start);
	} else if (streq(alt->fieldname, "pnum")) {
		return rune_alt_single_int(ctx, alt, cinfo->params->size);
	} else if (streq(alt->fieldname, "rate")) {
		return rate_limit_check(ctx, rune, alt, cinfo);
	}

	/* Rest are params looksup: generate this once! */
	if (strmap_empty(&cinfo->cached_params)) {
		const jsmntok_t *t;
		size_t i;

		if (cinfo->params->type == JSMN_OBJECT) {
			json_for_each_obj(i, t, cinfo->params) {
				char *pmemname = tal_fmt(tmpctx,
							 "pname%.*s",
							 t->end - t->start,
							 cinfo->buf + t->start);
				size_t off = strlen("pname");
				/* Remove punctuation! */
				for (size_t n = off; pmemname[n]; n++) {
					if (cispunct(pmemname[n]))
						continue;
					pmemname[off++] = pmemname[n];
				}
				pmemname[off++] = '\0';
				strmap_add(&cinfo->cached_params, pmemname, t+1);
			}
		} else if (cinfo->params->type == JSMN_ARRAY) {
			json_for_each_arr(i, t, cinfo->params) {
				char *pmemname = tal_fmt(tmpctx, "parr%zu", i);
				strmap_add(&cinfo->cached_params, pmemname, t);
			}
		}
	}

	ptok = strmap_get(&cinfo->cached_params, alt->fieldname);
	if (!ptok)
		return rune_alt_single_missing(ctx, alt);

	return rune_alt_single_str(ctx, alt,
				   cinfo->buf + ptok->start,
				   ptok->end - ptok->start);
}

static const char *check_rune(const tal_t *ctx,
			      struct commando *incoming,
			      const struct node_id *peer,
			      const char *buf,
			      const jsmntok_t *method,
			      const jsmntok_t *params,
			      const jsmntok_t *runetok)
{
	struct rune *rune;
	struct cond_info cinfo;
	const char *err;

	if (!runetok)
		return "Missing rune";

	rune = rune_from_base64n(tmpctx, buf + runetok->start,
				 runetok->end - runetok->start);
	if (!rune)
		return "Invalid rune";

	cinfo.peer = peer;
	cinfo.buf = buf;
	cinfo.method = method;
	cinfo.params = params;
	cinfo.usage = NULL;
	strmap_init(&cinfo.cached_params);
	err = rune_test(tmpctx, master_rune, rune, check_condition, &cinfo);
	/* Just in case they manage to make us speak non-JSON, escape! */
	if (err)
		err = json_escape(ctx, err)->s;

	strmap_clear(&cinfo.cached_params);

	/* If it succeeded, *now* we increment any associated usage counter. */
	if (!err && cinfo.usage)
		cinfo.usage->counter++;
	return err;
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
	if (!params || (params->type != JSMN_OBJECT && params->type != JSMN_ARRAY)) {
		commando_error(incoming, COMMANDO_ERROR_REMOTE,
			       "Params must be object or array");
		return;
	}
	rune = json_get_member(buf, toks, "rune");

	failmsg = check_rune(tmpctx, incoming, peer, buf, method, params, rune);
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

		/* FIXME: This is ugly! */
		if (params->type == JSMN_OBJECT) {
			json_object_start(req->js, "params");
			json_for_each_obj(i, t, params) {
				json_add_jsonstr(req->js,
						 json_strdup(tmpctx, buf, t),
						 json_tok_full(buf, t+1),
						 json_tok_full_len(t+1));
			}
			json_object_end(req->js);
		} else {
			assert(params->type == JSMN_ARRAY);
			json_array_start(req->js, "params");
			json_for_each_arr(i, t, params) {
				json_add_jsonstr(req->js,
						 NULL,
						 json_tok_full(buf, t),
						 json_tok_full_len(t));
			}
			json_array_end(req->js);
		}
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

	if (!rune_counter)
		return;

	incmd = find_commando(incoming_commands, peer, NULL);
	/* Don't let them buffer multiple commands: discard old. */
	if (incmd && incmd->id != idnum) {
		plugin_log(plugin, LOG_DBG, "New cmd from %s, replacing old",
			   node_id_to_hexstr(tmpctx, peer));
		incmd = tal_free(incmd);
	}

	if (!incmd) {
		incmd = tal(plugin, struct commando);
		incmd->id = idnum;
		incmd->cmd = NULL;
		incmd->peer = *peer;
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
			   node_id_to_hexstr(tmpctx, peer));
		return;
	}

	try_command(peer, idnum, incmd->contents, tal_bytelen(incmd->contents));
	tal_free(incmd);
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
	tal_free(rune);

	return send_more_cmd(cmd, NULL, NULL, outgoing);
}

static struct command_result *param_rune(struct command *cmd, const char *name,
					 const char * buffer, const jsmntok_t *tok,
					 struct rune **rune)
{
	*rune = rune_from_base64n(cmd, buffer + tok->start, tok->end - tok->start);
	if (!*rune)
		return command_fail_badparam(cmd, name, buffer, tok,
					     "should be base64 string");

	return NULL;
}

static struct rune_restr **readonly_restrictions(const tal_t *ctx)
{
	struct rune_restr **restrs = tal_arr(ctx, struct rune_restr *, 2);

	/* Any list*, get*, or summary:
	 *  method^list|method^get|method=summary
	 */
	restrs[0] = rune_restr_new(restrs);
	rune_restr_add_altern(restrs[0],
			      take(rune_altern_new(NULL,
						   "method",
						   RUNE_COND_BEGINS,
						   "list")));
	rune_restr_add_altern(restrs[0],
			      take(rune_altern_new(NULL,
						   "method",
						   RUNE_COND_BEGINS,
						   "get")));
	rune_restr_add_altern(restrs[0],
			      take(rune_altern_new(NULL,
						   "method",
						   RUNE_COND_EQUAL,
						   "summary")));
	/* But not listdatastore!
	 *  method/listdatastore
	 */
	restrs[1] = rune_restr_new(restrs);
	rune_restr_add_altern(restrs[1],
			      take(rune_altern_new(NULL,
						   "method",
						   RUNE_COND_NOT_EQUAL,
						   "listdatastore")));

	return restrs;
}

static struct command_result *param_restrictions(struct command *cmd,
						 const char *name,
						 const char *buffer,
						 const jsmntok_t *tok,
						 struct rune_restr ***restrs)
{
	if (json_tok_streq(buffer, tok, "readonly"))
		*restrs = readonly_restrictions(cmd);
	else if (tok->type == JSMN_ARRAY) {
		size_t i;
		const jsmntok_t *t;

		*restrs = tal_arr(cmd, struct rune_restr *, tok->size);
		json_for_each_arr(i, t, tok) {
			(*restrs)[i] = rune_restr_from_string(*restrs,
							      buffer + t->start,
							      t->end - t->start);
			if (!(*restrs)[i])
				return command_fail_badparam(cmd, name, buffer, t,
							     "not a valid restriction");
		}
	} else {
		*restrs = tal_arr(cmd, struct rune_restr *, 1);
		(*restrs)[0] = rune_restr_from_string(*restrs,
						      buffer + tok->start,
						      tok->end - tok->start);
		if (!(*restrs)[0])
			return command_fail_badparam(cmd, name, buffer, tok,
						     "not a valid restriction");
	}
	return NULL;
}

static struct command_result *reply_with_rune(struct command *cmd,
					      const char *buf UNUSED,
					      const jsmntok_t *result UNUSED,
					      struct rune *rune)
{
	struct json_stream *js = jsonrpc_stream_success(cmd);

	json_add_string(js, "rune", rune_to_base64(tmpctx, rune));
	json_add_string(js, "unique_id", rune->unique_id);

	if (tal_count(rune->restrs) <= 1) {
		json_add_string(js, "warning_unrestricted_rune", "WARNING: This rune has no restrictions! Anyone who has access to this rune could drain funds from your node. Be careful when giving this to apps that you don't trust. Consider using the restrictions parameter to only allow access to specific rpc methods.");
	}
	return command_finished(cmd, js);
}

static struct command_result *json_commando_rune(struct command *cmd,
						 const char *buffer,
						 const jsmntok_t *params)
{
	struct rune *rune;
	struct rune_restr **restrs;
	struct out_req *req;

	if (!param(cmd, buffer, params,
		   p_opt("rune", param_rune, &rune),
		   p_opt("restrictions", param_restrictions, &restrs),
		   NULL))
		return command_param_failed();

	if (rune) {
		for (size_t i = 0; i < tal_count(restrs); i++)
			rune_add_restr(rune, restrs[i]);
		return reply_with_rune(cmd, NULL, NULL, rune);
	}

	rune = rune_derive_start(cmd, master_rune,
				 tal_fmt(tmpctx, "%"PRIu64,
					 rune_counter ? *rune_counter : 0));
	for (size_t i = 0; i < tal_count(restrs); i++)
		rune_add_restr(rune, restrs[i]);

	/* Now update datastore, before returning rune */
	req = jsonrpc_request_start(plugin, cmd, "datastore",
				    reply_with_rune, forward_error, rune);
	json_array_start(req->js, "key");
	json_add_string(req->js, NULL, "commando");
	json_add_string(req->js, NULL, "rune_counter");
	json_array_end(req->js);
	if (rune_counter) {
		(*rune_counter)++;
		json_add_string(req->js, "mode", "must-replace");
	} else {
		/* This used to say "🌩🤯🧨🔫!" but our log filters are too strict :( */
		plugin_log(plugin, LOG_INFORM, "Commando powers enabled: BOOM!");
		rune_counter = tal(plugin, u64);
		*rune_counter = 1;
		json_add_string(req->js, "mode", "must-create");
	}
	json_add_u64(req->js, "string", *rune_counter);
	return send_outreq(plugin, req);
}

#if DEVELOPER
static void memleak_mark_globals(struct plugin *p, struct htable *memtable)
{
	memleak_remove_region(memtable, outgoing_commands, tal_bytelen(outgoing_commands));
	memleak_remove_region(memtable, incoming_commands, tal_bytelen(incoming_commands));
	memleak_remove_region(memtable, master_rune, sizeof(*master_rune));
	memleak_remove_htable(memtable, &usage_table.raw);
	if (rune_counter)
		memleak_remove_region(memtable, rune_counter, sizeof(*rune_counter));
}
#endif

static const char *init(struct plugin *p,
			const char *buf UNUSED, const jsmntok_t *config UNUSED)
{
	struct secret rune_secret;

	outgoing_commands = tal_arr(p, struct commando *, 0);
	incoming_commands = tal_arr(p, struct commando *, 0);
	usage_table_init(&usage_table);
	plugin = p;
#if DEVELOPER
	plugin_set_memleak_handler(p, memleak_mark_globals);
#endif

	rune_counter = tal(p, u64);
	if (!rpc_scan_datastore_str(plugin, "commando/rune_counter",
				    JSON_SCAN(json_to_u64, rune_counter)))
		rune_counter = tal_free(rune_counter);

	/* Old python commando used to store secret */
	if (!rpc_scan_datastore_hex(plugin, "commando/secret",
				    JSON_SCAN(json_to_secret, &rune_secret))) {
		rpc_scan(plugin, "makesecret",
			 /* $ i commando
			  * 99 0x63 0143 0b1100011 'c'
			  * 111 0x6F 0157 0b1101111 'o'
			  * 109 0x6D 0155 0b1101101 'm'
			  * 109 0x6D 0155 0b1101101 'm'
			  * 97 0x61 0141 0b1100001 'a'
			  * 110 0x6E 0156 0b1101110 'n'
			  * 100 0x64 0144 0b1100100 'd'
			  * 111 0x6F 0157 0b1101111 'o'
			  */
			 take(json_out_obj(NULL, "hex", "636F6D6D616E646F")),
			 "{secret:%}",
			 JSON_SCAN(json_to_secret, &rune_secret));
	}

	master_rune = rune_new(plugin, rune_secret.data, ARRAY_SIZE(rune_secret.data),
			       NULL);

	/* Start flush timer. */
	flush_usage_table(NULL);
	return NULL;
}

static const struct plugin_command commands[] = { {
	"commando",
	"utility",
	"Send a commando message to a direct peer, wait for response",
	"Sends {peer_id} {method} with optional {params} and {rune}",
	json_commando,
	}, {
	"commando-rune",
	"utility",
	"Create or restrict a rune",
	"Takes an optional {rune} with optional {restrictions} and returns {rune}",
	json_commando_rune,
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
