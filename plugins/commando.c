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

struct blacklist {
	u64 start, end;
};

static struct plugin *plugin;
static struct commando **outgoing_commands;
static struct commando **incoming_commands;
static u64 *rune_counter;
static struct rune *master_rune;
static struct blacklist *blacklist;

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
static struct usage_table *usage_table;

/* The unique id is embedded with a special restriction with an empty field name */
static bool is_unique_id(struct rune_restr **restrs, unsigned int index)
{
	/* must be the first restriction */
	if (index != 0)
		return false;

	/* Must be the only alternative */
	if (tal_count(restrs[index]->alterns) != 1)
		return false;

	/* Must have an empty field name */
	return streq(restrs[index]->alterns[0]->fieldname, "");
}

static char *rune_altern_to_english(const tal_t *ctx, const struct rune_altern *alt)
{
	const char *cond_str;
	switch (alt->condition) {
		case RUNE_COND_IF_MISSING:
			return tal_strcat(ctx, alt->fieldname, " is missing");
		case RUNE_COND_EQUAL:
			cond_str = "equal to";
			break;
		case RUNE_COND_NOT_EQUAL:
			cond_str = "unequal to";
			break;
		case RUNE_COND_BEGINS:
			cond_str = "starts with";
			break;
		case RUNE_COND_ENDS:
			cond_str = "ends with";
			break;
		case RUNE_COND_CONTAINS:
			cond_str = "contains";
			break;
		case RUNE_COND_INT_LESS:
			cond_str = "<";
			break;
		case RUNE_COND_INT_GREATER:
			cond_str = ">";
			break;
		case RUNE_COND_LEXO_BEFORE:
			cond_str = "sorts before";
			break;
		case RUNE_COND_LEXO_AFTER:
			cond_str = "sorts after";
			break;
		case RUNE_COND_COMMENT:
			return tal_fmt(ctx, "comment: %s %s", alt->fieldname, alt->value);
	}
	return tal_fmt(ctx, "%s %s %s", alt->fieldname, cond_str, alt->value);
}

static char *json_add_alternative(const tal_t *ctx,
				  struct json_stream *js,
				  const char *fieldname,
				  struct rune_altern *alternative)
{
	char *altern_english;
	altern_english = rune_altern_to_english(ctx, alternative);
	json_object_start(js, fieldname);
	json_add_string(js, "fieldname", alternative->fieldname);
	json_add_string(js, "value", alternative->value);
	json_add_stringn(js, "condition", (char *)&alternative->condition, 1);
	json_add_string(js, "english", altern_english);
	json_object_end(js);
	return altern_english;
}

static bool is_rune_blacklisted(const struct rune *rune)
{
	u64 uid;

	/* Every rune *we produce* has a unique_id which is a number, but
	 * it's legal to have a rune without one. */
	if (rune->unique_id == NULL) {
		return false;
	}
	uid = atol(rune->unique_id);
	for (size_t i = 0; i < tal_count(blacklist); i++) {
		if (blacklist[i].start <= uid && blacklist[i].end >= uid) {
			return true;
		}
	}
	return false;
}

/* Every minute we forget entries. */
static void flush_usage_table(void *unused)
{
	struct usage *u;
	struct usage_table_iter it;

	for (u = usage_table_first(usage_table, &it);
	     u;
	     u = usage_table_next(usage_table, &it)) {
		usage_table_delval(usage_table, &it);
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
		cinfo->usage = usage_table_get(usage_table, atol(rune->unique_id));
		if (!cinfo->usage) {
			cinfo->usage = tal(plugin, struct usage);
			cinfo->usage->id = atol(rune->unique_id);
			cinfo->usage->counter = 0;
			usage_table_add(usage_table, cinfo->usage);
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

	/* Pass through valid integers as integers. */
	if (ptok->type == JSMN_PRIMITIVE) {
		s64 val;

		if (json_to_s64(cinfo->buf, ptok, &val)) {
			plugin_log(plugin, LOG_DBG, "It's an int %"PRId64, val);
			return rune_alt_single_int(ctx, alt, val);
		}

		/* Otherwise, treat it as a string (< and > will fail with
		 * "is not an integer field") */
	}
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

	if (is_rune_blacklisted(rune))
		return "Blacklisted rune";

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
	const jsmntok_t *toks, *method, *params, *rune, *id, *filter;
	const char *buf = (const char *)msg, *failmsg;
	struct out_req *req;
	const char *cmdid_prefix;

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
	filter = json_get_member(buf, toks, "filter");
	id = json_get_member(buf, toks, "id");
	if (!id) {
		if (!deprecated_apis) {
			commando_error(incoming, COMMANDO_ERROR_REMOTE,
				       "missing id field");
			return;
		}
		cmdid_prefix = NULL;
		incoming->json_id = NULL;
	} else {
		cmdid_prefix = tal_fmt(tmpctx, "%.*s/",
				       id->end - id->start,
				       buf + id->start);
		/* Includes quotes, if any! */
		incoming->json_id = tal_strndup(incoming,
						json_tok_full(buf, id),
						json_tok_full_len(id));
	}

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
						 cmdid_prefix,
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
	if (filter) {
		json_add_jsonstr(req->js, "filter",
				 json_tok_full(buf, filter),
				 json_tok_full_len(filter));
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
	const jsmntok_t *toks, *result, *err, *id;
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
	const char *rune, *filter;
	struct commando	*ocmd;
	struct outgoing *outgoing;
	char *json;
	size_t jsonlen;

	if (!param(cmd, buffer, params,
		   p_req("peer_id", param_node_id, &peer),
		   p_req("method", param_string, &method),
		   p_opt("params", param_string, &cparams),
		   p_opt("rune", param_string, &rune),
		   p_opt("filter", param_string, &filter),
		   NULL))
		return command_param_failed();

	ocmd = tal(cmd, struct commando);
	ocmd->cmd = cmd;
	ocmd->peer = *peer;
	ocmd->contents = tal_arr(ocmd, u8, 0);
	ocmd->json_id = tal_strdup(ocmd, cmd->id);
	do {
		ocmd->id = pseudorand_u64();
	} while (find_commando(outgoing_commands, NULL, &ocmd->id));
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

static struct rune_altern *rune_altern_from_json(const tal_t *ctx,
						 const char *buffer,
						 const jsmntok_t *tok)
{
	struct rune_altern *alt;
	size_t condoff;
	/* We still need to unescape here, for \\ -> \.  JSON doesn't
	 * allow unnecessary \ */
	const char *unescape;
	struct json_escape *e = json_escape_string_(tmpctx,
						    buffer + tok->start,
						    tok->end - tok->start);
	unescape = json_escape_unescape(tmpctx, e);
	if (!unescape)
		return NULL;

	condoff = rune_altern_fieldname_len(unescape, strlen(unescape));
	if (!rune_condition_is_valid(unescape[condoff]))
		return NULL;

	alt = tal(ctx, struct rune_altern);
	alt->fieldname = tal_strndup(alt, unescape, condoff);
	alt->condition = unescape[condoff];
	alt->value = tal_strdup(alt, unescape + condoff + 1);
	return alt;
}

static struct rune_restr *rune_restr_from_json(const tal_t *ctx,
					       const char *buffer,
					       const jsmntok_t *tok)
{
	const jsmntok_t *t;
	size_t i;
	struct rune_restr *restr;

	/* \| is not valid JSON, so they use \\|: undo it! */
	if (deprecated_apis && tok->type == JSMN_STRING) {
		const char *unescape;
		struct json_escape *e = json_escape_string_(tmpctx,
							    buffer + tok->start,
							    tok->end - tok->start);
		unescape = json_escape_unescape(tmpctx, e);
		if (!unescape)
			return NULL;
		return rune_restr_from_string(ctx, unescape, strlen(unescape));
	}

	restr = tal(ctx, struct rune_restr);
	/* FIXME: after deprecation removed, allow singletons again! */
	if (tok->type != JSMN_ARRAY)
		return NULL;

	restr->alterns = tal_arr(restr, struct rune_altern *, tok->size);
	json_for_each_arr(i, t, tok) {
		restr->alterns[i] = rune_altern_from_json(restr->alterns,
							  buffer, t);
		if (!restr->alterns[i])
			return tal_free(restr);
	}
	return restr;
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
			(*restrs)[i] = rune_restr_from_json(*restrs, buffer, t);
			if (!(*restrs)[i]) {
				return command_fail_badparam(cmd, name, buffer, t,
							     "not a valid restriction (should be array)");
			}
		}
	} else {
		*restrs = tal_arr(cmd, struct rune_restr *, 1);
		(*restrs)[0] = rune_restr_from_json(*restrs, buffer, tok);
		if (!(*restrs)[0])
			return command_fail_badparam(cmd, name, buffer, tok,
						     "not a valid restriction (should be array)");
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

static struct command_result *save_rune(struct command *cmd,
					      const char *buf UNUSED,
					      const jsmntok_t *result UNUSED,
					      struct rune *rune)
{
	const char *path = tal_fmt(cmd, "commando/runes/%s", rune->unique_id);
	return jsonrpc_set_datastore_string(plugin, cmd, path,
					    rune_to_base64(tmpctx, rune),
					    "must-create", reply_with_rune,
					    forward_error, rune);
}

static void towire_blacklist(u8 **pptr, const struct blacklist *b)
{
	for (size_t i = 0; i < tal_count(b); i++) {
		towire_u64(pptr, b[i].start);
		towire_u64(pptr, b[i].end);
	}
}

static struct blacklist *fromwire_blacklist(const tal_t *ctx,
					    const u8 **cursor,
					    size_t *max)
{
	struct blacklist *blist = tal_arr(ctx, struct blacklist, 0);
	while (*max > 0) {
		struct blacklist b;
		b.start = fromwire_u64(cursor, max);
		b.end = fromwire_u64(cursor, max);
		tal_arr_expand(&blist, b);
	}
	if (!*cursor) {
		return tal_free(blist);
	}
	return blist;
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
				    save_rune, forward_error, rune);
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
	json_add_string(req->js, "string",
			tal_fmt(tmpctx, "%"PRIu64, *rune_counter));
	return send_outreq(plugin, req);
}

static void join_strings(char **base, const char *connector, char *append)
{
	if (streq(*base, "")) {
		*base = append;
	} else {
		tal_append_fmt(base, " %s %s", connector, append);
	}
}

static struct command_result *json_add_rune(struct json_stream *js,
						 const struct rune *rune,
						 const char *rune_str,
						 size_t rune_strlen,
						 bool stored)
{
	char *rune_english;
	rune_english = "";
	json_object_start(js, NULL);
	json_add_stringn(js, "rune", rune_str, rune_strlen);
	if (!stored) {
		json_add_bool(js, "stored", false);
	}
	if (is_rune_blacklisted(rune)) {
		json_add_bool(js, "blacklisted", true);
	}
	if (rune_is_derived(master_rune, rune)) {
		json_add_bool(js, "our_rune", false);
	}
	json_add_string(js, "unique_id", rune->unique_id);
	json_array_start(js, "restrictions");
	for (size_t i = 0; i < tal_count(rune->restrs); i++) {
		char *restr_english;
		restr_english = "";
		/* Already printed out the unique id */
		if (is_unique_id(rune->restrs, i)) {
			continue;
		}
		json_object_start(js, NULL);
		json_array_start(js, "alternatives");
		for (size_t j = 0; j < tal_count(rune->restrs[i]->alterns); j++) {
			join_strings(&restr_english, "OR",
				     json_add_alternative(tmpctx, js, NULL, rune->restrs[i]->alterns[j]));
		}
		json_array_end(js);
		json_add_string(js, "english", restr_english);
		json_object_end(js);
		join_strings(&rune_english, "AND", restr_english);
	}
	json_array_end(js);
	json_add_string(js, "restrictions_as_english", rune_english);
	json_object_end(js);
	return NULL;
}

static struct command_result *listdatastore_done(struct command *cmd,
					      const char *buf,
					      const jsmntok_t *result,
					      struct rune *rune)
{
	struct json_stream *js;
	const jsmntok_t *t, *d = json_get_member(buf, result, "datastore");
	size_t i;
	const char *runestr;
	bool printed = false;

	if (rune != NULL) {
		runestr = rune_to_string(tmpctx, rune);
	} else {
		runestr = NULL;
	}

	js = jsonrpc_stream_success(cmd);

	json_array_start(js, "runes");
	json_for_each_arr(i, t, d) {
		const struct rune *this_rune;
		const jsmntok_t *s = json_get_member(buf, t, "string");
		if (runestr != NULL && !json_tok_streq(buf, s, runestr))
			continue;
		if (rune) {
			this_rune = rune;
		} else {
			this_rune = rune_from_base64n(tmpctx, buf + s->start, s->end - s->start);
			if (this_rune == NULL) {
				plugin_log(plugin, LOG_BROKEN,
					   "Invalid rune in datastore %.*s",
					   s->end - s->start, buf + s->start);
				continue;
			}
		}
		json_add_rune(js, this_rune, buf + s->start, s->end - s->start, true);
		printed = true;
	}
	if (rune && !printed) {
		json_add_rune(js, rune, runestr, strlen(runestr), false);
	}
	json_array_end(js);
	return command_finished(cmd, js);
}

static void blacklist_merge(struct blacklist *blacklist,
			    const struct blacklist *entry)
{
	if (entry->start < blacklist->start) {
		blacklist->start = entry->start;
	}
	if (entry->end > blacklist->end) {
		blacklist->end = entry->end;
	}
}

static bool blacklist_before(const struct blacklist *first,
			     const struct blacklist *second)
{
	// Is it before with a gap
	return (first->end + 1) < second->start;
}

static struct command_result *list_blacklist(struct command *cmd)
{
	struct json_stream *js = jsonrpc_stream_success(cmd);
	json_array_start(js, "blacklist");
	for (size_t i = 0; i < tal_count(blacklist); i++) {
		json_object_start(js, NULL);
		json_add_u64(js, "start", blacklist[i].start);
		json_add_u64(js, "end", blacklist[i].end);
		json_object_end(js);
	}
	json_array_end(js);
	return command_finished(cmd, js);
}

static struct command_result *blacklist_save_done(struct command *cmd,
					      const char *buf,
					      const jsmntok_t *result,
					      void *unused)
{
	return list_blacklist(cmd);
}

static struct command_result *json_commando_blacklist(struct command *cmd,
						 const char *buffer,
						 const jsmntok_t *params)
{
	u64 *start, *end;
	u8 *bwire;
	struct blacklist *entry, *newblacklist;

	if (!param(cmd, buffer, params,
		   p_opt("start", param_u64, &start), p_opt("end", param_u64, &end), NULL))
		return command_param_failed();

	if (end && !start) {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS, "Can not specify end without start");
	}
	if (!start) {
		return list_blacklist(cmd);
	}
	if (!end) {
		end = start;
	}
	entry = tal(cmd, struct blacklist);
	entry->start = *start;
	entry->end = *end;

	newblacklist = tal_arr(cmd->plugin, struct blacklist, 0);

	for (size_t i = 0; i < tal_count(blacklist); i++) {
		/* if new entry if already merged just copy the old list */
		if (entry == NULL) {
			tal_arr_expand(&newblacklist, blacklist[i]);
			continue;
		}
		/* old list has not reached the entry yet, so we are just copying it */
		if (blacklist_before(&blacklist[i], entry)) {
			tal_arr_expand(&newblacklist, blacklist[i]);
			continue;
		}
		/* old list has passed the entry, time to put the entry in */
		if (blacklist_before(entry, &blacklist[i])) {
			tal_arr_expand(&newblacklist, *entry);
			tal_arr_expand(&newblacklist, blacklist[i]);
			// mark entry as copied
			entry = NULL;
			continue;
		}
		/* old list overlaps combined into the entry we are adding */
		blacklist_merge(entry, &blacklist[i]);
	}
	if (entry != NULL) {
		tal_arr_expand(&newblacklist, *entry);
	}
	tal_free(blacklist);
	blacklist = newblacklist;
	bwire = tal_arr(tmpctx, u8, 0);
	towire_blacklist(&bwire, blacklist);
	return jsonrpc_set_datastore_binary(cmd->plugin, cmd, "commando/blacklist", bwire, "create-or-replace", blacklist_save_done, NULL, NULL);
}

static struct command_result *json_commando_listrunes(struct command *cmd,
						 const char *buffer,
						 const jsmntok_t *params)
{
	struct rune *rune;
	struct out_req *req;

	if (!param(cmd, buffer, params,
		   p_opt("rune", param_rune, &rune), NULL))
		return command_param_failed();

	req = jsonrpc_request_start(plugin, cmd, "listdatastore", listdatastore_done, forward_error, rune);
	json_array_start(req->js, "key");
	json_add_string(req->js, NULL, "commando");
	json_add_string(req->js, NULL, "runes");
	json_array_end(req->js);
	return send_outreq(plugin, req);
}

#if DEVELOPER
static void memleak_mark_globals(struct plugin *p, struct htable *memtable)
{
	memleak_scan_obj(memtable, usage_table);
	memleak_scan_obj(memtable, outgoing_commands);
	memleak_scan_obj(memtable, incoming_commands);
	memleak_scan_obj(memtable, master_rune);
	memleak_scan_htable(memtable, &usage_table->raw);
	memleak_scan_obj(memtable, blacklist);
	if (rune_counter)
		memleak_scan_obj(memtable, rune_counter);
}
#endif

static const char *init(struct plugin *p,
			const char *buf UNUSED, const jsmntok_t *config UNUSED)
{
	struct secret rune_secret;
	const char *err;
	u8 *bwire;

	if (rpc_scan_datastore_hex(tmpctx, p, "commando/blacklist",
				   JSON_SCAN_TAL(tmpctx, json_tok_bin_from_hex,
						 &bwire)) == NULL) {
		size_t max = tal_bytelen(bwire);
		blacklist = fromwire_blacklist(p, cast_const2(const u8 **,
							      &bwire),
					       &max);
		if (blacklist == NULL) {
			plugin_err(p, "Invalid commando/blacklist");
		}
	}
	outgoing_commands = tal_arr(p, struct commando *, 0);
	incoming_commands = tal_arr(p, struct commando *, 0);
	usage_table = tal(p, struct usage_table);
	usage_table_init(usage_table);
	plugin = p;
#if DEVELOPER
	plugin_set_memleak_handler(p, memleak_mark_globals);
#endif

	rune_counter = tal(p, u64);
	/* If this fails, it probably doesn't exist */
	err = rpc_scan_datastore_str(tmpctx, plugin, "commando/rune_counter",
				     JSON_SCAN(json_to_u64, rune_counter));
	if (err)
		rune_counter = tal_free(rune_counter);

	/* Old python commando used to store secret */
	err = rpc_scan_datastore_hex(tmpctx, plugin, "commando/secret",
				     JSON_SCAN(json_to_secret, &rune_secret));
	if (err) {
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
	{
	"commando-listrunes",
	"utility",
	"List runes we have created earlier",
	"Takes an optional {rune} and returns list of {rune}",
	json_commando_listrunes,
	},
	{
	"commando-blacklist",
	"utility",
	"Blacklist a rune or range of runes by unique id",
	"Takes an optional {start} and an optional {end} and returns {blacklist} array containing {start}, {end}",
	json_commando_blacklist,
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
