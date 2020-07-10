#include <bitcoin/chainparams.h>
#include <ccan/err/err.h>
#include <ccan/io/io.h>
#include <ccan/json_out/json_out.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/tal/str/str.h>
#include <common/daemon.h>
#include <common/json_stream.h>
#include <common/utils.h>
#include <errno.h>
#include <plugins/libplugin.h>
#include <poll.h>
#include <stdarg.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#define READ_CHUNKSIZE 4096

bool deprecated_apis;

struct plugin_timer {
	struct timer timer;
	void (*cb)(void *cb_arg);
	void *cb_arg;
};

struct rpc_conn {
	int fd;
	MEMBUF(char) mb;
};

struct plugin {
	/* lightningd interaction */
	struct io_conn *stdin_conn;
	struct io_conn *stdout_conn;

	/* To read from lightningd */
	char *buffer;
	size_t used, len_read;

	/* To write to lightningd */
	struct json_stream **js_arr;

	/* Asynchronous RPC interaction */
	struct io_conn *io_rpc_conn;
	struct json_stream **rpc_js_arr;
	char *rpc_buffer;
	size_t rpc_used, rpc_len_read;
	/* Tracking async RPC requests */
	UINTMAP(struct out_req *) out_reqs;
	u64 next_outreq_id;

	/* Synchronous RPC interaction */
	struct rpc_conn *rpc_conn;

	/* Plugin informations */
	enum plugin_restartability restartability;
	const struct plugin_command *commands;
	size_t num_commands;
	const struct plugin_notification *notif_subs;
	size_t num_notif_subs;
	const struct plugin_hook *hook_subs;
	size_t num_hook_subs;
	struct plugin_option *opts;

	/* Anything special to do at init ? */
	void (*init)(struct plugin *p,
		     const char *buf, const jsmntok_t *);
	/* Has the manifest been sent already ? */
	bool manifested;
	/* Has init been received ? */
	bool initialized;

	/* Map from json command names to usage strings: we don't put this inside
	 * struct json_command as it's good practice to have those const. */
	STRMAP(const char *) usagemap;
	/* Timers */
	struct timers timers;
	size_t in_timer;

	/* Feature set for lightningd */
	struct feature_set *our_features;
};

/* command_result is mainly used as a compile-time check to encourage you
 * to return as soon as you get one (and not risk use-after-free of command).
 * Here we use two values: complete (cmd freed) and pending (still going) */
struct command_result {
	char c;
};
static struct command_result complete, pending;

struct command_result *command_param_failed(void)
{
	return &complete;
}


static void ld_send(struct plugin *plugin, struct json_stream *stream)
{
	tal_steal(plugin->js_arr, stream);
	tal_arr_expand(&plugin->js_arr, stream);
	io_wake(plugin);
}

static void ld_rpc_send(struct plugin *plugin, struct json_stream *stream)
{
	tal_steal(plugin->rpc_js_arr, stream);
	tal_arr_expand(&plugin->rpc_js_arr, stream);
	io_wake(plugin->io_rpc_conn);
}

/* FIXME: Move lightningd/jsonrpc to common/ ? */

struct out_req *
jsonrpc_request_start_(struct plugin *plugin, struct command *cmd,
		       const char *method,
		       struct command_result *(*cb)(struct command *command,
						    const char *buf,
						    const jsmntok_t *result,
						    void *arg),
		       struct command_result *(*errcb)(struct command *command,
						       const char *buf,
						       const jsmntok_t *result,
						       void *arg),
		       void *arg)
{
	struct out_req *out;

	out = tal(plugin, struct out_req);
	out->id = plugin->next_outreq_id++;
	out->cmd = cmd;
	out->cb = cb;
	out->errcb = errcb;
	out->arg = arg;
	uintmap_add(&plugin->out_reqs, out->id, out);

	out->js = new_json_stream(NULL, cmd, NULL);
	json_object_start(out->js, NULL);
	json_add_string(out->js, "jsonrpc", "2.0");
	json_add_u64(out->js, "id", out->id);
	json_add_string(out->js, "method", method);
	json_object_start(out->js, "params");

	return out;
}

const struct feature_set *plugin_feature_set(const struct plugin *p)
{
	return p->our_features;
}

static void jsonrpc_finish_and_send(struct plugin *p, struct json_stream *js)
{
	json_object_compat_end(js);
	json_stream_close(js, NULL);
	ld_send(p, js);
}

static struct json_stream *jsonrpc_stream_start(struct command *cmd)
{
	struct json_stream *js = new_json_stream(cmd, cmd, NULL);

	json_object_start(js, NULL);
	json_add_string(js, "jsonrpc", "2.0");
	json_add_u64(js, "id", *cmd->id);

	return js;
}

struct json_stream *jsonrpc_stream_success(struct command *cmd)
{
	struct json_stream *js = jsonrpc_stream_start(cmd);

	json_object_start(js, "result");
	return js;
}

struct json_stream *jsonrpc_stream_fail(struct command *cmd,
					int code,
					const char *err)
{
	struct json_stream *js = jsonrpc_stream_start(cmd);

	json_object_start(js, "error");
	json_add_member(js, "code", false, "%d", code);
	json_add_string(js, "message", err);

	return js;
}

struct json_stream *jsonrpc_stream_fail_data(struct command *cmd,
					     int code,
					     const char *err)
{
	struct json_stream *js = jsonrpc_stream_fail(cmd, code, err);

	json_object_start(js, "data");
	return js;
}

static struct command_result *command_complete(struct command *cmd,
					       struct json_stream *result)
{
	/* Global object */
	json_object_compat_end(result);
	json_stream_close(result, cmd);
	ld_send(cmd->plugin, result);
	tal_free(cmd);

	return &complete;
}

struct command_result *WARN_UNUSED_RESULT
command_finished(struct command *cmd, struct json_stream *response)
{
	/* "result" or "error" object */
	json_object_end(response);

	return command_complete(cmd, response);
}

struct command_result *WARN_UNUSED_RESULT
command_still_pending(struct command *cmd)
{
	return &pending;
}

struct json_out *json_out_obj(const tal_t *ctx,
			      const char *fieldname,
			      const char *str)
{
	struct json_out *jout = json_out_new(ctx);
	json_out_start(jout, NULL, '{');
	if (str)
		json_out_addstr(jout, fieldname, str);
	json_out_end(jout, '}');
	json_out_finished(jout);

	return jout;
}

/* Realloc helper for tal membufs */
static void *membuf_tal_realloc(struct membuf *mb, void *rawelems,
				size_t newsize)
{
	char *p = rawelems;

	tal_resize(&p, newsize);
	return p;
}

static int read_json_from_rpc(struct plugin *p)
{
	char *end;

	/* We rely on the double-\n marker which only terminates JSON top
	 * levels.  Thanks lightningd! */
	while ((end = memmem(membuf_elems(&p->rpc_conn->mb),
			     membuf_num_elems(&p->rpc_conn->mb), "\n\n", 2))
	       == NULL) {
		ssize_t r;

		/* Make sure we've room for at least READ_CHUNKSIZE. */
		membuf_prepare_space(&p->rpc_conn->mb, READ_CHUNKSIZE);
		r = read(p->rpc_conn->fd, membuf_space(&p->rpc_conn->mb),
			 membuf_num_space(&p->rpc_conn->mb));
		/* lightningd goes away, we go away. */
		if (r == 0)
			exit(0);
		if (r < 0)
			plugin_err(p, "Reading JSON input: %s", strerror(errno));
		membuf_added(&p->rpc_conn->mb, r);
	}

	return end + 2 - membuf_elems(&p->rpc_conn->mb);
}

/* This starts a JSON RPC message with boilerplate */
static struct json_out *start_json_rpc(const tal_t *ctx, u64 id)
{
	struct json_out *jout = json_out_new(ctx);

	json_out_start(jout, NULL, '{');
	json_out_addstr(jout, "jsonrpc", "2.0");
	json_out_add(jout, "id", false, "%"PRIu64, id);

	return jout;
}

/* This closes a JSON response and writes it out. */
static void finish_and_send_json(int fd, struct json_out *jout)
{
	size_t len;
	const char *p;

	json_out_end(jout, '}');
	/* We double-\n terminate.  Don't need to, but it's more readable. */
	memcpy(json_out_direct(jout, 2), "\n\n", 2);
	json_out_finished(jout);

	p = json_out_contents(jout, &len);
	write_all(fd, p, len);
	json_out_consume(jout, len);
}

/* str is raw JSON from RPC output. */
static struct command_result *WARN_UNUSED_RESULT
command_done_raw(struct command *cmd,
		 const char *label,
		 const char *str, int size)
{
	struct json_stream *js = jsonrpc_stream_start(cmd);

	memcpy(json_out_member_direct(js->jout, label, size), str, size);

	return command_complete(cmd, js);
}

struct command_result *WARN_UNUSED_RESULT
command_success(struct command *cmd, const struct json_out *result)
{
	struct json_stream *js = jsonrpc_stream_start(cmd);

	json_out_add_splice(js->jout, "result", result);
	return command_complete(cmd, js);
}

struct command_result *WARN_UNUSED_RESULT
command_success_str(struct command *cmd, const char *str)
{
	struct json_stream *js = jsonrpc_stream_start(cmd);

	if (str)
		json_add_string(js, "result", str);
	else {
		/* Use an empty object if they don't want anything. */
		json_object_start(js, "result");
		json_object_end(js);
	}
	return command_complete(cmd, js);
}

struct command_result *command_done_err(struct command *cmd,
					errcode_t code,
					const char *errmsg,
					const struct json_out *data)
{
	struct json_stream *js = jsonrpc_stream_start(cmd);

	json_object_start(js, "error");
	json_add_errcode(js, "code", code);
	json_add_string(js, "message", errmsg);

	if (data)
		json_out_add_splice(js->jout, "data", data);
	json_object_end(js);

	return command_complete(cmd, js);
}

struct command_result *command_err_raw(struct command *cmd,
				       const char *json_str)
{
	return command_done_raw(cmd, "error",
				json_str, strlen(json_str));
}

struct command_result *timer_complete(struct plugin *p)
{
	assert(p->in_timer > 0);
	p->in_timer--;
	return &complete;
}

struct command_result *forward_error(struct command *cmd,
				     const char *buf,
				     const jsmntok_t *error,
				     void *arg UNNEEDED)
{
	/* Push through any errors. */
	return command_done_raw(cmd, "error",
				buf + error->start, error->end - error->start);
}

struct command_result *forward_result(struct command *cmd,
				      const char *buf,
				      const jsmntok_t *result,
				      void *arg UNNEEDED)
{
	/* Push through the result. */
	return command_done_raw(cmd, "result",
				buf + result->start, result->end - result->start);
}

/* Called by param() directly if it's malformed. */
struct command_result *command_fail(struct command *cmd,
				    errcode_t code, const char *fmt, ...)
{
	va_list ap;
	struct command_result *res;

	va_start(ap, fmt);
	res = command_done_err(cmd, code, tal_vfmt(cmd, fmt, ap), NULL);
	va_end(ap);
	return res;
}

/* We invoke param for usage at registration time. */
bool command_usage_only(const struct command *cmd)
{
	return cmd->usage_only;
}

/* FIXME: would be good to support this! */
bool command_check_only(const struct command *cmd)
{
	return false;
}

void command_set_usage(struct command *cmd, const char *usage TAKES)
{
	usage = tal_strdup(NULL, usage);
	if (!strmap_add(&cmd->plugin->usagemap, cmd->methodname, usage))
		plugin_err(cmd->plugin, "Two usages for command %s?",
			   cmd->methodname);
}

/* Reads rpc reply and returns tokens, setting contents to 'error' or
 * 'result' (depending on *error). */
static const jsmntok_t *read_rpc_reply(const tal_t *ctx,
				       struct plugin *plugin,
				       const jsmntok_t **contents,
				       bool *error,
				       int *reqlen)
{
	const jsmntok_t *toks;
	bool valid;

	*reqlen = read_json_from_rpc(plugin);

	toks = json_parse_input(ctx, membuf_elems(&plugin->rpc_conn->mb), *reqlen, &valid);
	if (!valid)
		plugin_err(plugin, "Malformed JSON reply '%.*s'",
			   *reqlen, membuf_elems(&plugin->rpc_conn->mb));

	*contents = json_get_member(membuf_elems(&plugin->rpc_conn->mb), toks, "error");
	if (*contents)
		*error = true;
	else {
		*contents = json_get_member(membuf_elems(&plugin->rpc_conn->mb), toks,
					    "result");
		if (!*contents)
			plugin_err(plugin, "JSON reply with no 'result' nor 'error'? '%.*s'",
				   *reqlen, membuf_elems(&plugin->rpc_conn->mb));
		*error = false;
	}
	return toks;
}

static struct json_out *start_json_request(const tal_t *ctx,
					   u64 id,
					   const char *method,
					   const struct json_out *params TAKES)
{
	struct json_out *jout;

	jout = start_json_rpc(tmpctx, id);
	json_out_addstr(jout, "method", method);
	json_out_add_splice(jout, "params", params);
	if (taken(params))
		tal_free(params);

	return jout;
}

/* Synchronous routine to send command and extract single field from response */
const char *rpc_delve(const tal_t *ctx,
		      struct plugin *plugin,
		      const char *method,
		      const struct json_out *params TAKES,
		      const char *guide)
{
	bool error;
	const jsmntok_t *contents, *t;
	int reqlen;
	const char *ret;
	struct json_out *jout;

	jout = start_json_request(tmpctx, 0, method, params);
	finish_and_send_json(plugin->rpc_conn->fd, jout);

	read_rpc_reply(tmpctx, plugin, &contents, &error, &reqlen);
	if (error)
		plugin_err(plugin, "Got error reply to %s: '%.*s'",
		     method, reqlen, membuf_elems(&plugin->rpc_conn->mb));

	t = json_delve(membuf_elems(&plugin->rpc_conn->mb), contents, guide);
	if (!t)
		plugin_err(plugin, "Could not find %s in reply to %s: '%.*s'",
			   guide, method, reqlen, membuf_elems(&plugin->rpc_conn->mb));

	ret = json_strdup(ctx, membuf_elems(&plugin->rpc_conn->mb), t);
	membuf_consume(&plugin->rpc_conn->mb, reqlen);
	return ret;
}

static void handle_rpc_reply(struct plugin *plugin, const jsmntok_t *toks)
{
	const jsmntok_t *idtok, *contenttok;
	struct out_req *out;
	struct command_result *res;
	u64 id;

	idtok = json_get_member(plugin->rpc_buffer, toks, "id");
	if (!idtok)
		plugin_err(plugin, "JSON reply without id '%.*s'",
			   json_tok_full_len(toks),
			   json_tok_full(plugin->rpc_buffer, toks));
	if (!json_to_u64(plugin->rpc_buffer, idtok, &id))
		plugin_err(plugin, "JSON reply without numeric id '%.*s'",
			   json_tok_full_len(toks),
			   json_tok_full(plugin->rpc_buffer, toks));
	out = uintmap_get(&plugin->out_reqs, id);
	if (!out)
		plugin_err(plugin, "JSON reply with unknown id '%.*s' (%"PRIu64")",
			   json_tok_full_len(toks),
			   json_tok_full(plugin->rpc_buffer, toks), id);

	/* We want to free this if callback doesn't. */
	tal_steal(tmpctx, out);
	uintmap_del(&plugin->out_reqs, out->id);

	contenttok = json_get_member(plugin->rpc_buffer, toks, "error");
	if (contenttok)
		res = out->errcb(out->cmd, plugin->rpc_buffer,
				 contenttok, out->arg);
	else {
		contenttok = json_get_member(plugin->rpc_buffer, toks, "result");
		if (!contenttok)
			plugin_err(plugin, "Bad JSONRPC, no 'error' nor 'result': '%.*s'",
				   json_tok_full_len(toks),
				   json_tok_full(plugin->rpc_buffer, toks));
		res = out->cb(out->cmd, plugin->rpc_buffer, contenttok, out->arg);
	}

	assert(res == &pending || res == &complete);
}

struct command_result *
send_outreq(struct plugin *plugin, const struct out_req *req)
{
	/* The "param" object. */
	json_object_end(req->js);
	json_object_compat_end(req->js);
	json_stream_close(req->js, req->cmd);

	ld_rpc_send(plugin, req->js);

	return &pending;
}

static struct command_result *
handle_getmanifest(struct command *getmanifest_cmd)
{
	struct json_stream *params = jsonrpc_stream_success(getmanifest_cmd);
	struct plugin *p = getmanifest_cmd->plugin;

	json_array_start(params, "options");
	for (size_t i = 0; i < tal_count(p->opts); i++) {
		json_object_start(params, NULL);
		json_add_string(params, "name", p->opts[i].name);
		json_add_string(params, "type", p->opts[i].type);
		json_add_string(params, "description", p->opts[i].description);
		json_object_end(params);
	}
	json_array_end(params);

	json_array_start(params, "rpcmethods");
	for (size_t i = 0; i < p->num_commands; i++) {
		json_object_start(params, NULL);
		json_add_string(params, "name", p->commands[i].name);
		json_add_string(params, "usage",
				strmap_get(&p->usagemap, p->commands[i].name));
		json_add_string(params, "description", p->commands[i].description);
		if (p->commands[i].long_description)
			json_add_string(params, "long_description",
					p->commands[i].long_description);
		json_object_end(params);
	}
	json_array_end(params);

	json_array_start(params, "subscriptions");
	for (size_t i = 0; i < p->num_notif_subs; i++)
		json_add_string(params, NULL, p->notif_subs[i].name);
	json_array_end(params);

	json_array_start(params, "hooks");
	for (size_t i = 0; i < p->num_hook_subs; i++)
		json_add_string(params, NULL, p->hook_subs[i].name);
	json_array_end(params);

	if (p->our_features != NULL) {
		json_object_start(params, "featurebits");
		for (size_t i = 0; i < NUM_FEATURE_PLACE; i++) {
			u8 *f = p->our_features->bits[i];
			const char *fieldname = feature_place_names[i];
			if (fieldname == NULL)
				continue;
			json_add_hex(params, fieldname, f, tal_bytelen(f));
		}
		json_object_end(params);
	}

	json_add_bool(params, "dynamic", p->restartability == PLUGIN_RESTARTABLE);

	return command_finished(getmanifest_cmd, params);
}

static void rpc_conn_finished(struct io_conn *conn,
			      struct plugin *plugin)
{
	plugin_err(plugin, "Lost connection to the RPC socket.");
}

static bool rpc_read_response_one(struct plugin *plugin)
{
	bool valid;
	const jsmntok_t *toks, *jrtok;

	/* FIXME: This could be done more efficiently by storing the
	 * toks and doing an incremental parse, like lightning-cli
	 * does. */
	toks = json_parse_input(NULL, plugin->rpc_buffer, plugin->rpc_used,
				&valid);
	if (!toks) {
		if (!valid) {
			plugin_err(plugin, "Failed to parse RPC JSON response '%.*s'",
				   (int)plugin->rpc_used, plugin->rpc_buffer);
			return false;
		}
		/* We need more. */
		return false;
	}

	/* Empty buffer? (eg. just whitespace). */
	if (tal_count(toks) == 1) {
		plugin->rpc_used = 0;
		return false;
	}

	jrtok = json_get_member(plugin->rpc_buffer, toks, "jsonrpc");
	if (!jrtok) {
		plugin_err(plugin, "JSON-RPC message does not contain \"jsonrpc\" field: '%.*s'",
                                   (int)plugin->rpc_used, plugin->rpc_buffer);
		return false;
	}

	handle_rpc_reply(plugin, toks);

	/* Move this object out of the buffer */
	memmove(plugin->rpc_buffer, plugin->rpc_buffer + toks[0].end,
		tal_count(plugin->rpc_buffer) - toks[0].end);
	plugin->rpc_used -= toks[0].end;
	tal_free(toks);

	return true;
}

static struct io_plan *rpc_conn_read_response(struct io_conn *conn,
					      struct plugin *plugin)
{
	plugin->rpc_used += plugin->rpc_len_read;
	if (plugin->rpc_used == tal_count(plugin->rpc_buffer))
		tal_resize(&plugin->rpc_buffer, plugin->rpc_used * 2);

	/* Read and process all messages from the connection */
	while (rpc_read_response_one(plugin))
		;

	/* Read more, if there is. */
	return io_read_partial(plugin->io_rpc_conn,
			       plugin->rpc_buffer + plugin->rpc_used,
			       tal_bytelen(plugin->rpc_buffer) - plugin->rpc_used,
			       &plugin->rpc_len_read,
			       rpc_conn_read_response, plugin);
}

static struct io_plan *rpc_conn_write_request(struct io_conn *conn,
					      struct plugin *plugin);

static struct io_plan *
rpc_stream_complete(struct io_conn *conn, struct json_stream *js,
		    struct plugin *plugin)
{
	assert(tal_count(plugin->rpc_js_arr) > 0);
	/* Remove js and shift all remaining over */
	tal_arr_remove(&plugin->rpc_js_arr, 0);

	/* It got dropped off the queue, free it. */
	tal_free(js);

	return rpc_conn_write_request(conn, plugin);
}

static struct io_plan *rpc_conn_write_request(struct io_conn *conn,
					      struct plugin *plugin)
{
	if (tal_count(plugin->rpc_js_arr) > 0)
		return json_stream_output(plugin->rpc_js_arr[0], conn,
					  rpc_stream_complete, plugin);

	return io_out_wait(conn, plugin->io_rpc_conn,
			   rpc_conn_write_request, plugin);
}

static struct io_plan *rpc_conn_init(struct io_conn *conn,
				     struct plugin *plugin)
{
	plugin->io_rpc_conn = conn;
	io_set_finish(conn, rpc_conn_finished, plugin);
	return io_duplex(conn,
			 rpc_conn_read_response(conn, plugin),
			 rpc_conn_write_request(conn, plugin));
}

static struct feature_set *json_to_feature_set(struct plugin *plugin,
					       const char *buf,
					       const jsmntok_t *features)
{
	struct feature_set *fset = talz(plugin, struct feature_set);
	const jsmntok_t *t;
	size_t i;

	json_for_each_obj(i, t, features) {
		enum feature_place p;
		if (json_tok_streq(buf, t, "init"))
			p = INIT_FEATURE;
		else if (json_tok_streq(buf, t, "node"))
			p = NODE_ANNOUNCE_FEATURE;
		else if (json_tok_streq(buf, t, "channel"))
			p = CHANNEL_FEATURE;
		else if (json_tok_streq(buf, t, "invoice"))
			p = BOLT11_FEATURE;
		else
			continue;
		fset->bits[p] = json_tok_bin_from_hex(fset, buf, t + 1);
	}
	return fset;
}

static struct command_result *handle_init(struct command *cmd,
					  const char *buf,
					  const jsmntok_t *params)
{
	const jsmntok_t *configtok, *rpctok, *dirtok, *opttok, *nettok, *fsettok,
		*t;
	struct sockaddr_un addr;
	size_t i;
	char *dir, *network;
	struct json_out *param_obj;
	struct plugin *p = cmd->plugin;
	bool with_rpc = true;

	configtok = json_delve(buf, params, ".configuration");

	/* Move into lightning directory: other files are relative */
	dirtok = json_delve(buf, configtok, ".lightning-dir");
	dir = json_strdup(tmpctx, buf, dirtok);
	if (chdir(dir) != 0)
		plugin_err(p, "chdir to %s: %s", dir, strerror(errno));

	nettok = json_delve(buf, configtok, ".network");
	network = json_strdup(tmpctx, buf, nettok);
	chainparams = chainparams_for_network(network);

	fsettok = json_delve(buf, configtok, ".feature_set");
	p->our_features = json_to_feature_set(p, buf, fsettok);

	rpctok = json_delve(buf, configtok, ".rpc-file");
	p->rpc_conn->fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (rpctok->end - rpctok->start + 1 > sizeof(addr.sun_path))
		plugin_err(p, "rpc filename '%.*s' too long",
			   rpctok->end - rpctok->start,
			   buf + rpctok->start);
	memcpy(addr.sun_path, buf + rpctok->start, rpctok->end - rpctok->start);
	addr.sun_path[rpctok->end - rpctok->start] = '\0';
	addr.sun_family = AF_UNIX;

	if (connect(p->rpc_conn->fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
		with_rpc = false;
		plugin_log(p, LOG_UNUSUAL, "Could not connect to '%.*s': %s",
			   rpctok->end - rpctok->start, buf + rpctok->start,
			   strerror(errno));
	} else {
		param_obj = json_out_obj(NULL, "config", "allow-deprecated-apis");
		deprecated_apis = streq(rpc_delve(tmpctx, p, "listconfigs",
						  take(param_obj),
						  ".allow-deprecated-apis"),
					"true");
	}

	opttok = json_get_member(buf, params, "options");
	json_for_each_obj(i, t, opttok) {
		char *opt = json_strdup(NULL, buf, t);
		for (size_t i = 0; i < tal_count(p->opts); i++) {
			char *problem;
			if (!streq(p->opts[i].name, opt))
				continue;
			problem = p->opts[i].handle(json_strdup(opt, buf, t+1),
						    p->opts[i].arg);
			if (problem)
				plugin_err(p, "option '%s': %s",
					   p->opts[i].name, problem);
			break;
		}
		tal_free(opt);
	}

	if (p->init)
		p->init(p, buf, configtok);

	if (with_rpc)
		io_new_conn(p, p->rpc_conn->fd, rpc_conn_init, p);

	return command_success_str(cmd, NULL);
}

char *u64_option(const char *arg, u64 *i)
{
	char *endp;

	/* This is how the manpage says to do it.  Yech. */
	errno = 0;
	*i = strtol(arg, &endp, 0);
	if (*endp || !arg[0])
		return tal_fmt(NULL, "'%s' is not a number", arg);
	if (errno)
		return tal_fmt(NULL, "'%s' is out of range", arg);
	return NULL;
}

char *u32_option(const char *arg, u32 *i)
{
	char *endp;
	u64 n;

	errno = 0;
	n = strtoul(arg, &endp, 0);
	if (*endp || !arg[0])
		return tal_fmt(NULL, "'%s' is not a number", arg);
	if (errno)
		return tal_fmt(NULL, "'%s' is out of range", arg);

	*i = n;
	if (*i != n)
		return tal_fmt(NULL, "'%s' is too large (overflow)", arg);

	return NULL;
}

char *bool_option(const char *arg, bool *i)
{
	if (!streq(arg, "true") && !streq(arg, "false"))
		return tal_fmt(NULL, "'%s' is not a bool, must be \"true\" or \"false\"", arg);

	*i = streq(arg, "true");
	return NULL;
}

char *flag_option(const char *arg, bool *i)
{
	/* We only get called if the flag was provided, so *i should be false
	 * by default */
	assert(*i == false);
	if (!streq(arg, "true"))
		return tal_fmt(NULL, "Invalid argument '%s' passed to a flag", arg);

	*i = true;
	return NULL;
}

char *charp_option(const char *arg, char **p)
{
	*p = tal_strdup(NULL, arg);
	return NULL;
}

static void setup_command_usage(struct plugin *p)
{
	struct command *usage_cmd = tal(tmpctx, struct command);

	/* This is how common/param can tell it's just a usage request */
	usage_cmd->usage_only = true;
	usage_cmd->plugin = p;
	for (size_t i = 0; i < p->num_commands; i++) {
		struct command_result *res;

		usage_cmd->methodname = p->commands[i].name;
		res = p->commands[i].handle(usage_cmd, NULL, NULL);
		assert(res == &complete);
		assert(strmap_get(&p->usagemap, p->commands[i].name));
	}
}

static void call_plugin_timer(struct plugin *p, struct timer *timer)
{
	struct plugin_timer *t = container_of(timer, struct plugin_timer, timer);

	p->in_timer++;
	/* Free this if they don't. */
	tal_steal(tmpctx, t);
	t->cb(t->cb_arg);
}

static void destroy_plugin_timer(struct plugin_timer *timer, struct plugin *p)
{
	timer_del(&p->timers, &timer->timer);
}

struct plugin_timer *plugin_timer_(struct plugin *p, struct timerel t,
				   void (*cb)(void *cb_arg),
				   void *cb_arg)
{
	struct plugin_timer *timer = tal(NULL, struct plugin_timer);
	timer->cb = cb;
	timer->cb_arg = cb_arg;
	timer_init(&timer->timer);
	timer_addrel(&p->timers, &timer->timer, t);
	tal_add_destructor2(timer, destroy_plugin_timer, p);
	return timer;
}

static void plugin_logv(struct plugin *p, enum log_level l,
			const char *fmt, va_list ap)
{
	struct json_stream *js = new_json_stream(NULL, NULL, NULL);

	json_object_start(js, NULL);
	json_add_string(js, "jsonrpc", "2.0");
	json_add_string(js, "method", "log");

	json_object_start(js, "params");
	json_add_string(js, "level",
			l == LOG_DBG ? "debug"
			: l == LOG_INFORM ? "info"
			: l == LOG_UNUSUAL ? "warn"
			: "error");
	json_out_addv(js->jout, "message", true, fmt, ap);
	json_object_end(js);

	jsonrpc_finish_and_send(p, js);
}

void NORETURN plugin_err(struct plugin *p, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	plugin_logv(p, LOG_BROKEN, fmt, ap);
	va_end(ap);
	va_start(ap, fmt);
	errx(1, "%s", tal_vfmt(NULL, fmt, ap));
	va_end(ap);
}

void plugin_log(struct plugin *p, enum log_level l, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	plugin_logv(p, l, fmt, ap);
	va_end(ap);
}

static void ld_command_handle(struct plugin *plugin,
			      struct command *cmd,
			      const jsmntok_t *toks)
{
	const jsmntok_t *idtok, *methtok, *paramstok;

	idtok = json_get_member(plugin->buffer, toks, "id");
	methtok = json_get_member(plugin->buffer, toks, "method");
	paramstok = json_get_member(plugin->buffer, toks, "params");

	if (!methtok || !paramstok)
		plugin_err(plugin, "Malformed JSON-RPC notification missing "
			   "\"method\" or \"params\": %.*s",
			   json_tok_full_len(toks),
			   json_tok_full(plugin->buffer, toks));

	cmd->plugin = plugin;
	cmd->id = NULL;
	cmd->usage_only = false;
	cmd->methodname = json_strdup(cmd, plugin->buffer, methtok);
	if (idtok) {
		cmd->id = tal(cmd, u64);
		if (!json_to_u64(plugin->buffer, idtok, cmd->id))
			plugin_err(plugin, "JSON id '%*.s' is not a number",
				   json_tok_full_len(idtok),
				   json_tok_full(plugin->buffer, idtok));
	}

	if (!plugin->manifested) {
		if (streq(cmd->methodname, "getmanifest")) {
			handle_getmanifest(cmd);
			plugin->manifested = true;
			return;
		}
		plugin_err(plugin, "Did not receive 'getmanifest' yet, but got '%s'"
			   " instead", cmd->methodname);
	}

	if (!plugin->initialized) {
		if (streq(cmd->methodname, "init")) {
			handle_init(cmd, plugin->buffer, paramstok);
			plugin->initialized = true;
			return;
		}
		plugin_err(plugin, "Did not receive 'init' yet, but got '%s'"
			   " instead", cmd->methodname);
	}

	/* If that's a notification. */
	if (!cmd->id) {
		for (size_t i = 0; i < plugin->num_notif_subs; i++) {
			if (streq(cmd->methodname,
				  plugin->notif_subs[i].name)) {
				plugin->notif_subs[i].handle(cmd,
							     plugin->buffer,
							     paramstok);
				return;
			}
		}
		plugin_err(plugin, "Unregistered notification %.*s",
			   json_tok_full_len(methtok),
			   json_tok_full(plugin->buffer, methtok));
	}

	for (size_t i = 0; i < plugin->num_hook_subs; i++) {
		if (streq(cmd->methodname, plugin->hook_subs[i].name)) {
			plugin->hook_subs[i].handle(cmd,
						    plugin->buffer,
						    paramstok);
			return;
		}
	}

	for (size_t i = 0; i < plugin->num_commands; i++) {
		if (streq(cmd->methodname, plugin->commands[i].name)) {
			plugin->commands[i].handle(cmd,
						   plugin->buffer,
						   paramstok);
			return;
		}
	}

	plugin_err(plugin, "Unknown command '%s'", cmd->methodname);
}

/**
 * Try to parse a complete message from lightningd's buffer, and return true
 * if we could handle it.
 */
static bool ld_read_json_one(struct plugin *plugin)
{
	bool valid;
	const jsmntok_t *toks;
	struct command *cmd = tal(plugin, struct command);

	/* FIXME: This could be done more efficiently by storing the
	 * toks and doing an incremental parse, like lightning-cli
	 * does. */
	toks = json_parse_input(NULL, plugin->buffer, plugin->used,
				&valid);
	if (!toks) {
		if (!valid) {
			plugin_err(plugin, "Failed to parse JSON response '%.*s'",
				   (int)plugin->used, plugin->buffer);
			return false;
		}
		/* We need more. */
		return false;
	}

	/* Empty buffer? (eg. just whitespace). */
	if (tal_count(toks) == 1) {
		plugin->used = 0;
		return false;
	}

	/* FIXME: Spark doesn't create proper jsonrpc 2.0!  So we don't
	 * check for "jsonrpc" here. */
	ld_command_handle(plugin, cmd, toks);

	/* Move this object out of the buffer */
	memmove(plugin->buffer, plugin->buffer + toks[0].end,
		tal_count(plugin->buffer) - toks[0].end);
	plugin->used -= toks[0].end;
	tal_free(toks);

	return true;
}

static struct io_plan *ld_read_json(struct io_conn *conn,
				    struct plugin *plugin)
{
	plugin->used += plugin->len_read;
	if (plugin->used && plugin->used == tal_count(plugin->buffer))
		tal_resize(&plugin->buffer, plugin->used * 2);

	/* Read and process all messages from the connection */
	while (ld_read_json_one(plugin))
		;

	/* Now read more from the connection */
	return io_read_partial(plugin->stdin_conn,
			       plugin->buffer + plugin->used,
			       tal_count(plugin->buffer) - plugin->used,
			       &plugin->len_read, ld_read_json, plugin);
}

static struct io_plan *ld_write_json(struct io_conn *conn,
				     struct plugin *plugin);

static struct io_plan *
ld_stream_complete(struct io_conn *conn, struct json_stream *js,
		   struct plugin *plugin)
{
	assert(tal_count(plugin->js_arr) > 0);
	/* Remove js and shift all remainig over */
	tal_arr_remove(&plugin->js_arr, 0);

	/* It got dropped off the queue, free it. */
	tal_free(js);

	return ld_write_json(conn, plugin);
}

static struct io_plan *ld_write_json(struct io_conn *conn,
				     struct plugin *plugin)
{
	if (tal_count(plugin->js_arr) > 0)
		return json_stream_output(plugin->js_arr[0], plugin->stdout_conn,
					  ld_stream_complete, plugin);

	return io_out_wait(conn, plugin, ld_write_json, plugin);
}

static void ld_conn_finish(struct io_conn *conn, struct plugin *plugin)
{
	/* Without one of the conns there is no reason to stay alive. That
	 * certainly means lightningd died, since there is no cleaner way
	 * to stop, return 0. */
	exit(0);
}

/* lightningd writes on our stdin */
static struct io_plan *stdin_conn_init(struct io_conn *conn,
				       struct plugin *plugin)
{
	plugin->stdin_conn = conn;
	io_set_finish(conn, ld_conn_finish, plugin);
	return io_read_partial(plugin->stdin_conn, plugin->buffer,
			       tal_bytelen(plugin->buffer), &plugin->len_read,
			       ld_read_json, plugin);
}

/* lightningd reads from our stdout */
static struct io_plan *stdout_conn_init(struct io_conn *conn,
                                        struct plugin *plugin)
{
	plugin->stdout_conn = conn;
	io_set_finish(conn, ld_conn_finish, plugin);
	return io_wait(plugin->stdout_conn, plugin, ld_write_json, plugin);
}

static struct plugin *new_plugin(const tal_t *ctx,
				 void (*init)(struct plugin *p,
					      const char *buf, const jsmntok_t *),
				 const enum plugin_restartability restartability,
				 struct feature_set *features,
				 const struct plugin_command *commands,
				 size_t num_commands,
				 const struct plugin_notification *notif_subs,
				 size_t num_notif_subs,
				 const struct plugin_hook *hook_subs,
				 size_t num_hook_subs,
				 va_list ap)
{
	const char *optname;
	struct plugin *p = tal(ctx, struct plugin);

	p->buffer = tal_arr(p, char, 64);
	p->js_arr = tal_arr(p, struct json_stream *, 0);
	p->used = 0;
	p->len_read = 0;
	/* Async RPC */
	p->rpc_buffer = tal_arr(p, char, 64);
	p->rpc_js_arr = tal_arr(p, struct json_stream *, 0);
	p->rpc_used = 0;
	p->rpc_len_read = 0;
	p->next_outreq_id = 0;
	uintmap_init(&p->out_reqs);

	p->our_features = features;
	/* Sync RPC FIXME: maybe go full async ? */
	p->rpc_conn = tal(p, struct rpc_conn);
	membuf_init(&p->rpc_conn->mb,
		    tal_arr(p, char, READ_CHUNKSIZE), READ_CHUNKSIZE,
		    membuf_tal_realloc);

	p->init = init;
	p->manifested = p->initialized = false;
	p->restartability = restartability;
	strmap_init(&p->usagemap);
	p->in_timer = 0;

	p->commands = commands;
	p->num_commands = num_commands;
	p->notif_subs = notif_subs;
	p->num_notif_subs = num_notif_subs;
	p->hook_subs = hook_subs;
	p->num_hook_subs = num_hook_subs;
	p->opts = tal_arr(p, struct plugin_option, 0);

	while ((optname = va_arg(ap, const char *)) != NULL) {
		struct plugin_option o;
		o.name = optname;
		o.type = va_arg(ap, const char *);
		o.description = va_arg(ap, const char *);
		o.handle = va_arg(ap, char *(*)(const char *str, void *arg));
		o.arg = va_arg(ap, void *);
		tal_arr_expand(&p->opts, o);
	}

	return p;
}

void plugin_main(char *argv[],
		 void (*init)(struct plugin *p,
			      const char *buf, const jsmntok_t *),
		 const enum plugin_restartability restartability,
		 struct feature_set *features,
		 const struct plugin_command *commands,
		 size_t num_commands,
		 const struct plugin_notification *notif_subs,
		 size_t num_notif_subs,
		 const struct plugin_hook *hook_subs,
		 size_t num_hook_subs,
		 ...)
{
	struct plugin *plugin;
	va_list ap;

	setup_locale();

	daemon_maybe_debug(argv);

	/* Note this already prints to stderr, which is enough for now */
	daemon_setup(argv[0], NULL, NULL);

	va_start(ap, num_hook_subs);
	plugin = new_plugin(NULL, init, restartability, features, commands,
			    num_commands, notif_subs, num_notif_subs, hook_subs,
			    num_hook_subs, ap);
	va_end(ap);
	setup_command_usage(plugin);

	timers_init(&plugin->timers, time_mono());

	io_new_conn(plugin, STDIN_FILENO, stdin_conn_init, plugin);
	io_new_conn(plugin, STDOUT_FILENO, stdout_conn_init, plugin);

	for (;;) {
		struct timer *expired = NULL;

		clean_tmpctx();

		/* Will only exit if a timer has expired. */
		io_loop(&plugin->timers, &expired);
		call_plugin_timer(plugin, expired);
	}

	tal_free(plugin);
}

static struct listpeers_channel *json_to_listpeers_channel(const tal_t *ctx,
							   const char *buffer,
							   const jsmntok_t *tok)
{
	struct listpeers_channel *chan;
	const jsmntok_t *privtok = json_get_member(buffer, tok, "private"),
			*statetok = json_get_member(buffer, tok, "state"),
			*ftxidtok =
			    json_get_member(buffer, tok, "funding_txid"),
			*scidtok =
			    json_get_member(buffer, tok, "short_channel_id"),
			*dirtok = json_get_member(buffer, tok, "direction"),
			*tmsattok =
			    json_get_member(buffer, tok, "total_msat"),
			*smsattok =
			    json_get_member(buffer, tok, "spendable_msat");

	if (privtok == NULL || privtok->type != JSMN_PRIMITIVE ||
	    statetok == NULL || statetok->type != JSMN_STRING ||
	    ftxidtok == NULL || ftxidtok->type != JSMN_STRING ||
	    (scidtok != NULL && scidtok->type != JSMN_STRING) ||
	    (dirtok != NULL && dirtok->type != JSMN_PRIMITIVE) ||
	    tmsattok == NULL || tmsattok->type != JSMN_STRING ||
	    smsattok == NULL || smsattok->type != JSMN_STRING)
		return NULL;

	chan = tal(ctx, struct listpeers_channel);

	json_to_bool(buffer, privtok, &chan->private);
	chan->state = json_strdup(chan, buffer, statetok);
	json_to_txid(buffer, ftxidtok, &chan->funding_txid);
	if (scidtok != NULL) {
		assert(dirtok != NULL);
		chan->scid = tal(chan, struct short_channel_id);
		chan->direction = tal(chan, int);
		json_to_short_channel_id(buffer, scidtok, chan->scid);
		json_to_int(buffer, dirtok, chan->direction);
	}else {
		assert(dirtok == NULL);
		chan->scid = NULL;
		chan->direction = NULL;
	}

	json_to_msat(buffer, tmsattok, &chan->total_msat);
	json_to_msat(buffer, smsattok, &chan->spendable_msat);

	return chan;
}

static struct listpeers_peer *json_to_listpeers_peer(const tal_t *ctx,
						  const char *buffer,
						  const jsmntok_t *tok)
{
	struct listpeers_peer *res;
	size_t i;
	const jsmntok_t *iter;
	const jsmntok_t *idtok = json_get_member(buffer, tok, "id"),
			*conntok = json_get_member(buffer, tok, "connected"),
			*netaddrtok = json_get_member(buffer, tok, "netaddr"),
			*channelstok = json_get_member(buffer, tok, "channels");

	/* Preliminary sanity checks. */
	if (idtok == NULL || idtok->type != JSMN_STRING || conntok == NULL ||
	    conntok->type != JSMN_PRIMITIVE ||
	    (netaddrtok != NULL && netaddrtok->type != JSMN_ARRAY) ||
	    channelstok == NULL || channelstok->type != JSMN_ARRAY)
		return NULL;

	res = tal(ctx, struct listpeers_peer);
	json_to_node_id(buffer, idtok, &res->id);
	json_to_bool(buffer, conntok, &res->connected);

	res->netaddr = tal_arr(res, const char *, 0);
	if (netaddrtok != NULL) {
		json_for_each_arr(i, iter, netaddrtok) {
			tal_arr_expand(&res->netaddr,
				       json_strdup(res, buffer, iter));
		}
	}

	res->channels = tal_arr(res, struct listpeers_channel *, 0);
	json_for_each_arr(i, iter, channelstok) {
		struct listpeers_channel *chan = json_to_listpeers_channel(res, buffer, iter);
		assert(chan != NULL);
		tal_arr_expand(&res->channels, chan);
	}

	return res;
}

struct listpeers_result *json_to_listpeers_result(const tal_t *ctx,
							  const char *buffer,
							  const jsmntok_t *toks)
{
	size_t i;
	const jsmntok_t *iter;
	struct listpeers_result *res;
	const jsmntok_t *peerstok = json_get_member(buffer, toks, "peers");

	if (peerstok == NULL || peerstok->type != JSMN_ARRAY)
		return NULL;

	res = tal(ctx, struct listpeers_result);
	res->peers = tal_arr(res, struct listpeers_peer *, 0);

	json_for_each_obj(i, iter, peerstok) {
		struct listpeers_peer *p =
		    json_to_listpeers_peer(res, buffer, iter);
		if (p == NULL)
			return tal_free(res);
		tal_arr_expand(&res->peers, p);
	}
	return res;
}

struct createonion_response *json_to_createonion_response(const tal_t *ctx,
							  const char *buffer,
							  const jsmntok_t *toks)
{
	size_t i;
	struct createonion_response *resp;
	const jsmntok_t *oniontok = json_get_member(buffer, toks, "onion");
	const jsmntok_t *secretstok = json_get_member(buffer, toks, "shared_secrets");
	const jsmntok_t *cursectok;

	if (oniontok == NULL || secretstok == NULL)
		return NULL;

	resp = tal(ctx, struct createonion_response);

	if (oniontok->type != JSMN_STRING)
		goto fail;

	resp->onion = json_tok_bin_from_hex(resp, buffer, oniontok);
	resp->shared_secrets = tal_arr(resp, struct secret, secretstok->size);

	json_for_each_arr(i, cursectok, secretstok) {
		if (cursectok->type != JSMN_STRING)
			goto fail;
		json_to_secret(buffer, cursectok, &resp->shared_secrets[i]);
	}
	return resp;

fail:
	return tal_free(resp);
}

static bool json_to_route_hop_inplace(struct route_hop *dst, const char *buffer,
				      const jsmntok_t *toks)
{
	const jsmntok_t *idtok = json_get_member(buffer, toks, "id");
	const jsmntok_t *channeltok = json_get_member(buffer, toks, "channel");
	const jsmntok_t *directiontok = json_get_member(buffer, toks, "direction");
	const jsmntok_t *amounttok = json_get_member(buffer, toks, "amount_msat");
	const jsmntok_t *delaytok = json_get_member(buffer, toks, "delay");
	const jsmntok_t *styletok = json_get_member(buffer, toks, "style");

	if (idtok == NULL || channeltok == NULL || directiontok == NULL ||
	    amounttok == NULL || delaytok == NULL || styletok == NULL)
		return false;

	json_to_node_id(buffer, idtok, &dst->nodeid);
	json_to_short_channel_id(buffer, channeltok, &dst->channel_id);
	json_to_int(buffer, directiontok, &dst->direction);
	json_to_msat(buffer, amounttok, &dst->amount);
	json_to_number(buffer, delaytok, &dst->delay);
	dst->style = json_tok_streq(buffer, styletok, "legacy")
			 ? ROUTE_HOP_LEGACY
			 : ROUTE_HOP_TLV;
	return true;
}

struct route_hop *json_to_route(const tal_t *ctx, const char *buffer,
				const jsmntok_t *toks)
{
	size_t num = toks->size, i;
	struct route_hop *hops;
	const jsmntok_t *rtok;
	if (toks->type != JSMN_ARRAY)
		return NULL;

	hops = tal_arr(ctx, struct route_hop, num);
	json_for_each_arr(i, rtok, toks) {
		if (!json_to_route_hop_inplace(&hops[i], buffer, rtok))
			return tal_free(hops);
	}
	return hops;
}
