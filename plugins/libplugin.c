#include "config.h"
#include <bitcoin/chainparams.h>
#include <bitcoin/privkey.h>
#include <ccan/io/io.h>
#include <ccan/json_out/json_out.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/tal/path/path.h>
#include <ccan/tal/str/str.h>
#include <common/daemon.h>
#include <common/deprecation.h>
#include <common/json_filter.h>
#include <common/json_param.h>
#include <common/json_parse_simple.h>
#include <common/json_stream.h>
#include <common/memleak.h>
#include <common/plugin.h>
#include <common/route.h>
#include <errno.h>
#include <plugins/libplugin.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>

#define READ_CHUNKSIZE 4096

struct plugin_timer {
	struct timer timer;
	const char *id;
	struct command_result *(*cb)(struct command *cmd, void *cb_arg);
	void *cb_arg;
};

struct rpc_conn {
	int fd;
	MEMBUF(char) mb;
};

/* We can have more than one of these pending at once. */
struct jstream {
	struct list_node list;
	struct json_stream *js;
};

/* Create an array of these, one for each --option you support. */
struct plugin_option {
	const char *name;
	const char *type;
	const char *description;
	/* Handle an option.  If dynamic, check_only may be set to check
	 * for validity (but must not make any changes!) */
	char *(*handle)(struct plugin *plugin, const char *str, bool check_only,
			void *arg);
	/* Print an option (used to show the default value, if returns true) */
	bool (*jsonfmt)(struct plugin *plugin, struct json_stream *js, const char *fieldname,
			void *arg);
	/* Arg for handle and jsonfmt */
	void *arg;
	/* If true, this option requires --developer to be enabled */
	bool dev_only;
	/* If it's deprecated from a particular release (or NULL) */
	const char *depr_start, *depr_end;
	/* If true, allow setting after plugin has initialized */
	bool dynamic;
};

struct plugin {
	/* lightningd interaction */
	struct io_conn *stdin_conn;
	struct io_conn *stdout_conn;

	/* Are we in developer mode? */
	bool developer;

	/* Global deprecations enabled? */
	bool deprecated_ok;

	/* Is this command overriding global deprecated_ok? */
	bool *deprecated_ok_override;

	/* to append to all our command ids */
	const char *id;

	/* Data for the plugin user */
	void *data;

	/* options to i-promise-to-fix-broken-api-user */
	const char **beglist;

	/* To read from lightningd */
	char *buffer;
	size_t used, len_read;
	jsmn_parser parser;
	jsmntok_t *toks;

	/* To write to lightningd */
	struct list_head js_list;

	/* Asynchronous RPC interaction */
	struct io_conn *io_rpc_conn;
	struct list_head rpc_js_list;
	char *rpc_buffer;
	size_t rpc_used, rpc_len_read, rpc_read_offset;
	jsmn_parser rpc_parser;
	jsmntok_t *rpc_toks;
	/* Tracking async RPC requests */
	STRMAP(struct out_req *) out_reqs;
	u64 next_outreq_id;

	/* Synchronous RPC interaction */
	struct rpc_conn *rpc_conn;

	/* Plugin information details */
	enum plugin_restartability restartability;
	const struct plugin_command *commands;
	size_t num_commands;
	const struct plugin_notification *notif_subs;
	size_t num_notif_subs;
	const struct plugin_hook *hook_subs;
	size_t num_hook_subs;
	struct plugin_option *opts;

	/* Anything special to do at init ? */
	const char *(*init)(struct plugin *p,
			    const char *buf, const jsmntok_t *);
	/* Has the manifest been sent already ? */
	bool manifested;
	/* Has init been received ? */
	bool initialized;
	/* Are we exiting? */
	bool exiting;

	/* Map from json command names to usage strings: we don't put this inside
	 * struct json_command as it's good practice to have those const. */
	STRMAP(const char *) usagemap;
	/* Timers */
	struct timers timers;

	/* Feature set for lightningd */
	struct feature_set *our_features;
	/* Features we want to add to lightningd */
	const struct feature_set *desired_features;

	/* Location of the RPC filename in case we need to defer RPC
	 * initialization or need to recover from a disconnect. */
	const char *rpc_location;

	const char **notif_topics;
	size_t num_notif_topics;

	/* Lets them remove ptrs from leak detection. */
	void (*mark_mem)(struct plugin *plugin, struct htable *memtable);
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

struct json_filter **command_filter_ptr(struct command *cmd)
{
	return &cmd->filter;
}

static void complain_deprecated_nocmd(const char *feature,
				      bool allowing,
				      struct plugin *plugin)
{
	if (!allowing) {
		/* Mild log message for disallowing */
		plugin_log(plugin, LOG_DBG,
			   "Note: disallowing deprecated %s",
			   feature);
	} else {
		plugin_log(plugin, LOG_BROKEN,
			   "DEPRECATED API USED: %s",
			   feature);
	}
}

/* New command, without a filter */
static struct command *new_command(const tal_t *ctx,
				   struct plugin *plugin,
				   const char *id TAKES,
				   const char *methodname TAKES,
				   enum command_type type)
{
	struct command *cmd = tal(ctx, struct command);

	cmd->plugin = plugin;
	cmd->type = type;
	cmd->filter = NULL;
	cmd->methodname = tal_strdup(cmd, methodname);
	cmd->id = tal_strdup(cmd, id);
	return cmd;
}

bool command_deprecated_in_nocmd_ok(struct plugin *plugin,
				    const char *name,
				    const char *depr_start,
				    const char *depr_end)
{
	return deprecated_ok(plugin->deprecated_ok,
			     name,
			     depr_start, depr_end,
			     plugin->beglist,
			     complain_deprecated_nocmd, plugin);
}

static void complain_deprecated(const char *feature,
				bool allowing,
				struct command *cmd)
{
	if (!allowing) {
		/* Mild log message for disallowing */
		plugin_log(cmd->plugin, LOG_DBG,
			   "Note: disallowing deprecated %s for %s",
			   feature, cmd->id);
	} else {
		plugin_log(cmd->plugin, LOG_BROKEN,
			   "DEPRECATED API USED: %s by %s",
			   feature, cmd->id);
	}
}

bool command_deprecated_in_named_ok(struct command *cmd,
				    const char *cmdname,
				    const char *param,
				    const char *depr_start,
				    const char *depr_end)
{
	return deprecated_ok(command_deprecated_ok_flag(cmd),
			     param
			     ? tal_fmt(tmpctx, "%s.%s", cmdname, param)
			     : cmdname,
			     depr_start, depr_end,
			     cmd->plugin->beglist,
			     complain_deprecated, cmd);
}

bool command_deprecated_in_ok(struct command *cmd,
			      const char *param,
			      const char *depr_start,
			      const char *depr_end)
{
	return command_deprecated_in_named_ok(cmd, cmd->methodname, param,
					      depr_start, depr_end);
}

bool command_deprecated_out_ok(struct command *cmd,
			       const char *fieldname,
			       const char *depr_start,
			       const char *depr_end)
{
	return deprecated_ok(command_deprecated_ok_flag(cmd),
			     tal_fmt(tmpctx, "%s.%s", cmd->methodname, fieldname),
			     depr_start, depr_end,
			     /* FIXME: Get api begs from lightningd! */
			     NULL,
			     NULL, NULL);
}

static void ld_send(struct plugin *plugin, struct json_stream *stream)
{
	struct jstream *jstr = tal(plugin, struct jstream);
	jstr->js = tal_steal(jstr, stream);
	list_add_tail(&plugin->js_list, &jstr->list);
	io_wake(plugin);
}

static void ld_rpc_send(struct plugin *plugin, struct json_stream *stream)
{
	struct jstream *jstr = tal(plugin, struct jstream);
	jstr->js = tal_steal(jstr, stream);
	list_add_tail(&plugin->rpc_js_list, &jstr->list);
	io_wake(plugin->io_rpc_conn);
}


/* When cmd for request is gone, we use this as noop callback */
static struct command_result *ignore_cb(struct command *command,
					const char *buf,
					const jsmntok_t *result,
					void *arg)
{
	return &complete;
}

static void disable_request_cb(struct command *cmd, struct out_req *out)
{
	out->errcb = NULL;
	out->cb = ignore_cb;
	/* Called because cmd got free'd */
	out->cmd = NULL;
}

const char *json_id_prefix(const tal_t *ctx, const struct command *cmd)
{
	/* Strip quotes! */
	if (strstarts(cmd->id, "\"")) {
		assert(strlen(cmd->id) >= 2);
		assert(strends(cmd->id, "\""));
		return tal_fmt(ctx, "%.*s/",
			       (int)strlen(cmd->id) - 2, cmd->id + 1);
	}
	return tal_fmt(ctx, "%s/", cmd->id);
}

static const char *append_json_id(const tal_t *ctx,
				  struct plugin *plugin,
				  const char *method,
				  const char *prefix)
{
	return tal_fmt(ctx, "\"%s%s:%s#%"PRIu64"\"",
		       prefix, plugin->id, method, plugin->next_outreq_id++);
}

static void destroy_out_req(struct out_req *out_req, struct plugin *plugin)
{
	strmap_del(&plugin->out_reqs, out_req->id, NULL);
}

/* FIXME: Move lightningd/jsonrpc to common/ ? */

struct out_req *
jsonrpc_request_start_(struct plugin *plugin, struct command *cmd,
		       const char *method,
		       const char *id_prefix,
		       const char *filter,
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

	assert(cmd);
	out = tal(cmd, struct out_req);
	out->id = append_json_id(out, plugin, method, id_prefix);
	out->cmd = cmd;
	out->cb = cb;
	out->errcb = errcb;
	out->arg = arg;
	strmap_add(&plugin->out_reqs, out->id, out);
	tal_add_destructor2(out, destroy_out_req, plugin);

	/* If command goes away, don't call callbacks! */
	tal_add_destructor2(out->cmd, disable_request_cb, out);

	out->js = new_json_stream(NULL, cmd, NULL);
	json_object_start(out->js, NULL);
	json_add_string(out->js, "jsonrpc", "2.0");
	json_add_id(out->js, out->id);
	json_add_string(out->js, "method", method);
	if (filter) {
		/* This is raw JSON, so paste, don't escape! */
		size_t len = strlen(filter);
		char *p = json_out_member_direct(out->js->jout, "filter", len);
		memcpy(p, filter, len);
	}
	if (out->errcb)
		json_object_start(out->js, "params");

	return out;
}

const struct feature_set *plugin_feature_set(const struct plugin *p)
{
	return p->our_features;
}

static void jsonrpc_finish_and_send(struct plugin *p, struct json_stream *js)
{
	json_object_end(js);
	json_stream_close(js, NULL);
	ld_send(p, js);
}

static struct json_stream *jsonrpc_stream_start(struct command *cmd)
{
	struct json_stream *js = new_json_stream(cmd, cmd, NULL);

	json_object_start(js, NULL);
	json_add_string(js, "jsonrpc", "2.0");
	json_add_id(js, cmd->id);

	return js;
}

struct json_stream *jsonrpc_stream_success(struct command *cmd)
{
	struct json_stream *js = jsonrpc_stream_start(cmd);
	assert(cmd->type == COMMAND_TYPE_NORMAL
	       || cmd->type == COMMAND_TYPE_HOOK);

	json_object_start(js, "result");
	if (cmd->filter)
		json_stream_attach_filter(js, cmd->filter);
	return js;
}

struct json_stream *jsonrpc_stream_fail(struct command *cmd,
					int code,
					const char *err)
{
	struct json_stream *js = jsonrpc_stream_start(cmd);

	assert(cmd->type == COMMAND_TYPE_NORMAL
	       || cmd->type == COMMAND_TYPE_CHECK);
	json_object_start(js, "error");
	json_add_primitive_fmt(js, "code", "%d", code);
	json_add_string(js, "message", err);
	cmd->filter = tal_free(cmd->filter);

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
	json_object_end(result);
	json_stream_close(result, cmd);
	ld_send(cmd->plugin, result);
	tal_free(cmd);

	return &complete;
}

struct command_result *command_finished(struct command *cmd,
					struct json_stream *response)
{
	assert(cmd->type == COMMAND_TYPE_NORMAL
	       || cmd->type == COMMAND_TYPE_HOOK
	       || cmd->type == COMMAND_TYPE_CHECK);

	/* Detach filter before it complains about closing object it never saw */
	if (cmd->filter) {
		const char *err = json_stream_detach_filter(tmpctx, response);
		if (err)
			json_add_string(response, "warning_parameter_filter",
					err);
	}

	/* "result" or "error" object */
	json_object_end(response);

	return command_complete(cmd, response);
}

struct command_result *WARN_UNUSED_RESULT
command_still_pending(struct command *cmd)
{
	notleak_with_children(cmd);
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
	assert(cmd->type == COMMAND_TYPE_NORMAL
	       || cmd->type == COMMAND_TYPE_HOOK);

	json_out_add_splice(js->jout, "result", result);
	return command_complete(cmd, js);
}

struct command_result *command_done_err(struct command *cmd,
					enum jsonrpc_errcode code,
					const char *errmsg,
					const struct json_out *data)
{
	struct json_stream *js = jsonrpc_stream_start(cmd);
	assert(cmd->type == COMMAND_TYPE_NORMAL
	       || cmd->type == COMMAND_TYPE_CHECK);

	json_object_start(js, "error");
	json_add_jsonrpc_errcode(js, "code", code);
	json_add_string(js, "message", errmsg);

	if (data)
		json_out_add_splice(js->jout, "data", data);
	json_object_end(js);

	return command_complete(cmd, js);
}

struct command_result *command_err_raw(struct command *cmd,
				       const char *json_str)
{
	assert(cmd->type == COMMAND_TYPE_NORMAL
	       || cmd->type == COMMAND_TYPE_CHECK);
	return command_done_raw(cmd, "error",
				json_str, strlen(json_str));
}

struct command_result *timer_complete(struct command *cmd)
{
	assert(cmd->type == COMMAND_TYPE_TIMER);
	tal_free(cmd);
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
				    enum jsonrpc_errcode code, const char *fmt, ...)
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
	return cmd->type == COMMAND_TYPE_USAGE_ONLY;
}

bool command_dev_apis(const struct command *cmd)
{
	return cmd->plugin->developer;
}

bool command_check_only(const struct command *cmd)
{
	return cmd->type == COMMAND_TYPE_CHECK;
}

void command_log(struct command *cmd, enum log_level level,
		 const char *fmt, ...)
{
	const char *msg;
	va_list ap;

	va_start(ap, fmt);
	msg = tal_vfmt(cmd, fmt, ap);
	plugin_log(cmd->plugin, level, "JSON COMMAND %s: %s",
		   cmd->methodname, msg);
	va_end(ap);
}

struct command_result *command_check_done(struct command *cmd)
{
	struct json_stream *js = jsonrpc_stream_start(cmd);
	assert(command_check_only(cmd));

	json_out_add_splice(js->jout, "result",
			    json_out_obj(cmd, "command_to_check",
					 cmd->methodname));
	return command_complete(cmd, js);
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

	do {
		*reqlen = read_json_from_rpc(plugin);

		toks = json_parse_simple(ctx,
					 membuf_elems(&plugin->rpc_conn->mb),
					 *reqlen);
		if (!toks)
			plugin_err(plugin, "Malformed JSON reply '%.*s'",
				   *reqlen, membuf_elems(&plugin->rpc_conn->mb));
		/* FIXME: Don't simply ignore notifications here! */
	} while (!json_get_member(membuf_elems(&plugin->rpc_conn->mb), toks,
				  "id"));

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

/* Send request, return response, set resp/len to reponse */
static const jsmntok_t *sync_req(const tal_t *ctx,
				 struct plugin *plugin,
				 const char *method,
				 const struct json_out *params TAKES,
				 const char **resp)
{
	bool error;
	const jsmntok_t *contents;
	int reqlen;
	struct json_out *jout = json_out_new(tmpctx);
	const char *id = append_json_id(tmpctx, plugin, method, "init/");

	json_out_start(jout, NULL, '{');
	json_out_addstr(jout, "jsonrpc", "2.0");
	/* Copy in id *literally* */
	memcpy(json_out_member_direct(jout, "id", strlen(id)), id, strlen(id));
	json_out_addstr(jout, "method", method);
	json_out_add_splice(jout, "params", params);
	if (taken(params))
		tal_free(params);
	finish_and_send_json(plugin->rpc_conn->fd, jout);

	read_rpc_reply(ctx, plugin, &contents, &error, &reqlen);
	if (error)
		plugin_err(plugin, "Got error reply to %s: '%.*s'",
			   method, reqlen, membuf_elems(&plugin->rpc_conn->mb));

	*resp = membuf_consume(&plugin->rpc_conn->mb, reqlen);
	return contents;
}

const jsmntok_t *jsonrpc_request_sync(const tal_t *ctx, struct plugin *plugin,
				      const char *method,
				      const struct json_out *params TAKES,
				      const char **resp)
{
	return sync_req(ctx, plugin, method, params, resp);
}

/* Returns contents of scanning guide on 'result' */
static const char *rpc_scan_core(const tal_t *ctx,
				 struct plugin *plugin,
				 const char *method,
				 const struct json_out *params TAKES,
				 const char *guide,
				 va_list ap)
{
	const jsmntok_t *contents;
	const char *p;

	contents = sync_req(tmpctx, plugin, method, params, &p);
	return json_scanv(ctx, p, contents, guide, ap);
}

/* Synchronous routine to send command and extract fields from response */
void rpc_scan(struct plugin *plugin,
	      const char *method,
	      const struct json_out *params TAKES,
	      const char *guide,
	      ...)
{
	const char *err;
	va_list ap;

	va_start(ap, guide);
	err = rpc_scan_core(tmpctx, plugin, method, params, guide, ap);
	va_end(ap);

	if (err)
		plugin_err(plugin, "Could not parse %s in reply to %s: %s",
			   guide, method, err);
}

static void json_add_keypath(struct json_out *jout, const char *fieldname, const char *path)
{
	char **parts = tal_strsplit(tmpctx, path, "/", STR_EMPTY_OK);

	json_out_start(jout, fieldname, '[');
	for (size_t i = 0; parts[i]; parts++)
		json_out_addstr(jout, NULL, parts[i]);
	json_out_end(jout, ']');
}

static const char *rpc_scan_datastore(const tal_t *ctx,
				      struct plugin *plugin,
				      const char *path,
				      const char *hex_or_string,
				      va_list ap)
{
	const char *guide;
	struct json_out *params;

	params = json_out_new(NULL);
	json_out_start(params, NULL, '{');
	json_add_keypath(params, "key", path);
	json_out_end(params, '}');
	json_out_finished(params);

	guide = tal_fmt(tmpctx, "{datastore:[0:{%s:%%}]}", hex_or_string);
	return rpc_scan_core(ctx, plugin, "listdatastore", take(params),
			     guide, ap);
}

const char *rpc_scan_datastore_str(const tal_t *ctx,
				   struct plugin *plugin,
				   const char *path,
				   ...)
{
	const char *ret;
	va_list ap;

	va_start(ap, path);
	ret = rpc_scan_datastore(ctx, plugin, path, "string", ap);
	va_end(ap);
	return ret;
}

/* This variant scans the hex encoding, not the string */
const char *rpc_scan_datastore_hex(const tal_t *ctx,
				   struct plugin *plugin,
				   const char *path,
				   ...)
{
	const char *ret;
	va_list ap;

	va_start(ap, path);
	ret = rpc_scan_datastore(ctx, plugin, path, "hex", ap);
	va_end(ap);
	return ret;
}

void rpc_enable_batching(struct plugin *plugin)
{
	const char *p;
	struct json_out *params;

	params = json_out_new(NULL);
	json_out_start(params, NULL, '{');
	json_out_add(params, "enable", false, "true");
	json_out_end(params, '}');
	json_out_finished(params);

	/* We don't actually care about (empty) response */
	sync_req(tmpctx, plugin, "batching", take(params), &p);
}

static struct command_result *datastore_fail(struct command *command,
					     const char *buf,
					     const jsmntok_t *result,
					     void *unused)
{
	plugin_err(command->plugin, "datastore failed: %.*s",
		   json_tok_full_len(result),
		   json_tok_full(buf, result));
}

struct command_result *jsonrpc_set_datastore_(struct plugin *plugin,
					      struct command *cmd,
					      const char *path,
					      const void *value,
					      bool value_is_string,
					      const char *mode,
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
	struct out_req *req;

	if (!cb)
		cb = ignore_cb;
	if (!errcb)
		errcb = datastore_fail;

	req = jsonrpc_request_start(plugin, cmd, "datastore", cb, errcb, arg);

	json_add_keypath(req->js->jout, "key", path);
	if (value_is_string)
		json_add_string(req->js, "string", value);
	else
		json_add_hex_talarr(req->js, "hex", value);
	json_add_string(req->js, "mode", mode);
	return send_outreq(plugin, req);
}

struct get_ds_info {
	struct command_result *(*string_cb)(struct command *command,
					    const char *val,
					    void *arg);
	struct command_result *(*binary_cb)(struct command *command,
					    const u8 *val,
					    void *arg);
	void *arg;
};

static struct command_result *listdatastore_done(struct command *cmd,
						 const char *buf,
						 const jsmntok_t *result,
						 struct get_ds_info *dsi)
{
	const jsmntok_t *ds = json_get_member(buf, result, "datastore");
	void *val;

	if (ds->size == 0)
		val = NULL;
	else {
		/* First element in array is object */
		ds = ds + 1;
		if (dsi->string_cb) {
			const jsmntok_t *s;
			s = json_get_member(buf, ds, "string");
			if (!s) {
				/* Complain loudly, since they
				 * expected string! */
				plugin_log(cmd->plugin, LOG_BROKEN,
					   "Datastore gave nonstring result %.*s",
					   json_tok_full_len(result),
					   json_tok_full(buf, result));
				val = NULL;
			} else {
				val = json_strdup(cmd, buf, s);
			}
		} else {
			const jsmntok_t *hex;
			hex = json_get_member(buf, ds, "hex");
			val = json_tok_bin_from_hex(cmd, buf, hex);
		}
	}

	if (dsi->string_cb)
		return dsi->string_cb(cmd, val, dsi->arg);
	return dsi->binary_cb(cmd, val, dsi->arg);
}

struct command_result *jsonrpc_get_datastore_(struct plugin *plugin,
					      struct command *cmd,
					      const char *path,
					      struct command_result *(*string_cb)(struct command *command,
									   const char *val,
									   void *arg),
					      struct command_result *(*binary_cb)(struct command *command,
									   const u8 *val,
									   void *arg),
					      void *arg)
{
	struct out_req *req;
	struct get_ds_info *dsi = tal(NULL, struct get_ds_info);

	dsi->string_cb = string_cb;
	dsi->binary_cb = binary_cb;
	dsi->arg = arg;

	/* listdatastore doesn't fail (except API misuse) */
	req = jsonrpc_request_start(plugin, cmd, "listdatastore",
				    listdatastore_done, datastore_fail, dsi);
	tal_steal(req, dsi);

	json_add_keypath(req->js->jout, "key", path);
	return send_outreq(plugin, req);
}

static void handle_rpc_reply(struct plugin *plugin, const jsmntok_t *toks)
{
	const jsmntok_t *idtok, *contenttok;
	struct out_req *out;
	struct command_result *res;
	const char *buf = plugin->rpc_buffer + plugin->rpc_read_offset;

	idtok = json_get_member(buf, toks, "id");
	if (!idtok)
		/* FIXME: Don't simply ignore notifications! */
		return;

	out = strmap_getn(&plugin->out_reqs,
			  json_tok_full(buf, idtok),
			  json_tok_full_len(idtok));
	if (!out) {
		/* This can actually happen, if they free req! */
		plugin_log(plugin, LOG_DBG, "JSON reply with unknown id '%.*s'",
			   json_tok_full_len(toks),
			   json_tok_full(buf, toks));
		return;
	}

	/* Remove destructor if one existed */
	tal_del_destructor2(out->cmd, disable_request_cb, out);

	/* We want to free this if callback doesn't. */
	tal_steal(tmpctx, out);

	contenttok = json_get_member(buf, toks, "error");
	if (contenttok) {
		if (out->errcb)
			res = out->errcb(out->cmd, buf, contenttok, out->arg);
		else
			res = out->cb(out->cmd, buf, toks, out->arg);
	} else {
		contenttok = json_get_member(buf, toks, "result");
		if (!contenttok)
			plugin_err(plugin, "Bad JSONRPC, no 'error' nor 'result': '%.*s'",
				   json_tok_full_len(toks),
				   json_tok_full(buf, toks));
		/* errcb is NULL if it's a single whole-object callback */
		if (out->errcb)
			res = out->cb(out->cmd, buf, contenttok, out->arg);
		else
			res = out->cb(out->cmd, buf, toks, out->arg);
	}

	assert(res == &pending || res == &complete);
}

struct command_result *
send_outreq(struct plugin *plugin, const struct out_req *req)
{
	/* The "param" object. */
	if (req->errcb)
		json_object_end(req->js);
	json_object_end(req->js);
	json_stream_close(req->js, req->cmd);

	ld_rpc_send(plugin, req->js);

	if (req->cmd != NULL)
		notleak_with_children(req->cmd);
	return &pending;
}

struct request_batch {
	size_t num_remaining;

	struct command_result *(*cb)(struct command *,
				     const char *,
				     const jsmntok_t *,
				     void *);
	struct command_result *(*errcb)(struct command *,
					const char *,
					const jsmntok_t *,
					void *);
	struct command_result *(*finalcb)(struct command *,
					  void *);
	void *arg;
};

struct request_batch *request_batch_new_(const tal_t *ctx,
					 struct command_result *(*cb)(struct command *,
								      const char *,
								      const jsmntok_t *,
								      void *),
					 struct command_result *(*errcb)(struct command *,
									 const char *,
									 const jsmntok_t *,
									 void *),
					 struct command_result *(*finalcb)(struct command *,
									   void *),
					 void *arg)
{
	struct request_batch *batch = tal(ctx, struct request_batch);

	batch->num_remaining = 0;
	batch->cb = cb;
	batch->errcb = errcb;
	batch->finalcb = finalcb;
	batch->arg = arg;
	return batch;
}

static struct command_result *batch_one_complete(struct command *cmd,
						 struct request_batch *batch)
{
	void *arg;
	struct command_result *(*finalcb)(struct command *, void *);

	assert(batch->num_remaining);

	if (--batch->num_remaining != 0)
		return command_still_pending(cmd);

	arg = batch->arg;
	finalcb = batch->finalcb;
	tal_free(batch);
	return finalcb(cmd, arg);
}

static struct command_result *batch_one_success(struct command *cmd,
						const char *buf,
						const jsmntok_t *result,
						struct request_batch *batch)
{
	/* If this frees stuff (e.g. fails), just return */
	if (batch->cb && batch->cb(cmd, buf, result, batch->arg) == &complete)
		return &complete;
	return batch_one_complete(cmd, batch);
}

static struct command_result *batch_one_failed(struct command *cmd,
					       const char *buf,
					       const jsmntok_t *result,
					       struct request_batch *batch)
{
	/* If this frees stuff (e.g. fails), just return */
	if (batch->errcb && batch->errcb(cmd, buf, result, batch->arg) == &complete)
		return &complete;
	return batch_one_complete(cmd, batch);
}

struct out_req *add_to_batch(struct command *cmd,
			     struct request_batch *batch,
			     const char *cmdname)
{
	batch->num_remaining++;

	return jsonrpc_request_start(cmd->plugin, cmd, cmdname,
				     batch_one_success,
				     batch_one_failed,
				     batch);
}

/* Runs finalcb immediately if batch is empty. */
struct command_result *batch_done(struct command *cmd,
				  struct request_batch *batch)
{
	/* Same path as completion */
	batch->num_remaining++;
	return batch_one_complete(cmd, batch);
}

static void json_add_deprecated(struct json_stream *js,
				const char *fieldname,
				const char *depr_start, const char *depr_end)
{
	if (!depr_start)
		return;
	json_array_start(js, fieldname);
	json_add_string(js, NULL, depr_start);
	if (depr_end)
		json_add_string(js, NULL, depr_end);
	json_array_end(js);
}

static struct command_result *
handle_getmanifest(struct command *getmanifest_cmd,
		   const char *buf,
		   const jsmntok_t *getmanifest_params)
{
	struct json_stream *params = jsonrpc_stream_success(getmanifest_cmd);
	struct plugin *p = getmanifest_cmd->plugin;
	bool has_shutdown_notif;

	if (json_scan(tmpctx, buf, getmanifest_params,
		      "{allow-deprecated-apis:%}",
		      JSON_SCAN(json_to_bool, &p->deprecated_ok)) != NULL) {
		plugin_err(p, "Invalid allow-deprecated-apis in '%.*s'",
			   json_tok_full_len(getmanifest_params),
			   json_tok_full(buf, getmanifest_params));
	}

	json_array_start(params, "options");
	for (size_t i = 0; i < tal_count(p->opts); i++) {
		if (p->opts[i].dev_only && !p->developer)
			continue;
		json_object_start(params, NULL);
		json_add_string(params, "name", p->opts[i].name);
		json_add_string(params, "type", p->opts[i].type);
		json_add_string(params, "description", p->opts[i].description);
		json_add_deprecated(params, "deprecated", p->opts[i].depr_start, p->opts[i].depr_end);
		json_add_bool(params, "dynamic", p->opts[i].dynamic);
		if (p->opts[i].jsonfmt)
			p->opts[i].jsonfmt(p, params, "default", p->opts[i].arg);
		json_object_end(params);
	}
	json_array_end(params);

	json_array_start(params, "rpcmethods");
	for (size_t i = 0; i < p->num_commands; i++) {
		if (p->commands[i].dev_only && !p->developer)
			continue;
		json_object_start(params, NULL);
		json_add_string(params, "name", p->commands[i].name);
		json_add_string(params, "usage",
				strmap_get(&p->usagemap, p->commands[i].name));
		json_add_deprecated(params, "deprecated",
				    p->commands[i].depr_start, p->commands[i].depr_end);
		json_object_end(params);
	}
	json_array_end(params);

	json_array_start(params, "subscriptions");
	has_shutdown_notif = false;
	for (size_t i = 0; i < p->num_notif_subs; i++) {
		json_add_string(params, NULL, p->notif_subs[i].name);
		if (streq(p->notif_subs[i].name, "shutdown"))
			has_shutdown_notif = true;
	}
	/* For memleak detection, always get notified of shutdown. */
	if (!has_shutdown_notif && p->developer)
		json_add_string(params, NULL, "shutdown");
	json_add_string(params, NULL, "deprecated_oneshot");
	json_array_end(params);

	json_array_start(params, "hooks");
	for (size_t i = 0; i < p->num_hook_subs; i++) {
		json_object_start(params, NULL);
		json_add_string(params, "name", p->hook_subs[i].name);
		if (p->hook_subs[i].before) {
			json_array_start(params, "before");
			for (size_t j = 0; p->hook_subs[i].before[j]; j++)
				json_add_string(params, NULL,
						p->hook_subs[i].before[j]);
			json_array_end(params);
		}
		if (p->hook_subs[i].after) {
			json_array_start(params, "after");
			for (size_t j = 0; p->hook_subs[i].after[j]; j++)
				json_add_string(params, NULL,
						p->hook_subs[i].after[j]);
			json_array_end(params);
		}
		json_object_end(params);
	}
	json_array_end(params);

	if (p->desired_features != NULL) {
		json_object_start(params, "featurebits");
		for (size_t i = 0; i < NUM_FEATURE_PLACE; i++) {
			u8 *f = p->desired_features->bits[i];
			const char *fieldname = feature_place_names[i];
			if (fieldname == NULL)
				continue;
			json_add_hex(params, fieldname, f, tal_bytelen(f));
		}
		json_object_end(params);
	}

	json_add_bool(params, "dynamic", p->restartability == PLUGIN_RESTARTABLE);
	json_add_bool(params, "nonnumericids", true);
	json_add_bool(params, "cancheck", true);

	json_array_start(params, "notifications");
	for (size_t i = 0; p->notif_topics && i < p->num_notif_topics; i++) {
		json_object_start(params, NULL);
		json_add_string(params, "method", p->notif_topics[i]);
		json_object_end(params);
	}
	json_array_end(params);

	return command_finished(getmanifest_cmd, params);
}

static void rpc_conn_finished(struct io_conn *conn,
			      struct plugin *plugin)
{
	plugin_err(plugin, "Lost connection to the RPC socket.");
}

static bool rpc_read_response_one(struct plugin *plugin)
{
	const jsmntok_t *jrtok;
	bool complete;

	if (!json_parse_input(&plugin->rpc_parser, &plugin->rpc_toks,
			      plugin->rpc_buffer + plugin->rpc_read_offset,
			      plugin->rpc_used - plugin->rpc_read_offset,
			      &complete)) {
		plugin_err(plugin, "Failed to parse RPC JSON response '%.*s'",
			   (int)(plugin->rpc_used - plugin->rpc_read_offset),
			   plugin->rpc_buffer + plugin->rpc_read_offset);
	}

	if (!complete) {
		/* We need more. */
		goto compact;
	}

	/* Empty buffer? (eg. just whitespace). */
	if (tal_count(plugin->rpc_toks) == 1) {
		jsmn_init(&plugin->rpc_parser);
		toks_reset(plugin->rpc_toks);
		goto compact;
	}

	jrtok = json_get_member(plugin->rpc_buffer + plugin->rpc_read_offset,
				plugin->rpc_toks, "jsonrpc");
	if (!jrtok) {
		plugin_err(plugin, "JSON-RPC message does not contain \"jsonrpc\" field: '%.*s'",
			   (int)(plugin->rpc_used - plugin->rpc_read_offset),
			   plugin->rpc_buffer + plugin->rpc_read_offset);
	}

	handle_rpc_reply(plugin, plugin->rpc_toks);

	/* Move this object out of the buffer */
	plugin->rpc_read_offset += plugin->rpc_toks[0].end;
	jsmn_init(&plugin->rpc_parser);
	toks_reset(plugin->rpc_toks);
	return true;

compact:
	memmove(plugin->rpc_buffer, plugin->rpc_buffer + plugin->rpc_read_offset,
		plugin->rpc_used - plugin->rpc_read_offset);
	plugin->rpc_used -= plugin->rpc_read_offset;
	plugin->rpc_read_offset = 0;
	return false;
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
	struct jstream *jstr = list_pop(&plugin->rpc_js_list, struct jstream, list);
	assert(jstr);
	assert(jstr->js == js);
	tal_free(jstr);

	return rpc_conn_write_request(conn, plugin);
}

static struct io_plan *rpc_conn_write_request(struct io_conn *conn,
					      struct plugin *plugin)
{
	struct jstream *jstr = list_top(&plugin->rpc_js_list, struct jstream, list);
	if (jstr)
		return json_stream_output(jstr->js, conn,
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

static struct plugin_option *find_opt(struct plugin *plugin, const char *name)
{
	for (size_t i = 0; i < tal_count(plugin->opts); i++) {
		if (streq(plugin->opts[i].name, name))
			return &plugin->opts[i];
	}
	return NULL;
}

static const char **json_to_apilist(const tal_t *ctx, const char *buffer, const jsmntok_t *tok)
{
	size_t i;
	const jsmntok_t *t;
	const char **ret = tal_arr(ctx, const char *, tok->size);

	json_for_each_arr(i, t, tok)
		ret[i] = json_strdup(ret, buffer, t);

	return ret;
}

static struct command_result *handle_init(struct command *cmd,
					  const char *buf,
					  const jsmntok_t *params)
{
	const jsmntok_t *configtok, *opttok, *t;
	struct sockaddr_un addr;
	size_t i;
	char *dir, *network;
	struct plugin *p = cmd->plugin;
	bool with_rpc = p->rpc_conn != NULL;
	const char *err;

	configtok = json_get_member(buf, params, "configuration");
	err = json_scan(tmpctx, buf, configtok,
			"{lightning-dir:%"
			",network:%"
			",feature_set:%"
			",rpc-file:%}",
			JSON_SCAN_TAL(tmpctx, json_strdup, &dir),
			JSON_SCAN_TAL(tmpctx, json_strdup, &network),
			JSON_SCAN_TAL(p, json_to_feature_set, &p->our_features),
			JSON_SCAN_TAL(p, json_strdup, &p->rpc_location));
	if (err)
		plugin_err(p, "cannot scan init params: %s: %.*s",
			   err, json_tok_full_len(params),
			   json_tok_full(buf, params));

	/* Move into lightning directory: other files are relative */
	if (chdir(dir) != 0)
		plugin_err(p, "chdir to %s: %s", dir, strerror(errno));

	chainparams = chainparams_for_network(network);

	/* Only attempt to connect if the plugin has configured the rpc_conn
	 * already, if that's not the case we were told to run without an RPC
	 * connection, so don't even log an error. */
	/* FIXME: Move this to its own function so we can initialize at a
	 * later point in time. */
	if (p->rpc_conn != NULL) {
		p->rpc_conn->fd = socket(AF_UNIX, SOCK_STREAM, 0);
		if (strlen(p->rpc_location) + 1 > sizeof(addr.sun_path))
			plugin_err(p, "rpc filename '%s' too long",
				   p->rpc_location);
		strcpy(addr.sun_path, p->rpc_location);
		addr.sun_family = AF_UNIX;

		if (connect(p->rpc_conn->fd, (struct sockaddr *)&addr,
			    sizeof(addr)) != 0) {
			with_rpc = false;
			plugin_log(p, LOG_UNUSUAL,
				   "Could not connect to '%s': %s",
				   p->rpc_location, strerror(errno));
		}

		membuf_init(&p->rpc_conn->mb, tal_arr(p, char, READ_CHUNKSIZE),
			    READ_CHUNKSIZE, membuf_tal_realloc);

	}

	opttok = json_get_member(buf, params, "options");
	json_for_each_obj(i, t, opttok) {
		const char *name, *problem;
		struct plugin_option *popt;

		name = json_strdup(tmpctx, buf, t);
		popt = find_opt(p, name);
		if (!popt)
			plugin_err(p, "lightningd specified unknown option '%s'?", name);

		problem = popt->handle(p, json_strdup(tmpctx, buf, t+1), false, popt->arg);
		if (problem)
			plugin_err(p, "option '%s': %s", popt->name, problem);
	}

	if (p->init) {
		const char *disable = p->init(p, buf, configtok);
		if (disable)
			return command_success(cmd, json_out_obj(cmd, "disable",
								 disable));
	}

	if (with_rpc) {
		p->beglist = NULL;
		rpc_scan(p, "listconfigs",
			 take(json_out_obj(NULL, "config", "i-promise-to-fix-broken-api-user")),
			 "{configs:{i-promise-to-fix-broken-api-user?:%}}",
			 JSON_SCAN_TAL(p, json_to_apilist, &p->beglist));
		io_new_conn(p, p->rpc_conn->fd, rpc_conn_init, p);
	}

	return command_success(cmd, json_out_obj(cmd, NULL, NULL));
}

char *u64_option(struct plugin *plugin, const char *arg, bool check_only, u64 *i)
{
	char *endp;
	u64 v;

	/* This is how the manpage says to do it.  Yech. */
	errno = 0;
	v = strtoul(arg, &endp, 0);
	if (*endp || !arg[0])
		return tal_fmt(tmpctx, "'%s' is not a number", arg);
	if (errno)
		return tal_fmt(tmpctx, "'%s' is out of range", arg);
	if (!check_only)
		*i = v;
	return NULL;
}

char *u32_option(struct plugin *plugin, const char *arg, bool check_only, u32 *i)
{
	u64 n;
	char *problem = u64_option(plugin, arg, false, &n);

	if (problem)
		return problem;

	if ((u32)n != n)
		return tal_fmt(tmpctx, "'%s' is too large (overflow)", arg);

	if (!check_only)
		*i = n;
	return NULL;
}

char *u16_option(struct plugin *plugin, const char *arg, bool check_only, u16 *i)
{
	u64 n;
	char *problem = u64_option(plugin, arg, false, &n);

	if (problem)
		return problem;

	if ((u16)n != n)
		return tal_fmt(tmpctx, "'%s' is too large (overflow)", arg);

	if (!check_only)
		*i = n;
	return NULL;
}

char *bool_option(struct plugin *plugin, const char *arg, bool check_only, bool *i)
{
	if (!streq(arg, "true") && !streq(arg, "false"))
		return tal_fmt(tmpctx, "'%s' is not a bool, must be \"true\" or \"false\"", arg);

	if (!check_only)
		*i = streq(arg, "true");
	return NULL;
}

char *flag_option(struct plugin *plugin, const char *arg, bool check_only, bool *i)
{
	/* We only get called if the flag was provided, so *i should be false
	 * by default */
	assert(check_only || *i == false);
	if (!streq(arg, "true"))
		return tal_fmt(tmpctx, "Invalid argument '%s' passed to a flag", arg);

	if (!check_only)
		*i = true;
	return NULL;
}

char *charp_option(struct plugin *plugin, const char *arg, bool check_only, char **p)
{
	if (!check_only)
		*p = tal_strdup(NULL, arg);
	return NULL;
}

bool u64_jsonfmt(struct plugin *plugin, struct json_stream *js, const char *fieldname, u64 *i)
{
	json_add_u64(js, fieldname, *i);
	return true;
}

bool u32_jsonfmt(struct plugin *plugin, struct json_stream *js, const char *fieldname, u32 *i)
{
	json_add_u32(js, fieldname, *i);
	return true;
}

bool u16_jsonfmt(struct plugin *plugin, struct json_stream *js, const char *fieldname, u16 *i)
{
	json_add_u32(js, fieldname, *i);
	return true;
}

bool bool_jsonfmt(struct plugin *plugin, struct json_stream *js, const char *fieldname, bool *i)
{
	json_add_bool(js, fieldname, *i);
	return true;
}

bool charp_jsonfmt(struct plugin *plugin, struct json_stream *js, const char *fieldname, char **p)
{
	if (!*p)
		return false;
	json_add_string(js, fieldname, *p);
	return true;
}

bool flag_jsonfmt(struct plugin *plugin, struct json_stream *js, const char *fieldname, bool *i)
{
	/* Don't print if the default (false) */
	if (!*i)
		return false;
	return bool_jsonfmt(plugin, js, fieldname, i);
}

static void setup_command_usage(struct plugin *p)
{
	struct command *usage_cmd = new_command(tmpctx, p, "usage",
						"check-usage",
						COMMAND_TYPE_USAGE_ONLY);

	/* This is how common/param can tell it's just a usage request */
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
	struct command *timer_cmd;
	struct command_result *res;

	/* This *isn't* owned by timer, which is owned by original command,
	 * since they may free that in callback */
	timer_cmd = new_command(p, p, t->id, "timer", COMMAND_TYPE_TIMER);
	res = t->cb(timer_cmd, t->cb_arg);
	assert(res == &pending || res == &complete);
}

static void destroy_plugin_timer(struct plugin_timer *timer, struct plugin *p)
{
	timer_del(&p->timers, &timer->timer);
}

static struct plugin_timer *new_timer(const tal_t *ctx,
				      struct plugin *p,
				      const char *id TAKES,
				      struct timerel t,
				      struct command_result *(*cb)(struct command *, void *),
				      void *cb_arg)
{
	struct plugin_timer *timer = notleak(tal(ctx, struct plugin_timer));
	timer->id = tal_strdup(timer, id);
	timer->cb = cb;
	timer->cb_arg = cb_arg;
	timer_init(&timer->timer);
	timer_addrel(&p->timers, &timer->timer, t);
	tal_add_destructor2(timer, destroy_plugin_timer, p);
	return timer;
}

struct plugin_timer *global_timer_(struct plugin *p,
				   struct timerel t,
				   struct command_result *(*cb)(struct command *cmd, void *cb_arg),
				   void *cb_arg)
{
	return new_timer(p, p, "timer", t, cb, cb_arg);
}

struct plugin_timer *command_timer_(struct command *cmd,
				    struct timerel t,
				    struct command_result *(*cb)(struct command *cmd, void *cb_arg),
				    void *cb_arg)
{
	return new_timer(cmd, cmd->plugin,
			 take(tal_fmt(NULL, "%s-timer", cmd->id)),
			 t, cb, cb_arg);
}

void plugin_logv(struct plugin *p, enum log_level l,
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

struct json_stream *plugin_notification_start(struct plugin *plugin,
					      const char *method)
{
	struct json_stream *js = new_json_stream(plugin, NULL, NULL);

	json_object_start(js, NULL);
	json_add_string(js, "jsonrpc", "2.0");
	json_add_string(js, "method", method);

	json_object_start(js, "params");
	return js;
}

void plugin_notification_end(struct plugin *plugin,
			     struct json_stream *stream)
{
	json_object_end(stream);
	jsonrpc_finish_and_send(plugin, stream);
}

struct json_stream *plugin_notify_start(struct command *cmd, const char *method)
{
	struct json_stream *js = new_json_stream(cmd, NULL, NULL);

	json_object_start(js, NULL);
	json_add_string(js, "jsonrpc", "2.0");
	json_add_string(js, "method", method);

	json_object_start(js, "params");
	json_add_id(js, cmd->id);

	return js;
}

void plugin_notify_end(struct command *cmd, struct json_stream *js)
{
	json_object_end(js);

	jsonrpc_finish_and_send(cmd->plugin, js);
}

/* Convenience wrapper for notify with "message" */
void plugin_notify_message(struct command *cmd,
			   enum log_level level,
			   const char *fmt, ...)
{
	va_list ap;
	struct json_stream *js;
	const char *msg;

	va_start(ap, fmt);
	msg = tal_vfmt(tmpctx, fmt, ap);
	va_end(ap);

	/* Also log, debug level */
	plugin_log(cmd->plugin, LOG_DBG, "notify msg %s: %s",
		   log_level_name(level), msg);

	js = plugin_notify_start(cmd, "message");
	json_add_string(js, "level", log_level_name(level));

	/* In case we're OOM */
	if (js->jout)
		json_out_addstr(js->jout, "message", msg);

	plugin_notify_end(cmd, js);
}

void plugin_notify_progress(struct command *cmd,
			    u32 num_stages, u32 stage,
			    u32 num_progress, u32 progress)
{
	struct json_stream *js = plugin_notify_start(cmd, "progress");

	assert(progress < num_progress);
	json_add_u32(js, "num", progress);
	json_add_u32(js, "total", num_progress);
	if (num_stages > 0) {
		assert(stage < num_stages);
		json_object_start(js, "stage");
		json_add_u32(js, "num", stage);
		json_add_u32(js, "total", num_stages);
		json_object_end(js);
	}
	plugin_notify_end(cmd, js);
}

void NORETURN plugin_exit(struct plugin *p, int exitcode)
{
	p->exiting = true;
	io_conn_out_exclusive(p->stdout_conn, true);
	io_wake(p);
	io_loop(NULL, NULL);
	exit(exitcode);
}

void NORETURN plugin_errv(struct plugin *p, const char *fmt, va_list ap)
{
	va_list ap2;

	/* In case it gets consumed, make a copy. */
	va_copy(ap2, ap);

	plugin_logv(p, LOG_BROKEN, fmt, ap);
	vfprintf(stderr, fmt, ap2);
	plugin_exit(p, 1);
	va_end(ap2);
}

void NORETURN plugin_err(struct plugin *p, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	plugin_errv(p, fmt, ap);
	va_end(ap);
}

void plugin_log(struct plugin *p, enum log_level l, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	plugin_logv(p, l, fmt, ap);
	va_end(ap);
}

static void PRINTF_FMT(2,3) log_memleak(struct plugin *plugin, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	plugin_logv(plugin, LOG_BROKEN, fmt, ap);
	va_end(ap);
}

static void memleak_check(struct plugin *plugin, struct command *cmd)
{
	struct htable *memtable;

	memtable = memleak_start(tmpctx);

	/* cmd in use right now */
	memleak_ptr(memtable, cmd);
	memleak_ignore_children(memtable, cmd);

	/* Now delete plugin and anything it has pointers to. */
	memleak_scan_obj(memtable, plugin);

	/* Memleak needs some help to see into strmaps */
	memleak_scan_strmap(memtable, &plugin->out_reqs);

	/* We know usage strings are referred to. */
	memleak_scan_strmap(memtable, &cmd->plugin->usagemap);

	if (plugin->mark_mem)
		plugin->mark_mem(plugin, memtable);

	dump_memleak(memtable, log_memleak, plugin);
}

void plugin_set_memleak_handler(struct plugin *plugin,
				void (*mark_mem)(struct plugin *plugin,
						 struct htable *memtable))
{
	if (plugin->developer)
		plugin->mark_mem = mark_mem;
}

bool command_deprecated_ok_flag(const struct command *cmd)
{
	if (cmd->plugin->deprecated_ok_override)
		return *cmd->plugin->deprecated_ok_override;
	return cmd->plugin->deprecated_ok;
}

static struct command_result *param_tok(struct command *cmd, const char *name,
					const char *buffer, const jsmntok_t * tok,
					const jsmntok_t **out)
{
	*out = tok;
	return NULL;
}

static void ld_command_handle(struct plugin *plugin,
			      const jsmntok_t *toks)
{
	const jsmntok_t *methtok, *paramstok, *filtertok;
	const char *methodname;
	struct command *cmd;
	const char *id;
	enum command_type type;

	methtok = json_get_member(plugin->buffer, toks, "method");
	paramstok = json_get_member(plugin->buffer, toks, "params");
	filtertok = json_get_member(plugin->buffer, toks, "filter");

	if (!methtok || !paramstok)
		plugin_err(plugin, "Malformed JSON-RPC notification missing "
			   "\"method\" or \"params\": %.*s",
			   json_tok_full_len(toks),
			   json_tok_full(plugin->buffer, toks));

	methodname = json_strdup(NULL, plugin->buffer, methtok);
	id = json_get_id(tmpctx, plugin->buffer, toks);

	if (!id)
		type = COMMAND_TYPE_NOTIFICATION;
	else if (streq(methodname, "check"))
		type = COMMAND_TYPE_CHECK;
	else
		type = COMMAND_TYPE_NORMAL;

	cmd = new_command(plugin, plugin,
			  id ? id : tal_fmt(tmpctx, "notification-%s", methodname),
			  take(methodname),
			  type);

	if (!plugin->manifested) {
		if (streq(cmd->methodname, "getmanifest")) {
			handle_getmanifest(cmd, plugin->buffer, paramstok);
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
	if (cmd->type == COMMAND_TYPE_NOTIFICATION) {
		bool is_shutdown = streq(cmd->methodname, "shutdown");
		if (is_shutdown && plugin->developer)
			memleak_check(plugin, cmd);

		if (streq(cmd->methodname, "deprecated_oneshot")) {
			const char *err;

			plugin->deprecated_ok_override = tal(plugin, bool);
			err = json_scan(tmpctx, plugin->buffer, paramstok,
					"{deprecated_oneshot:{deprecated_ok:%}}",
					JSON_SCAN(json_to_bool,
						  plugin->deprecated_ok_override));
			if (err)
				plugin_err(plugin, "Parsing deprecated_oneshot notification: %s", err);
			return;
		}
		for (size_t i = 0; i < plugin->num_notif_subs; i++) {
			if (streq(cmd->methodname,
				  plugin->notif_subs[i].name)
			    || is_asterix_notification(cmd->methodname,
						       plugin->notif_subs[i].name)) {
				plugin->notif_subs[i].handle(cmd,
							     plugin->buffer,
							     paramstok);
				return;
			}
		}

		/* We subscribe them to this always */
		if (is_shutdown && plugin->developer)
			plugin_exit(plugin, 0);

		plugin_err(plugin, "Unregistered notification %.*s",
			   json_tok_full_len(methtok),
			   json_tok_full(plugin->buffer, methtok));
	}

	for (size_t i = 0; i < plugin->num_hook_subs; i++) {
		if (streq(cmd->methodname, plugin->hook_subs[i].name)) {
			cmd->type = COMMAND_TYPE_HOOK;
			plugin->hook_subs[i].handle(cmd,
						    plugin->buffer,
						    paramstok);
			return;
		}
	}

	if (filtertok) {
		/* On error, this fails cmd */
		if (parse_filter(cmd, "filter", plugin->buffer, filtertok)
		    != NULL)
			return;
	}

	/* Is this actually a check command? */
	if (cmd->type == COMMAND_TYPE_CHECK) {
		const jsmntok_t *method;
		jsmntok_t *mod_params;

		/* We're going to mangle it, so make a copy */
		mod_params = json_tok_copy(cmd, paramstok);
		if (!param_check(cmd, plugin->buffer, mod_params,
				 p_req("command_to_check", param_tok, &method),
				 p_opt_any(),
				 NULL)) {
			plugin_err(plugin,
				   "lightningd check without command_to_check: %.*s",
				   json_tok_full_len(toks),
				   json_tok_full(plugin->buffer, toks));
		}
		tal_free(cmd->methodname);
		cmd->methodname = json_strdup(cmd, plugin->buffer, method);

		/* Point method to the name, not the value */
		if (mod_params->type == JSMN_OBJECT)
			method--;

		json_tok_remove(&mod_params, mod_params, method, 1);
		paramstok = mod_params;
	}

	for (size_t i = 0; i < plugin->num_commands; i++) {
		if (streq(cmd->methodname, plugin->commands[i].name)) {
			plugin->commands[i].handle(cmd,
						   plugin->buffer,
						   paramstok);
			/* Reset this */
			plugin->deprecated_ok_override
				= tal_free(plugin->deprecated_ok_override);
			return;
		}
	}

	/* Dynamic parameters */
	if (streq(cmd->methodname, "setconfig")) {
		const jsmntok_t *valtok;
		const char *config, *val, *problem;
		struct plugin_option *popt;
		struct command_result *ret;
		bool check_only;

		config = json_strdup(tmpctx, plugin->buffer,
				     json_get_member(plugin->buffer, paramstok, "config"));
		popt = find_opt(plugin, config);
		if (!popt) {
			plugin_err(plugin,
				   "lightningd setconfig unknown option '%s'?",
				   config);
		}
		if (!popt->dynamic) {
			plugin_err(plugin,
				   "lightningd setconfig non-dynamic option '%s'?",
				   config);
		}

		check_only = command_check_only(cmd);
		plugin_log(plugin, LOG_DBG, "setconfig %s check_only=%i", config, check_only);

		valtok = json_get_member(plugin->buffer, paramstok, "val");
		if (valtok)
			val = json_strdup(tmpctx, plugin->buffer, valtok);
		else
			val = "true";

		problem = popt->handle(plugin, val, check_only, popt->arg);
		if (problem)
			ret = command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					   "%s", problem);
		else {
			if (check_only)
				ret = command_check_done(cmd);
			else
				ret = command_finished(cmd, jsonrpc_stream_success(cmd));
		}
		assert(ret == &complete);
		return;
	}

	plugin_err(plugin, "Unknown command '%s'", cmd->methodname);
}

/**
 * Try to parse a complete message from lightningd's buffer, and return true
 * if we could handle it.
 */
static bool ld_read_json_one(struct plugin *plugin)
{
	bool complete;

	if (!json_parse_input(&plugin->parser, &plugin->toks,
			      plugin->buffer, plugin->used,
			      &complete)) {
		plugin_err(plugin, "Failed to parse JSON response '%.*s'",
			   (int)plugin->used, plugin->buffer);
		return false;
	}

	if (!complete) {
		/* We need more. */
		return false;
	}

	/* Empty buffer? (eg. just whitespace). */
	if (tal_count(plugin->toks) == 1) {
		toks_reset(plugin->toks);
		jsmn_init(&plugin->parser);
		plugin->used = 0;
		return false;
	}

	/* FIXME: Spark doesn't create proper jsonrpc 2.0!  So we don't
	 * check for "jsonrpc" here. */
	ld_command_handle(plugin, plugin->toks);

	/* Move this object out of the buffer */
	memmove(plugin->buffer, plugin->buffer + plugin->toks[0].end,
		tal_count(plugin->buffer) - plugin->toks[0].end);
	plugin->used -= plugin->toks[0].end;
	toks_reset(plugin->toks);
	jsmn_init(&plugin->parser);

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
	struct jstream *jstr = list_pop(&plugin->js_list, struct jstream, list);
	assert(jstr);
	assert(jstr->js == js);
	tal_free(jstr);

	return ld_write_json(conn, plugin);
}

static struct io_plan *ld_write_json(struct io_conn *conn,
				     struct plugin *plugin)
{
	struct jstream *jstr = list_top(&plugin->js_list, struct jstream, list);
	if (jstr)
		return json_stream_output(jstr->js, plugin->stdout_conn,
					  ld_stream_complete, plugin);

	/* If we were simply flushing final output, stop now. */
	if (plugin->exiting)
		io_break(plugin);
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
				 const char *argv0,
				 bool developer,
				 const char *(*init)(struct plugin *p,
						     const char *buf,
						     const jsmntok_t *),
				 const enum plugin_restartability restartability,
				 bool init_rpc,
				 struct feature_set *features STEALS,
				 const struct plugin_command *commands TAKES,
				 size_t num_commands,
				 const struct plugin_notification *notif_subs TAKES,
				 size_t num_notif_subs,
				 const struct plugin_hook *hook_subs TAKES,
				 size_t num_hook_subs,
				 const char **notif_topics TAKES,
				 size_t num_notif_topics,
				 va_list ap)
{
	const char *optname;
	struct plugin *p = tal(ctx, struct plugin);
	char *name;

	/* id is our name, without extension (not that we expect any, in C!) */
	name = path_basename(p, argv0);
	name[path_ext_off(name)] = '\0';
	p->id = name;
	p->developer = developer;
	p->deprecated_ok_override = NULL;
	p->buffer = tal_arr(p, char, 64);
	list_head_init(&p->js_list);
	p->used = 0;
	p->len_read = 0;
	jsmn_init(&p->parser);
	p->toks = toks_alloc(p);
	/* Async RPC */
	p->rpc_buffer = tal_arr(p, char, 64);
	list_head_init(&p->rpc_js_list);
	p->rpc_used = 0;
	p->rpc_read_offset = 0;
	p->rpc_len_read = 0;
	jsmn_init(&p->rpc_parser);
	p->rpc_toks = toks_alloc(p);
	p->next_outreq_id = 0;
	strmap_init(&p->out_reqs);

	p->desired_features = tal_steal(p, features);
	if (init_rpc) {
		/* Sync RPC FIXME: maybe go full async ? */
		p->rpc_conn = tal(p, struct rpc_conn);
	} else {
		p->rpc_conn = NULL;
	}

	p->init = init;
	p->manifested = p->initialized = p->exiting = false;
	p->restartability = restartability;
	strmap_init(&p->usagemap);

	p->commands = commands;
	if (taken(commands))
		tal_steal(p, commands);
	p->num_commands = num_commands;
	p->notif_topics = notif_topics;
	if (taken(notif_topics))
		tal_steal(p, notif_topics);
	p->num_notif_topics = num_notif_topics;
	p->notif_subs = notif_subs;
	if (taken(notif_subs))
		tal_steal(p, notif_subs);
	p->num_notif_subs = num_notif_subs;
	p->hook_subs = hook_subs;
	if (taken(hook_subs))
		tal_steal(p, hook_subs);
	p->num_hook_subs = num_hook_subs;
	p->opts = tal_arr(p, struct plugin_option, 0);

	while ((optname = va_arg(ap, const char *)) != NULL) {
		struct plugin_option o;
		o.name = optname;
		o.type = va_arg(ap, const char *);
		o.description = va_arg(ap, const char *);
		o.handle = va_arg(ap, char *(*)(struct plugin *, const char *str, bool check_only, void *arg));
		o.jsonfmt = va_arg(ap, bool (*)(struct plugin *, struct json_stream *, const char *, void *arg));
		o.arg = va_arg(ap, void *);
		o.dev_only = va_arg(ap, int); /* bool gets promoted! */
		o.depr_start = va_arg(ap, const char *);
		o.depr_end = va_arg(ap, const char *);
		o.dynamic = va_arg(ap, int); /* bool gets promoted! */
		tal_arr_expand(&p->opts, o);
	}

	p->mark_mem = NULL;
	return p;
}

void plugin_main(char *argv[],
		 const char *(*init)(struct plugin *p,
				     const char *buf, const jsmntok_t *),
		 void *data,
		 const enum plugin_restartability restartability,
		 bool init_rpc,
		 struct feature_set *features STEALS,
		 const struct plugin_command *commands TAKES,
		 size_t num_commands,
		 const struct plugin_notification *notif_subs TAKES,
		 size_t num_notif_subs,
		 const struct plugin_hook *hook_subs TAKES,
		 size_t num_hook_subs,
		 const char **notif_topics TAKES,
		 size_t num_notif_topics,
		 ...)
{
	struct plugin *plugin;
	va_list ap;
	bool developer;

	setup_locale();

	developer = daemon_developer_mode(argv);

	/* Note this already prints to stderr, which is enough for now */
	daemon_setup(argv[0], NULL, NULL);

	va_start(ap, num_notif_topics);
	plugin = new_plugin(NULL, argv[0], developer,
			    init, restartability, init_rpc, features, commands,
			    num_commands, notif_subs, num_notif_subs, hook_subs,
			    num_hook_subs, notif_topics, num_notif_topics, ap);
	plugin_set_data(plugin, data);
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
			*tmsattok = json_get_member(buffer, tok, "total_msat"),
			*smsattok =
			    json_get_member(buffer, tok, "spendable_msat"),
			*aliastok = json_get_member(buffer, tok, "alias"),
			*max_htlcs = json_get_member(buffer, tok, "max_accepted_htlcs"),
			*htlcstok = json_get_member(buffer, tok, "htlcs"),
			*idtok = json_get_member(buffer, tok, "peer_id"),
			*conntok = json_get_member(buffer, tok, "peer_connected");

	chan = tal(ctx, struct listpeers_channel);

	if (scidtok != NULL) {
		assert(dirtok != NULL);
		chan->scid = tal(chan, struct short_channel_id);
		json_to_short_channel_id(buffer, scidtok, chan->scid);
	} else {
		chan->scid = NULL;
	}

	if (aliastok != NULL) {
		const jsmntok_t *loctok =
				    json_get_member(buffer, aliastok, "local"),
				*remtok =
				    json_get_member(buffer, aliastok, "remote");
		if (loctok) {
			chan->alias[LOCAL] = tal(chan, struct short_channel_id);
			json_to_short_channel_id(buffer, loctok,
						 chan->alias[LOCAL]);
		} else
			chan->alias[LOCAL] = NULL;

		if (remtok) {
			chan->alias[REMOTE] = tal(chan, struct short_channel_id);
			json_to_short_channel_id(buffer, loctok,
						 chan->alias[REMOTE]);
		} else
			chan->alias[REMOTE] = NULL;
	} else {
		chan->alias[LOCAL] = NULL;
		chan->alias[REMOTE] = NULL;
	}

	/* If we catch a channel during opening, these might not be set.
	 * It's not a real channel (yet), so ignore it! */
	if (!chan->scid && !chan->alias[LOCAL])
		return tal_free(chan);

	json_to_node_id(buffer, idtok, &chan->id);
	json_to_bool(buffer, conntok, &chan->connected);
	json_to_bool(buffer, privtok, &chan->private);
	chan->state = json_strdup(chan, buffer, statetok);
	json_to_txid(buffer, ftxidtok, &chan->funding_txid);

	json_to_int(buffer, dirtok, &chan->direction);
	json_to_msat(buffer, tmsattok, &chan->total_msat);
	json_to_msat(buffer, smsattok, &chan->spendable_msat);
	json_to_u16(buffer, max_htlcs, &chan->max_accepted_htlcs);
	chan->num_htlcs = htlcstok->size;

	return chan;
}

struct listpeers_channel **json_to_listpeers_channels(const tal_t *ctx,
						      const char *buffer,
						      const jsmntok_t *tok)
{
	size_t i;
	const jsmntok_t *iter;
	const jsmntok_t *channelstok = json_get_member(buffer, tok, "channels");
	struct listpeers_channel **chans;

	chans = tal_arr(ctx, struct listpeers_channel *, 0);
	json_for_each_arr(i, iter, channelstok) {
		struct listpeers_channel *chan;

		chan = json_to_listpeers_channel(chans, buffer, iter);
		if (!chan)
			continue;
		tal_arr_expand(&chans, chan);
	}
	return chans;
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

	json_to_node_id(buffer, idtok, &dst->node_id);
	json_to_short_channel_id(buffer, channeltok, &dst->scid);
	json_to_int(buffer, directiontok, &dst->direction);
	json_to_msat(buffer, amounttok, &dst->amount);
	json_to_number(buffer, delaytok, &dst->delay);
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

struct command_result *WARN_UNUSED_RESULT
command_hook_success(struct command *cmd)
{
	struct json_stream *response = jsonrpc_stream_success(cmd);
	assert(cmd->type == COMMAND_TYPE_HOOK);
	json_add_string(response, "result", "continue");
	return command_finished(cmd, response);
}

struct command *aux_command(const struct command *cmd)
{
	return new_command(cmd->plugin, cmd->plugin, cmd->id,
			   cmd->methodname, COMMAND_TYPE_AUX);
}

struct command_result *WARN_UNUSED_RESULT
aux_command_done(struct command *cmd)
{
	assert(cmd->type == COMMAND_TYPE_AUX);
	tal_free(cmd);
	return &complete;
}

struct command_result *WARN_UNUSED_RESULT
notification_handled(struct command *cmd)
{
	assert(cmd->type == COMMAND_TYPE_NOTIFICATION);
	tal_free(cmd);
	return &complete;
}

bool plugin_developer_mode(const struct plugin *plugin)
{
	return plugin->developer;
}

void plugin_set_data(struct plugin *plugin, void *data TAKES)
{
	if (taken(data))
		tal_steal(plugin, data);
	plugin->data = data;
}

void *plugin_get_data_(struct plugin *plugin)
{
	return plugin->data;
}
