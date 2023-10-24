/* Code for JSON_RPC API.
 *
 * Each socket connection is represented by a `struct json_connection`.
 *
 * This can have zero, one or more `struct command` in progress at a time:
 * because the json_connection can be closed at any point, these `struct command`
 * have a independent lifetimes.
 *
 * Each `struct command` writes into a `struct json_stream`, which is created
 * the moment they start writing output (see attach_json_stream).  Initially
 * the struct command owns it since they're writing into it.  When they're
 * done, the `json_connection` needs to drain it (if it's still around).  At
 * that point, the `json_connection` becomes the owner (or it's simply freed).
 */
/* eg: { "jsonrpc":"2.0", "method" : "dev-echo", "params" : [ "hello", "Arabella!" ], "id" : "1" } */
#include "config.h"
#include <ccan/asort/asort.h>
#include <ccan/err/err.h>
#include <ccan/io/io.h>
#include <ccan/json_escape/json_escape.h>
#include <ccan/json_out/json_out.h>
#include <ccan/tal/str/str.h>
#include <common/configdir.h>
#include <common/json_command.h>
#include <common/json_filter.h>
#include <common/json_param.h>
#include <common/memleak.h>
#include <common/timeout.h>
#include <common/trace.h>
#include <db/exec.h>
#include <fcntl.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/plugin_hook.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>


/* Dummy structure. */
struct command_result {
	char c;
};

static struct command_result param_failed, complete, pending, unknown;

struct command_result *command_param_failed(void)
{
	return &param_failed;
}

/* For our purposes, the same as command_param_failed: we examine
 * cmd->mode to see if it's really done. */
struct command_result *command_check_done(struct command *cmd)
{
	assert(cmd->mode == CMD_CHECK);
	return &param_failed;
}

struct command_result *command_its_complicated(const char *relationship_details
					       UNNEEDED)
{
	return &unknown;
}

/* This represents a JSON RPC connection.  It can invoke multiple commands, but
 * a command can outlive the connection, which could close any time. */
struct json_connection {
	/* The global state */
	struct lightningd *ld;

	/* This io_conn (and our owner!) */
	struct io_conn *conn;

	/* Logging for this json connection. */
	struct logger *log;

	/* The buffer (required to interpret tokens). */
	char *buffer;

	/* Internal state: */
	/* How much is already filled. */
	size_t used;
	/* How much has just been filled. */
	size_t len_read;

	/* JSON parsing state. */
	jsmn_parser input_parser;
	jsmntok_t *input_toks;

	/* Our commands */
	struct list_head commands;

	/* Are notifications enabled? */
	bool notifications_enabled;

	/* Are we allowed to batch database commitments? */
	bool db_batching;

	/* Our json_streams (owned by the commands themselves while running).
	 * Since multiple streams could start returning data at once, we
	 * always service these in order, freeing once empty. */
	struct json_stream **js_arr;
};

/**
 * `jsonrpc` encapsulates the entire state of the JSON-RPC interface,
 * including a list of methods that the interface supports (can be
 * appended dynamically, e.g., for plugins, and logs. It also serves
 * as a convenient `tal`-parent for all JSON-RPC related allocations.
 */
struct jsonrpc {
	struct io_listener *rpc_listener;
	struct json_command **commands;

	/* Map from json command names to usage strings: we don't put this inside
	 * struct json_command as it's good practice to have those const. */
	STRMAP(const char *) usagemap;
};

/* The command itself usually owns the stream, because jcon may get closed.
 * The command transfers ownership once it's done though. */
static struct json_stream *jcon_new_json_stream(const tal_t *ctx,
						struct json_connection *jcon,
						struct command *writer)
{
	struct json_stream *js = new_json_stream(ctx, writer, jcon->log);

	/* Wake writer to start streaming, in case it's not already. */
	io_wake(jcon);

	/* FIXME: Keep streams around for recycling. */
	tal_arr_expand(&jcon->js_arr, js);
	return js;
}

static void jcon_remove_json_stream(struct json_connection *jcon,
				    struct json_stream *js)
{
	for (size_t i = 0; i < tal_count(jcon->js_arr); i++) {
		if (js != jcon->js_arr[i])
			continue;

		tal_arr_remove(&jcon->js_arr, i);
		return;
	}
	abort();
}

/* jcon and cmd have separate lifetimes: we detach them on either destruction */
static void destroy_jcon(struct json_connection *jcon)
{
	struct command *c;

	list_for_each(&jcon->commands, c, list)
		c->jcon = NULL;

	/* Make sure this happens last! */
	tal_free(jcon->log);
}

struct logger *command_log(struct command *cmd)
{
	if (cmd->jcon)
		return cmd->jcon->log;
	return cmd->ld->log;
}

static struct command_result *json_help(struct command *cmd,
					const char *buffer,
					const jsmntok_t *obj UNNEEDED,
					const jsmntok_t *params);

static const struct json_command help_command = {
	"help",
	"utility",
	json_help,
	"List available commands, or give verbose help on one {command}.",
	.verbose = "help [command]\n"
	"Without [command]:\n"
	"  Outputs an array of objects with 'command' and 'description'\n"
	"With [command]:\n"
	"  Give a single object containing 'verbose', which completely describes\n"
	"  the command inputs and outputs."
};
AUTODATA(json_command, &help_command);

static struct command_result *json_stop(struct command *cmd,
					const char *buffer,
					const jsmntok_t *obj UNNEEDED,
					const jsmntok_t *params)
{
	struct json_out *jout;
	const char *p;
	size_t len;

	if (!param(cmd, buffer, params, NULL))
		return command_param_failed();

	log_unusual(cmd->ld->log, "JSON-RPC shutdown");

	/* With rpc_command_hook, jcon might have closed in the meantime! */
	if (!cmd->jcon) {
		/* Return us to toplevel lightningd.c */
		log_debug(cmd->ld->log, "io_break: %s", __func__);
		io_break(cmd->ld);
		return command_still_pending(cmd);
	}

	cmd->ld->stop_conn = cmd->jcon->conn;

	/* This is the one place where result is a literal string. */
	jout = json_out_new(tmpctx);
	json_out_start(jout, NULL, '{');
	json_out_addstr(jout, "jsonrpc", "2.0");
	/* Copy input id token exactly */
	memcpy(json_out_member_direct(jout, "id", strlen(cmd->id)),
	       cmd->id, strlen(cmd->id));
	json_out_addstr(jout, "result", "Shutdown complete");
	json_out_end(jout, '}');
	json_out_finished(jout);

	/* Add two \n */
	memcpy(json_out_direct(jout, 2), "\n\n", strlen("\n\n"));
	p = json_out_contents(jout, &len);
	cmd->ld->stop_response = tal_strndup(cmd->ld, p, len);

	/* Wake write loop in case it's not already. */
	io_wake(cmd->jcon);

	return command_still_pending(cmd);
}

static const struct json_command stop_command = {
	"stop",
	"utility",
	json_stop,
	"Shut down the lightningd process"
};
AUTODATA(json_command, &stop_command);

struct slowcmd {
	struct command *cmd;
	unsigned *msec;
	struct json_stream *js;
};

static void slowcmd_finish(struct slowcmd *sc)
{
	json_add_num(sc->js, "msec", *sc->msec);
	was_pending(command_success(sc->cmd, sc->js));
}

static void slowcmd_start(struct slowcmd *sc)
{
	sc->js = json_stream_success(sc->cmd);
	new_reltimer(sc->cmd->ld->timers, sc, time_from_msec(*sc->msec),
		     slowcmd_finish, sc);
}

static struct command_result *json_dev(struct command *cmd UNUSED,
				       const char *buffer,
				       const jsmntok_t *obj UNNEEDED,
				       const jsmntok_t *params)
{
	const char *subcmd;

	subcmd = param_subcommand(cmd, buffer, params,
				  "crash", "rhash", "slowcmd", NULL);
	if (!subcmd)
		return command_param_failed();

	if (streq(subcmd, "crash")) {
		if (!param(cmd, buffer, params,
			   p_req("subcommand", param_ignore, cmd),
			   NULL))
			return command_param_failed();
		fatal("Crash at user request");
	} else if (streq(subcmd, "slowcmd")) {
		struct slowcmd *sc = tal(cmd, struct slowcmd);

		sc->cmd = cmd;
		if (!param(cmd, buffer, params,
			   p_req("subcommand", param_ignore, cmd),
			   p_opt_def("msec", param_number, &sc->msec, 1000),
			   NULL))
			return command_param_failed();

		new_reltimer(cmd->ld->timers, sc, time_from_msec(0),
			     slowcmd_start, sc);
		return command_still_pending(cmd);
	} else {
		assert(streq(subcmd, "rhash"));
		struct json_stream *response;
		struct sha256 *secret;

		if (!param(cmd, buffer, params,
			   p_req("subcommand", param_ignore, cmd),
			   p_req("secret", param_sha256, &secret),
			   NULL))
			return command_param_failed();

		/* Hash in place. */
		sha256(secret, secret, sizeof(*secret));
		response = json_stream_success(cmd);
		json_add_sha256(response, "rhash", secret);
		return command_success(cmd, response);
	}
}

static const struct json_command dev_command = {
	"dev",
	"developer",
	json_dev,
	"Developer command test multiplexer",
	.verbose = "dev rhash {secret}\n"
	"	Show SHA256 of {secret}\n"
	"dev crash\n"
	"	Crash lightningd by calling fatal()\n"
	"dev slowcmd {msec}\n"
	"	Torture test for slow commands, optional {msec}\n",
	.dev_only = true,
};
AUTODATA(json_command, &dev_command);

static size_t num_cmdlist;

static struct json_command **get_cmdlist(void)
{
	static struct json_command **cmdlist;
	if (!cmdlist)
		cmdlist = autodata_get(json_command, &num_cmdlist);

	return cmdlist;
}

static void json_add_help_command(struct command *cmd,
				  struct json_stream *response,
				  struct json_command *json_command)
{
	char *usage;

	/* If they disallow deprecated APIs, don't even list them */
	if (!cmd->ld->deprecated_apis && json_command->deprecated)
		return;

	usage = tal_fmt(cmd, "%s%s %s",
			json_command->name,
			json_command->deprecated ? " (DEPRECATED!)" : "",
			strmap_get(&cmd->ld->jsonrpc->usagemap,
				   json_command->name));
	json_object_start(response, NULL);

	json_add_string(response, "command", usage);
	json_add_string(response, "category", json_command->category);
	json_add_string(response, "description", json_command->description);

	if (!json_command->verbose) {
		json_add_string(response, "verbose",
				"HELP! Please contribute"
				" a description for this"
				" json_command!");
	} else {
		struct json_escape *esc;

		esc = json_escape(NULL, json_command->verbose);
		json_add_escaped_string(response, "verbose", take(esc));
	}

	json_object_end(response);

}

static const struct json_command *find_command(struct json_command **commands,
					       const char *cmdname)
{
	for (size_t i = 0; i < tal_count(commands); i++) {
		if (streq(cmdname, commands[i]->name))
			return commands[i];
	}
	return NULL;
}

static int compare_commands_name(struct json_command *const *a,
					struct json_command *const *b, void *unused)
{
	return strcmp((*a)->name, (*b)->name);
}

static struct command_result *json_help(struct command *cmd,
					const char *buffer,
					const jsmntok_t *obj UNNEEDED,
					const jsmntok_t *params)
{
	struct json_stream *response;
	const char *cmdname;
	struct json_command **commands;
	const struct json_command *one_cmd;

	if (!param(cmd, buffer, params,
		   p_opt("command", param_string, &cmdname),
		   NULL))
		return command_param_failed();

	commands = cmd->ld->jsonrpc->commands;
	if (cmdname) {
		one_cmd = find_command(commands, cmdname);
		if (!one_cmd)
			return command_fail(cmd, JSONRPC2_METHOD_NOT_FOUND,
					    "Unknown command %s",
					    cmdname);
		if (!cmd->ld->deprecated_apis && one_cmd->deprecated)
			return command_fail(cmd, JSONRPC2_METHOD_NOT_FOUND,
					    "Deprecated command %s",
					    cmdname);
		if (!cmd->ld->developer && one_cmd->dev_only)
			return command_fail(cmd, JSONRPC2_METHOD_NOT_FOUND,
					    "Developer-only command %s",
					    cmdname);
	} else
		one_cmd = NULL;

	asort(commands, tal_count(commands), compare_commands_name, NULL);

	response = json_stream_success(cmd);
	json_array_start(response, "help");
	for (size_t i = 0; i < tal_count(commands); i++) {
		if (!one_cmd || one_cmd == commands[i])
			json_add_help_command(cmd, response, commands[i]);
	}
	json_array_end(response);

	/* Tell cli this is simple enough to be formatted flat for humans */
	json_add_string(response, "format-hint", "simple");

	return command_success(cmd, response);
}

static const struct json_command *find_cmd(const struct jsonrpc *rpc,
					   const char *buffer,
					   const jsmntok_t *tok)
{
	struct json_command **commands = rpc->commands;

	for (size_t i = 0; i < tal_count(commands); i++)
		if (json_tok_streq(buffer, tok, commands[i]->name))
			return commands[i];
	return NULL;
}

/* This can be called directly on shutdown, even with unfinished cmd */
static void destroy_command(struct command *cmd)
{
	if (!cmd->jcon) {
		log_debug(cmd->ld->log,
			    "Command returned result after jcon close");
		return;
	}
	list_del_from(&cmd->jcon->commands, &cmd->list);
}

struct command_result *command_raw_complete(struct command *cmd,
					    struct json_stream *result)
{
	json_stream_close(result, cmd);

	/* If we have a jcon, it will free result for us. */
	if (cmd->jcon)
		tal_steal(cmd->jcon, result);

	/* Don't free it here if we're doing `check` */
	if (command_check_only(cmd)) {
		cmd->mode = CMD_CHECK_FAILED;
		return command_param_failed();
	}

	tal_free(cmd);
	return &complete;
}

struct command_result *command_success(struct command *cmd,
				       struct json_stream *result)
{
	assert(cmd);
	assert(cmd->json_stream == result);

	/* Filter will get upset if we close "result" object it didn't
	 * see! */
	if (cmd->filter) {
		const char *err = json_stream_detach_filter(tmpctx, result);
		if (err)
			json_add_string(result, "warning_parameter_filter",
					err);
	}

	json_object_end(result);
	json_object_end(result);

	return command_raw_complete(cmd, result);
}

struct command_result *command_failed(struct command *cmd,
				      struct json_stream *result)
{
	assert(cmd->json_stream == result);
	/* Have to close error */
	json_object_end(result);
	json_object_end(result);

	return command_raw_complete(cmd, result);
}

struct command_result *command_fail(struct command *cmd, enum jsonrpc_errcode code,
				    const char *fmt, ...)
{
	const char *errmsg;
	struct json_stream *r;
	va_list ap;

	va_start(ap, fmt);
	errmsg = tal_vfmt(cmd, fmt, ap);
	va_end(ap);
	r = json_stream_fail_nodata(cmd, code, errmsg);

	return command_failed(cmd, r);
}

struct json_filter **command_filter_ptr(struct command *cmd)
{
	return &cmd->filter;
}

struct command_result *command_still_pending(struct command *cmd)
{
	notleak_with_children(cmd);
	cmd->pending = true;

	/* If we've started writing, wake reader. */
	if (cmd->json_stream)
		json_stream_flush(cmd->json_stream);

	return &pending;
}

static void json_command_malformed(struct json_connection *jcon,
				   const char *id,
				   const char *error)
{
	/* NULL writer is OK here, since we close it immediately. */
	struct json_stream *js = jcon_new_json_stream(jcon, jcon, NULL);

	json_object_start(js, NULL);
	json_add_string(js, "jsonrpc", "2.0");
	json_add_primitive(js, "id", id);
	json_object_start(js, "error");
	json_add_jsonrpc_errcode(js, "code", JSONRPC2_INVALID_REQUEST);
	json_add_string(js, "message", error);
	json_object_end(js);
	json_object_end(js);

	json_stream_close(js, NULL);
}

void json_notify_fmt(struct command *cmd,
		     enum log_level level,
		     const char *fmt, ...)
{
	va_list ap;
	struct json_stream *js;

	if (!cmd->send_notifications)
		return;

	js = json_stream_raw_for_cmd(cmd);

	va_start(ap, fmt);
	json_object_start(js, NULL);
	json_add_string(js, "jsonrpc", "2.0");
	json_add_string(js, "method", "message");
	json_object_start(js, "params");
	json_add_id(js, cmd->id);
	json_add_string(js, "level", log_level_name(level));
	json_add_string(js, "message", tal_vfmt(tmpctx, fmt, ap));
	json_object_end(js);
	json_object_end(js);

	json_stream_double_cr(js);
	json_stream_flush(js);
}

struct json_stream *json_stream_raw_for_cmd(struct command *cmd)
{
	struct json_stream *js;

	/* Might have already opened it for a notification */
	if (cmd->json_stream)
		return cmd->json_stream;

	/* If they still care about the result, attach it to them. */
	if (cmd->jcon)
		js = jcon_new_json_stream(cmd, cmd->jcon, cmd);
	else
		js = new_json_stream(cmd, cmd, NULL);

	assert(!cmd->json_stream);
	cmd->json_stream = js;
	return js;
}

void json_stream_log_suppress_for_cmd(struct json_stream *js,
				     const struct command *cmd)
{
	const char *nm = cmd->json_cmd->name;
	const char *s = tal_fmt(tmpctx, "Suppressing logging of %s command", nm);
	log_io(cmd->jcon->log, LOG_IO_OUT, NULL, s, NULL, 0);

	/* Really shouldn't be used for anything else */
	assert(streq(nm, "getlog"));
	js->log = NULL;
}

static struct json_stream *json_start(struct command *cmd)
{
	struct json_stream *js = json_stream_raw_for_cmd(cmd);

	json_object_start(js, NULL);
	json_add_string(js, "jsonrpc", "2.0");
	json_add_id(js, cmd->id);
	return js;
}

struct json_stream *json_stream_success(struct command *cmd)
{
	struct json_stream *r = json_start(cmd);
	json_object_start(r, "result");

	/* We have results?  OK, start filtering */
	if (cmd->filter)
		json_stream_attach_filter(r, cmd->filter);
	return r;
}

struct json_stream *json_stream_fail_nodata(struct command *cmd,
					    enum jsonrpc_errcode code,
					    const char *errmsg)
{
	struct json_stream *js = json_start(cmd);

	assert(code);

	json_object_start(js, "error");
	json_add_jsonrpc_errcode(js, "code", code);
	json_add_string(js, "message", errmsg);

	return js;
}

struct json_stream *json_stream_fail(struct command *cmd,
				     enum jsonrpc_errcode code,
				     const char *errmsg)
{
	struct json_stream *r = json_stream_fail_nodata(cmd, code, errmsg);

	json_object_start(r, "data");
	return r;
}

static struct command_result *command_exec(struct json_connection *jcon,
                                           struct command *cmd,
                                           const char *buffer,
                                           const jsmntok_t *request,
                                           const jsmntok_t *params)
{
	struct command_result *res;

	res = cmd->json_cmd->dispatch(cmd, buffer, request, params);

	assert(res == &param_failed
	       || res == &complete
	       || res == &pending
	       || res == &unknown);

	/* If they didn't complete it, they must call command_still_pending.
	 * If they completed it, it's freed already. */
	if (res == &pending)
		assert(cmd->pending);

	/* The command might outlive the connection. */
	if (jcon)
		list_for_each(&jcon->commands, cmd, list)
			assert(cmd->pending);

	return res;
}

/* A plugin hook to take over (fail/alter) RPC commands */
struct rpc_command_hook_payload {
	struct command *cmd;
	const char *buffer;
	const jsmntok_t *request;

	/* custom response/replace/error options plugins can have */
	const char *custom_result;
	const char *custom_error;
	const jsmntok_t *custom_replace;
	const char *custom_buffer;
};

static void rpc_command_hook_serialize(struct rpc_command_hook_payload *p,
				       struct json_stream *s,
				       struct plugin *plugin)
{
	const jsmntok_t *tok;
	size_t i;
	char *key;
	json_object_start(s, "rpc_command");

	json_for_each_obj(i, tok, p->request) {
		key = tal_strndup(NULL, p->buffer + tok->start,
				  tok->end - tok->start);
		json_add_tok(s, key, tok + 1, p->buffer);
		tal_free(key);
	}
	json_object_end(s);
}

static void replace_command(struct rpc_command_hook_payload *p,
			    const char *buffer,
			    const jsmntok_t *replacetok)
{
	const jsmntok_t *method = NULL, *params = NULL, *jsonrpc;
	const char *bad;

	/* Must contain "method", "params" and "id" */
	if (replacetok->type != JSMN_OBJECT) {
		bad = "'replace' must be an object";
		goto fail;
	}

	method = json_get_member(buffer, replacetok, "method");
	if (!method) {
		bad = "missing 'method'";
		goto fail;
	}
	params = json_get_member(buffer, replacetok, "params");
	if (!params) {
		bad = "missing 'params'";
		goto fail;
	}
	if (!json_get_member(buffer, replacetok, "id")) {
		bad = "missing 'id'";
		goto fail;
	}

	p->cmd->json_cmd = find_cmd(p->cmd->ld->jsonrpc, buffer, method);
	if (!p->cmd->json_cmd) {
		bad = tal_fmt(tmpctx, "redirected to unknown method '%.*s'",
			      method->end - method->start,
			      buffer + method->start);
		goto fail;
	}
	if (p->cmd->json_cmd->deprecated && !p->cmd->ld->deprecated_apis) {
		bad = tal_fmt(tmpctx, "redirected to deprecated command '%.*s'",
			      method->end - method->start,
			      buffer + method->start);
		goto fail;
	}
	if (p->cmd->json_cmd->dev_only && !p->cmd->ld->developer) {
		bad = tal_fmt(tmpctx, "redirected to developer-only command '%.*s'",
			      method->end - method->start,
			      buffer + method->start);
		goto fail;
	}

	jsonrpc = json_get_member(buffer, replacetok, "jsonrpc");
	if (!jsonrpc || jsonrpc->type != JSMN_STRING || !json_tok_streq(buffer, jsonrpc, "2.0")) {
		bad = "jsonrpc: \"2.0\" must be specified in the request";
		goto fail;
	}

	was_pending(command_exec(p->cmd->jcon, p->cmd, buffer, replacetok,
				 params));
	return;

fail:
	was_pending(command_fail(p->cmd, JSONRPC2_INVALID_REQUEST,
				 "Bad response to 'rpc_command' hook: %s", bad));
}

static void rpc_command_hook_final(struct rpc_command_hook_payload *p STEALS)
{
	const jsmntok_t *params;

	/* Free payload with cmd */
	tal_steal(p->cmd, p);

	if (p->custom_result != NULL) {
		struct json_stream *s = json_start(p->cmd);
		json_add_jsonstr(s, "result",
				 p->custom_result, strlen(p->custom_result));
		json_object_end(s);
		return was_pending(command_raw_complete(p->cmd, s));
	}
	if (p->custom_error != NULL) {
		struct json_stream *s = json_start(p->cmd);
		json_add_jsonstr(s, "error",
				 p->custom_error, strlen(p->custom_error));
		json_object_end(s);
		return was_pending(command_raw_complete(p->cmd, s));
	}
	if (p->custom_replace != NULL)
		return replace_command(p, p->custom_buffer, p->custom_replace);

	/* If no plugin requested a change, just continue command execution. */
	params = json_get_member(p->buffer, p->request, "params");
	return was_pending(command_exec(p->cmd->jcon,
					p->cmd,
					p->buffer,
					p->request,
					params));
}

static bool
rpc_command_hook_callback(struct rpc_command_hook_payload *p,
			  const char *buffer, const jsmntok_t *resulttok)
{
	const struct lightningd *ld = p->cmd->ld;
	const jsmntok_t *tok, *custom_return;
	static char *error = "";
	char *method;

	if (!resulttok || !buffer)
		return true;

	tok = json_get_member(buffer, resulttok, "result");
	if (tok) {
		if (!json_tok_streq(buffer, tok, "continue")) {
			error = "'result' should only be 'continue'.";
			goto log_error_and_skip;
		}
		/* plugin tells us to do nothing. just pass. */
		return true;
	}

	/* didn't just continue but hook was already modified by prior plugin */
	if (p->custom_result != NULL ||
	    p->custom_error != NULL ||
	    p->custom_replace != NULL) {
		/* get method name and log error (only the first time). */
		tok = json_get_member(p->buffer, p->request, "method");
		method = tal_strndup(p, p->buffer + tok->start, tok->end - tok->start);
		log_unusual(ld->log, "rpc_command hook '%s' already modified, ignoring.", method );
		rpc_command_hook_final(p);
		return false;
	}

	/* If the registered plugin did not respond with continue,
	 * it wants either to replace the request... */
	tok = json_get_member(buffer, resulttok, "replace");
	if (tok) {
		/* We need to make copies here, as buffer and tokens
		 * can be reused. */
		p->custom_replace = json_tok_copy(p, tok);
		p->custom_buffer = tal_dup_talarr(p, char, buffer);
		return true;
	}

	/* ...or return a custom JSONRPC response. */
	tok = json_get_member(buffer, resulttok, "return");
	if (tok) {
		custom_return = json_get_member(buffer, tok, "result");
		if (custom_return) {
			p->custom_result = json_strdup(p, buffer, custom_return);
			return true;
		}

		custom_return = json_get_member(buffer, tok, "error");
		if (custom_return) {
			enum jsonrpc_errcode code;
			const char *errmsg;
			if (!json_to_jsonrpc_errcode(buffer,
						     json_get_member(buffer, custom_return, "code"),
						     &code)) {
				error = "'error' object does not contain a code.";
				goto log_error_and_skip;
			}
			errmsg = json_strdup(tmpctx, buffer,
			                     json_get_member(buffer, custom_return, "message"));
			if (!errmsg) {
				error = "'error' object does not contain a message.";
				goto log_error_and_skip;
			}
			p->custom_error = json_strdup(p, buffer, custom_return);
			return true;
		}
	}

log_error_and_skip:
	/* Just log BROKEN errors. Give other plugins a chance. */
	log_broken(ld->log, "Bad response to 'rpc_command' hook. %s", error);
	return true;
}

REGISTER_PLUGIN_HOOK(rpc_command,
		     rpc_command_hook_callback,
		     rpc_command_hook_final,
		     rpc_command_hook_serialize,
		     struct rpc_command_hook_payload *);

/* We return struct command_result so command_fail return value has a natural
 * sink; we don't actually use the result. */
static struct command_result *
parse_request(struct json_connection *jcon, const jsmntok_t tok[])
{
	const jsmntok_t *method, *id, *params, *filter, *jsonrpc;
	struct command *c;
	struct rpc_command_hook_payload *rpc_hook;
	bool completed;

	if (tok[0].type != JSMN_OBJECT) {
		json_command_malformed(jcon, "null",
				       "Expected {} for json command");
		return NULL;
	}

	method = json_get_member(jcon->buffer, tok, "method");
	params = json_get_member(jcon->buffer, tok, "params");
	filter = json_get_member(jcon->buffer, tok, "filter");
	id = json_get_member(jcon->buffer, tok, "id");

	if (!id) {
		json_command_malformed(jcon, "null", "No id");
		return NULL;
	}

	if (id->type != JSMN_STRING && id->type != JSMN_PRIMITIVE) {
		json_command_malformed(jcon, "null",
				       "Expected string/primitive for id");
		return NULL;
	}

	jsonrpc = json_get_member(jcon->buffer, tok, "jsonrpc");
	if (!jsonrpc || jsonrpc->type != JSMN_STRING || !json_tok_streq(jcon->buffer, jsonrpc, "2.0")) {
		json_command_malformed(jcon, "null", "jsonrpc: \"2.0\" must be specified in the request");
		return NULL;
	}

	/* Allocate the command off of the `jsonrpc` object and not
	 * the connection since the command may outlive `conn`. */
	c = tal(jcon->ld->jsonrpc, struct command);
	c->jcon = jcon;
	c->send_notifications = jcon->notifications_enabled;
	c->ld = jcon->ld;
	c->pending = false;
	c->json_stream = NULL;
	c->id_is_string = (id->type == JSMN_STRING);
	/* Include "" around string */
	c->id = tal_strndup(c,
			    json_tok_full(jcon->buffer, id),
			    json_tok_full_len(id));
	c->mode = CMD_NORMAL;
	c->filter = NULL;
	list_add_tail(&jcon->commands, &c->list);
	tal_add_destructor(c, destroy_command);

	if (!method || !params) {
		return command_fail(c, JSONRPC2_INVALID_REQUEST,
				    method ? "No params" : "No method");
	}

	if (method->type != JSMN_STRING) {
		return command_fail(c, JSONRPC2_INVALID_REQUEST,
				    "Expected string for method");
	}

	if (filter) {
		struct command_result *ret;
		ret = parse_filter(c, "filter", jcon->buffer, filter);
		if (ret)
			return ret;
	}

	/* Debug was too chatty, so we use IO here, even though we're
	 * actually just logging the id */
	log_io(jcon->log, LOG_IO_IN, NULL, c->id, NULL, 0);

	c->json_cmd = find_cmd(jcon->ld->jsonrpc, jcon->buffer, method);
	if (!c->json_cmd) {
		return command_fail(
		    c, JSONRPC2_METHOD_NOT_FOUND, "Unknown command '%.*s'",
		    method->end - method->start, jcon->buffer + method->start);
	}
	if (c->json_cmd->deprecated && !jcon->ld->deprecated_apis) {
		return command_fail(c, JSONRPC2_METHOD_NOT_FOUND,
				    "Command %.*s is deprecated",
				    json_tok_full_len(method),
				    json_tok_full(jcon->buffer, method));
	}
	if (c->json_cmd->dev_only && !jcon->ld->developer) {
		return command_fail(c, JSONRPC2_METHOD_NOT_FOUND,
				    "Command %.*s is developer-only",
				    json_tok_full_len(method),
				    json_tok_full(jcon->buffer, method));
	}

	rpc_hook = tal(c, struct rpc_command_hook_payload);
	rpc_hook->cmd = c;
	/* Duplicate since we might outlive the connection */
	rpc_hook->buffer = tal_dup_talarr(rpc_hook, char, jcon->buffer);
	rpc_hook->request = tal_dup_talarr(rpc_hook, jsmntok_t, tok);

	/* NULL the custom_ values for the hooks */
	rpc_hook->custom_result = NULL;
	rpc_hook->custom_error = NULL;
	rpc_hook->custom_replace = NULL;
	rpc_hook->custom_buffer = NULL;

	trace_span_start("lightningd/jsonrpc", &c);
	trace_span_tag(&c, "method", c->json_cmd->name);
	completed = plugin_hook_call_rpc_command(jcon->ld, c->id, rpc_hook);
	trace_span_end(&c);

	/* If it's deferred, mark it (otherwise, it's completed) */
	if (!completed)
		return command_still_pending(c);
	return NULL;
}

/* Mutual recursion */
static struct io_plan *stream_out_complete(struct io_conn *conn,
					   struct json_stream *js,
					   struct json_connection *jcon);

static struct io_plan *start_json_stream(struct io_conn *conn,
					 struct json_connection *jcon)
{
	/* If something has created an output buffer, start streaming. */
	if (tal_count(jcon->js_arr)) {
		size_t len;
		const char *p = json_out_contents(jcon->js_arr[0]->jout, &len);
		if (len)
			log_io(jcon->log, LOG_IO_OUT, NULL, "", p, len);
		return json_stream_output(jcon->js_arr[0], conn,
					  stream_out_complete, jcon);
	}

	/* Tell reader it can run next command. */
	io_wake(conn);

	/* Once the stop_conn conn is drained, we can shut down. */
	if (jcon->ld->stop_conn == conn && jcon->ld->state == LD_STATE_RUNNING) {
		/* Return us to toplevel lightningd.c */
		log_debug(jcon->ld->log, "io_break: %s", __func__);
		io_break(jcon->ld);
		/* We never come back. */
		return io_out_wait(conn, conn, io_never, conn);
	}

	return io_out_wait(conn, jcon, start_json_stream, jcon);
}

/* Command has completed writing, and we've written it all out to conn. */
static struct io_plan *stream_out_complete(struct io_conn *conn,
					   struct json_stream *js,
					   struct json_connection *jcon)
{
	jcon_remove_json_stream(jcon, js);
	tal_free(js);

	/* Wait for more output. */
	return start_json_stream(conn, jcon);
}

static struct io_plan *read_json(struct io_conn *conn,
				 struct json_connection *jcon)
{
	bool complete;
	bool in_transaction = false;
	struct timemono start_time = time_mono();

	if (jcon->len_read)
		log_io(jcon->log, LOG_IO_IN, NULL, "",
		       jcon->buffer + jcon->used, jcon->len_read);

	/* Resize larger if we're full. */
	jcon->used += jcon->len_read;
	if (jcon->used == tal_count(jcon->buffer))
		tal_resize(&jcon->buffer, jcon->used * 2);

	/* We wait for pending output to be consumed, to avoid DoS */
	if (tal_count(jcon->js_arr) != 0) {
		jcon->len_read = 0;
		return io_wait(conn, conn, read_json, jcon);
	}

again:
	if (!json_parse_input(&jcon->input_parser, &jcon->input_toks,
			      jcon->buffer, jcon->used,
			      &complete)) {
		json_command_malformed(
		    jcon, "null",
		    tal_fmt(tmpctx, "Invalid token in json input: '%s'",
			    tal_hexstr(tmpctx, jcon->buffer, jcon->used)));
		if (in_transaction)
			db_commit_transaction(jcon->ld->wallet->db);
		return io_halfclose(conn);
	}

	if (!complete)
		goto read_more;

	/* Empty buffer? (eg. just whitespace). */
	if (tal_count(jcon->input_toks) == 1) {
		jcon->used = 0;

		/* Reset parser. */
		jsmn_init(&jcon->input_parser);
		toks_reset(jcon->input_toks);
		goto read_more;
	}

	if (!in_transaction) {
		db_begin_transaction(jcon->ld->wallet->db);
		in_transaction = true;
	}
	parse_request(jcon, jcon->input_toks);

	/* Remove first {}. */
	memmove(jcon->buffer, jcon->buffer + jcon->input_toks[0].end,
		tal_count(jcon->buffer) - jcon->input_toks[0].end);
	jcon->used -= jcon->input_toks[0].end;

	/* Reset parser. */
	jsmn_init(&jcon->input_parser);
	toks_reset(jcon->input_toks);

	/* Do we have more already read? */
	if (jcon->used) {
		if (!jcon->db_batching) {
			db_commit_transaction(jcon->ld->wallet->db);
			in_transaction = false;
		} else {
			/* FIXME: io_always() should interleave with
			 * real IO, and then we should rotate order we
			 * service fds in, to avoid starvation. */
			if (time_greater(timemono_between(time_mono(),
							  start_time),
					 time_from_msec(250))) {
				db_commit_transaction(jcon->ld->wallet->db);
				/* Call us back, as if we read nothing new */
				jcon->len_read = 0;
				return io_always(conn, read_json, jcon);
			}
		}
		goto again;
	}

read_more:
	if (in_transaction)
		db_commit_transaction(jcon->ld->wallet->db);
	return io_read_partial(conn, jcon->buffer + jcon->used,
			       tal_count(jcon->buffer) - jcon->used,
			       &jcon->len_read, read_json, jcon);
}

static struct io_plan *jcon_connected(struct io_conn *conn,
				      struct lightningd *ld)
{
	struct json_connection *jcon;

	/* We live as long as the connection, so we're not a leak. */
	jcon = notleak(tal(conn, struct json_connection));
	jcon->conn = conn;
	jcon->ld = ld;
	jcon->used = 0;
	jcon->buffer = tal_arr(jcon, char, 64);
	jcon->js_arr = tal_arr(jcon, struct json_stream *, 0);
	jcon->len_read = 0;
	jsmn_init(&jcon->input_parser);
	jcon->input_toks = toks_alloc(jcon);
	jcon->notifications_enabled = false;
	jcon->db_batching = false;
	list_head_init(&jcon->commands);

	/* We want to log on destruction, so we free this in destructor. */
	jcon->log = new_logger(ld->log_book, ld->log_book, NULL, "jsonrpc#%i",
			       io_conn_fd(conn));

	tal_add_destructor(jcon, destroy_jcon);

	/* Note that write_json and read_json alternate manually, by waking
	 * each other.  It would be simpler to not use a duplex io, and have
	 * read_json parse one command, then io_wait() for command completion
	 * and go to write_json.
	 *
	 * However, if we ever have notifications, this neat cmd-response
	 * pattern would break down, so we use this trick. */
	return io_duplex(conn,
			 read_json(conn, jcon),
			 start_json_stream(conn, jcon));
}

static struct io_plan *incoming_jcon_connected(struct io_conn *conn,
					       struct lightningd *ld)
{
	/* Lifetime of JSON conn is limited to fd connect time. */
	return jcon_connected(notleak(conn), ld);
}

static void destroy_json_command(struct json_command *command, struct jsonrpc *rpc)
{
	strmap_del(&rpc->usagemap, command->name, NULL);
	for (size_t i = 0; i < tal_count(rpc->commands); i++) {
		if (rpc->commands[i] == command) {
			tal_arr_remove(&rpc->commands, i);
			return;
		}
	}
	abort();
}

static bool command_add(struct jsonrpc *rpc, struct json_command *command)
{
	size_t count = tal_count(rpc->commands);

	/* Check that we don't clobber a method */
	for (size_t i = 0; i < count; i++)
		if (streq(rpc->commands[i]->name, command->name))
			return false;

	tal_arr_expand(&rpc->commands, command);
	return true;
}

/* Built-in commands get called to construct usage string via param() */
static void setup_command_usage(struct lightningd *ld,
				struct json_command *command)
{
	const struct command_result *res;
	struct command *dummy;

	/* Call it with minimal cmd, to fill out usagemap */
	dummy = tal(tmpctx, struct command);
	dummy->mode = CMD_USAGE;
	dummy->ld = ld;
	dummy->json_cmd = command;
	res = command->dispatch(dummy, NULL, NULL, NULL);
	assert(res == &param_failed);
	assert(strmap_get(&ld->jsonrpc->usagemap, command->name));
}

bool jsonrpc_command_add(struct jsonrpc *rpc, struct json_command *command,
			 const char *usage TAKES)
{
	if (!command_add(rpc, command))
		return false;
	usage = tal_strdup(command, usage);
	strmap_add(&rpc->usagemap, command->name, usage);
	tal_add_destructor2(command, destroy_json_command, rpc);
	return true;
}

static bool jsonrpc_command_add_perm(struct lightningd *ld,
				     struct jsonrpc *rpc,
				     struct json_command *command)
{
	if (!command_add(rpc, command))
		return false;
	setup_command_usage(ld, command);
	return true;
}

static void destroy_jsonrpc(struct jsonrpc *jsonrpc)
{
	strmap_clear(&jsonrpc->usagemap);
}

static void memleak_help_jsonrpc(struct htable *memtable,
				 struct jsonrpc *jsonrpc)
{
	memleak_scan_strmap(memtable, &jsonrpc->usagemap);
}

void jsonrpc_setup(struct lightningd *ld)
{
	struct json_command **commands = get_cmdlist();

	ld->jsonrpc = tal(ld, struct jsonrpc);
	strmap_init(&ld->jsonrpc->usagemap);
	ld->jsonrpc->commands = tal_arr(ld->jsonrpc, struct json_command *, 0);
	for (size_t i=0; i<num_cmdlist; i++) {
		if (!jsonrpc_command_add_perm(ld, ld->jsonrpc, commands[i]))
			fatal("Cannot add duplicate command %s",
			      commands[i]->name);
	}
	ld->jsonrpc->rpc_listener = NULL;
	tal_add_destructor(ld->jsonrpc, destroy_jsonrpc);
	memleak_add_helper(ld->jsonrpc, memleak_help_jsonrpc);
}

bool command_usage_only(const struct command *cmd)
{
	return cmd->mode == CMD_USAGE;
}

bool command_deprecated_apis(const struct command *cmd)
{
	return cmd->ld->deprecated_apis;
}

bool command_dev_apis(const struct command *cmd)
{
	return cmd->ld->developer;
}

void command_set_usage(struct command *cmd, const char *usage TAKES)
{
	usage = tal_strdup(cmd->ld, usage);
	if (!strmap_add(&cmd->ld->jsonrpc->usagemap, cmd->json_cmd->name, usage))
		fatal("Two usages for command %s?", cmd->json_cmd->name);
}

bool command_check_only(const struct command *cmd)
{
	return cmd->mode == CMD_CHECK || cmd->mode == CMD_CHECK_FAILED;
}

void jsonrpc_listen(struct jsonrpc *jsonrpc, struct lightningd *ld)
{
	struct sockaddr_un addr;
	int fd, old_umask, new_umask;
	const char *rpc_filename = ld->rpc_filename;

	/* Should not initialize it twice. */
	assert(!jsonrpc->rpc_listener);

	if (streq(rpc_filename, "/dev/tty")) {
		fd = open(rpc_filename, O_RDWR);
		if (fd == -1)
			err(1, "Opening %s", rpc_filename);
		/* Technically this is a leak, but there's only one */
		notleak(io_new_conn(ld, fd, jcon_connected, ld));
		return;
	}

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		errx(1, "domain socket creation failed");
	}
	if (strlen(rpc_filename) + 1 > sizeof(addr.sun_path))
		errx(1, "rpc filename '%s' too long", rpc_filename);
	strcpy(addr.sun_path, rpc_filename);
	addr.sun_family = AF_UNIX;

	/* Of course, this is racy! */
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0)
		errx(1, "rpc filename '%s' in use", rpc_filename);
	unlink(rpc_filename);

	/* Set the umask according to the desired file mode.  */
	new_umask = ld->rpc_filemode ^ 0777;
	old_umask = umask(new_umask);
	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)))
		err(1, "Binding rpc socket to '%s'", rpc_filename);
	umask(old_umask);

	if (listen(fd, 128) != 0)
		err(1, "Listening on '%s'", rpc_filename);

	/* All conns will be tal children of jsonrpc: good for freeing later! */
	jsonrpc->rpc_listener
		= io_new_listener(jsonrpc, fd, incoming_jcon_connected, ld);
}

void jsonrpc_stop_listening(struct jsonrpc *jsonrpc)
{
	jsonrpc->rpc_listener = tal_free(jsonrpc->rpc_listener);
}

void jsonrpc_stop_all(struct lightningd *ld)
{
	/* Closes all conns. */
	ld->jsonrpc = tal_free(ld->jsonrpc);
}

static struct command_result *param_command(struct command *cmd,
					    const char *name,
					    const char *buffer,
					    const jsmntok_t *tok,
					    const jsmntok_t **out)
{
	cmd->json_cmd = find_cmd(cmd->jcon->ld->jsonrpc, buffer, tok);
	if (cmd->json_cmd) {
		*out = tok;
		return NULL;
	}

	return command_fail(cmd, JSONRPC2_METHOD_NOT_FOUND,
			    "Unknown command '%.*s'",
			    tok->end - tok->start, buffer + tok->start);
}

struct jsonrpc_notification *jsonrpc_notification_start(const tal_t *ctx, const char *method)
{
	struct jsonrpc_notification *n = tal(ctx, struct jsonrpc_notification);
	n->method = tal_strdup(n, method);
	n->stream = new_json_stream(n, NULL, NULL);
	json_object_start(n->stream, NULL);
	json_add_string(n->stream, "jsonrpc", "2.0");
	json_add_string(n->stream, "method", method);
	json_object_start(n->stream, "params");

	return n;
}

void jsonrpc_notification_end(struct jsonrpc_notification *n)
{
	json_object_end(n->stream); /* closes '.params' */
	json_object_end(n->stream); /* closes '.' */

	/* We guarantee to have \n\n at end of each response. */
	json_stream_append(n->stream, "\n\n", strlen("\n\n"));
}

struct jsonrpc_request *jsonrpc_request_start_(
    const tal_t *ctx, const char *method,
    const char *id_prefix, bool id_as_string, struct logger *log,
    bool add_header,
    void (*notify_cb)(const char *buffer,
		      const jsmntok_t *methodtok,
		      const jsmntok_t *paramtoks,
		      const jsmntok_t *idtok,
		      void *),
    void (*response_cb)(const char *buffer, const jsmntok_t *toks,
			const jsmntok_t *idtok, void *),
    void *response_cb_arg)
{
	struct jsonrpc_request *r = tal(ctx, struct jsonrpc_request);
	static u64 next_request_id = 0;

	r->id_is_string = id_as_string;
	if (r->id_is_string) {
		if (id_prefix) {
			/* Strip "" and otherwise sanity-check */
			if (strstarts(id_prefix, "\"")
			    && strlen(id_prefix) > 1
			    && strends(id_prefix, "\"")) {
				id_prefix = tal_strndup(tmpctx, id_prefix + 1,
							strlen(id_prefix) - 2);
			}
			/* We could try escaping, but TBH they're
			 * messing with us at this point! */
			if (json_escape_needed(id_prefix, strlen(id_prefix)))
				id_prefix = "weird-id";

			r->id = tal_fmt(r, "\"%s/cln:%s#%"PRIu64"\"",
					id_prefix, method, next_request_id);
		} else
			r->id = tal_fmt(r, "\"cln:%s#%"PRIu64"\"", method, next_request_id);
	} else {
		r->id = tal_fmt(r, "%"PRIu64, next_request_id);
	}
	if (taken(id_prefix))
		tal_free(id_prefix);
	next_request_id++;
	r->notify_cb = notify_cb;
	r->response_cb = response_cb;
	r->response_cb_arg = response_cb_arg;
	r->method = tal_strdup(r, method);
	r->stream = new_json_stream(r, NULL, log);

	/* Disabling this serves as an escape hatch for plugin code to
	 * get a raw request to paste into, but get a valid request-id
	 * assigned. */
	if (add_header) {
		json_object_start(r->stream, NULL);
		json_add_string(r->stream, "jsonrpc", "2.0");
		json_add_id(r->stream, r->id);
		json_add_string(r->stream, "method", method);
		json_object_start(r->stream, "params");
	}
	if (log)
		log_io(log, LOG_IO_OUT, NULL, r->id, NULL, 0);

	return r;
}

void jsonrpc_request_end(struct jsonrpc_request *r)
{
	json_object_end(r->stream); /* closes '.params' */
	json_object_end(r->stream); /* closes '.' */

	/* We guarantee to have \n\n at end of each response. */
	json_stream_append(r->stream, "\n\n", strlen("\n\n"));
}

static struct command_result *json_check(struct command *cmd,
					 const char *buffer,
					 const jsmntok_t *obj UNNEEDED,
					 const jsmntok_t *params)
{
	jsmntok_t *mod_params;
	const jsmntok_t *name_tok;
	struct json_stream *response;
	struct command_result *res;

	if (cmd->mode == CMD_USAGE) {
		mod_params = NULL;
	} else {
		mod_params = json_tok_copy(cmd, params);
	}

	if (!param(cmd, buffer, mod_params,
		   p_req("command_to_check", param_command, &name_tok),
		   p_opt_any(),
		   NULL))
		return command_param_failed();

	/* Point name_tok to the name, not the value */
	if (params->type == JSMN_OBJECT)
		name_tok--;

	json_tok_remove(&mod_params, mod_params, name_tok, 1);

	cmd->mode = CMD_CHECK;
	/* Make *sure* it doesn't try to manip db! */
	db_set_readonly(cmd->ld->wallet->db, true);
	res = cmd->json_cmd->dispatch(cmd, buffer, mod_params, mod_params);
	db_set_readonly(cmd->ld->wallet->db, false);

	/* CMD_CHECK always makes it "fail" parameter parsing. */
	assert(res == &param_failed);
	if (cmd->mode == CMD_CHECK_FAILED) {
		tal_free(cmd);
		return res;
	}

	response = json_stream_success(cmd);
	json_add_string(response, "command_to_check", cmd->json_cmd->name);
	res = command_success(cmd, response);
	/* CMD_CHECK means we don't get freed! */
	tal_free(cmd);
	return res;
}

static const struct json_command check_command = {
	"check",
	"utility",
	json_check,
	"Don't run {command_to_check}, just verify parameters.",
	.verbose = "check command_to_check [parameters...]\n"
};
AUTODATA(json_command, &check_command);

static struct command_result *json_notifications(struct command *cmd,
						 const char *buffer,
						 const jsmntok_t *obj UNNEEDED,
						 const jsmntok_t *params)
{
	bool *enable;

	if (!param(cmd, buffer, params,
		   p_req("enable", param_bool, &enable),
		   NULL))
		return command_param_failed();

	/* Catch the case where they sent this command then hung up. */
	if (cmd->jcon)
		cmd->jcon->notifications_enabled = *enable;
	return command_success(cmd, json_stream_success(cmd));
}

static const struct json_command notifications_command = {
	"notifications",
	"utility",
	json_notifications,
	"{enable} notifications",
};
AUTODATA(json_command, &notifications_command);

static struct command_result *json_batching(struct command *cmd,
					    const char *buffer,
					    const jsmntok_t *obj UNNEEDED,
					    const jsmntok_t *params)
{
	bool *enable;

	if (!param(cmd, buffer, params,
		   p_req("enable", param_bool, &enable),
		   NULL))
		return command_param_failed();

	/* Catch the case where they sent this command then hung up. */
	if (cmd->jcon)
		cmd->jcon->db_batching = *enable;
	return command_success(cmd, json_stream_success(cmd));
}

static const struct json_command batching_command = {
	"batching",
	"utility",
	json_batching,
	"Database transaction batching {enable}",
};
AUTODATA(json_command, &batching_command);
