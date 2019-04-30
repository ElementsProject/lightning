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
#include <arpa/inet.h>
#include <bitcoin/address.h>
#include <bitcoin/base58.h>
#include <bitcoin/script.h>
#include <ccan/array_size/array_size.h>
#include <ccan/err/err.h>
#include <ccan/io/io.h>
#include <ccan/str/hex/hex.h>
#include <ccan/strmap/strmap.h>
#include <ccan/tal/str/str.h>
#include <common/bech32.h>
#include <common/json_command.h>
#include <common/json_escaped.h>
#include <common/jsonrpc_errors.h>
#include <common/memleak.h>
#include <common/param.h>
#include <common/timeout.h>
#include <common/version.h>
#include <common/wireaddr.h>
#include <errno.h>
#include <fcntl.h>
#include <lightningd/chaintopology.h>
#include <lightningd/json.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/log.h>
#include <lightningd/memdump.h>
#include <lightningd/options.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
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
	struct log *log;

	/* The buffer (required to interpret tokens). */
	char *buffer;

	/* Internal state: */
	/* How much is already filled. */
	size_t used;
	/* How much has just been filled. */
	size_t len_read;

	/* We've been told to stop. */
	bool stop;

	/* Our commands */
	struct list_head commands;

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
	struct log *log;

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

	list_for_each(&jcon->commands, c, list) {
		log_debug(jcon->log, "Abandoning command %s", c->json_cmd->name);
		c->jcon = NULL;
	}

	/* Make sure this happens last! */
	tal_free(jcon->log);
}

static struct command_result *json_help(struct command *cmd,
					const char *buffer,
					const jsmntok_t *obj UNNEEDED,
					const jsmntok_t *params);

static const struct json_command help_command = {
	"help",
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
	struct json_stream *response;

	if (!param(cmd, buffer, params, NULL))
		return command_param_failed();

	/* This can't have closed yet! */
	cmd->jcon->stop = true;
	response = json_stream_success(cmd);
	json_add_string(response, NULL, "Shutting down");
	return command_success(cmd, response);
}

static const struct json_command stop_command = {
	"stop",
	json_stop,
	"Shut down the lightningd process"
};
AUTODATA(json_command, &stop_command);

#if DEVELOPER
static struct command_result *json_rhash(struct command *cmd,
					 const char *buffer,
					 const jsmntok_t *obj UNUSED,
					 const jsmntok_t *params)
{
	struct json_stream *response;
	struct sha256 *secret;

	if (!param(cmd, buffer, params,
		   p_req("secret", param_sha256, &secret),
		   NULL))
		return command_param_failed();

	/* Hash in place. */
	sha256(secret, secret, sizeof(*secret));
	response = json_stream_success(cmd);
	json_object_start(response, NULL);
	json_add_hex(response, "rhash", secret, sizeof(*secret));
	json_object_end(response);
	return command_success(cmd, response);
}

static const struct json_command dev_rhash_command = {
	"dev-rhash",
	json_rhash,
	"Show SHA256 of {secret}"
};
AUTODATA(json_command, &dev_rhash_command);

struct slowcmd {
	struct command *cmd;
	unsigned *msec;
	struct json_stream *js;
};

static void slowcmd_finish(struct slowcmd *sc)
{
	json_object_start(sc->js, NULL);
	json_add_num(sc->js, "msec", *sc->msec);
	json_object_end(sc->js);
	was_pending(command_success(sc->cmd, sc->js));
}

static void slowcmd_start(struct slowcmd *sc)
{
	sc->js = json_stream_success(sc->cmd);
	new_reltimer(&sc->cmd->ld->timers, sc, time_from_msec(*sc->msec),
		     slowcmd_finish, sc);
}

static struct command_result *json_slowcmd(struct command *cmd,
					   const char *buffer,
					   const jsmntok_t *obj UNUSED,
					   const jsmntok_t *params)
{
	struct slowcmd *sc = tal(cmd, struct slowcmd);

	sc->cmd = cmd;
	if (!param(cmd, buffer, params,
		   p_opt_def("msec", param_number, &sc->msec, 1000),
		   NULL))
		return command_param_failed();

	new_reltimer(&cmd->ld->timers, sc, time_from_msec(0), slowcmd_start, sc);
	return command_still_pending(cmd);
}

static const struct json_command dev_slowcmd_command = {
	"dev-slowcmd",
	json_slowcmd,
	"Torture test for slow commands, optional {msec}"
};
AUTODATA(json_command, &dev_slowcmd_command);

static struct command_result *json_crash(struct command *cmd UNUSED,
					 const char *buffer,
					 const jsmntok_t *obj UNNEEDED,
					 const jsmntok_t *params)
{
	if (!param(cmd, buffer, params, NULL))
		return command_param_failed();

	fatal("Crash at user request");
}

static const struct json_command dev_crash_command = {
	"dev-crash",
	json_crash,
	"Crash lightningd by calling fatal()"
};
AUTODATA(json_command, &dev_crash_command);
#endif /* DEVELOPER */

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

	usage = tal_fmt(cmd, "%s %s",
			json_command->name,
			strmap_get(&cmd->ld->jsonrpc->usagemap,
				   json_command->name));
	json_object_start(response, NULL);

	json_add_string(response, "command", usage);
	json_add_string(response, "description", json_command->description);

	if (!json_command->verbose) {
		json_add_string(response, "verbose",
				"HELP! Please contribute"
				" a description for this"
				" json_command!");
	} else {
		struct json_escaped *esc;

		esc = json_escape(NULL, json_command->verbose);
		json_add_escaped_string(response, "verbose", take(esc));
	}

	json_object_end(response);

}

static const struct json_command *find_command(struct json_command **commands,
					       const char *buffer,
					       const jsmntok_t *cmdtok)
{
	for (size_t i = 0; i < tal_count(commands); i++) {
		if (json_tok_streq(buffer, cmdtok, commands[i]->name))
			return commands[i];
	}
	return NULL;
}

static struct command_result *json_help(struct command *cmd,
					const char *buffer,
					const jsmntok_t *obj UNNEEDED,
					const jsmntok_t *params)
{
	struct json_stream *response;
	const jsmntok_t *cmdtok;
	struct json_command **commands;
	const struct json_command *one_cmd;

	if (!param(cmd, buffer, params,
		   p_opt("command", param_tok, &cmdtok),
		   NULL))
		return command_param_failed();

	commands = cmd->ld->jsonrpc->commands;
	if (cmdtok) {
		one_cmd = find_command(commands, buffer, cmdtok);
		if (!one_cmd)
			return command_fail(cmd, JSONRPC2_METHOD_NOT_FOUND,
					    "Unknown command '%.*s'",
					    cmdtok->end - cmdtok->start,
					    buffer + cmdtok->start);
	} else
		one_cmd = NULL;

	response = json_stream_success(cmd);
	json_object_start(response, NULL);
	json_array_start(response, "help");
	for (size_t i = 0; i < tal_count(commands); i++) {
		if (!one_cmd || one_cmd == commands[i])
			json_add_help_command(cmd, response, commands[i]);
	}
	json_array_end(response);
	json_object_end(response);

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

struct json_stream *null_response(struct command *cmd)
{
	struct json_stream *response;

	response = json_stream_success(cmd);
	json_object_start(response, NULL);
	json_object_end(response);
	return response;
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

	tal_free(cmd);
	return &complete;
}

struct command_result *command_success(struct command *cmd,
				       struct json_stream *result)
{
	assert(cmd);
	assert(cmd->have_json_stream);
	json_stream_append(result, " }\n\n");

	return command_raw_complete(cmd, result);
}

struct command_result *command_failed(struct command *cmd,
				      struct json_stream *result)
{
	assert(cmd->have_json_stream);
	/* Have to close error */
	json_stream_append(result, " } }\n\n");

	return command_raw_complete(cmd, result);
}

struct command_result *command_fail(struct command *cmd, int code,
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

struct command_result *command_still_pending(struct command *cmd)
{
	notleak_with_children(cmd);
	cmd->pending = true;
	return &pending;
}

static void json_command_malformed(struct json_connection *jcon,
				   const char *id,
				   const char *error)
{
	/* NULL writer is OK here, since we close it immediately. */
	struct json_stream *js = jcon_new_json_stream(jcon, jcon, NULL);

	json_stream_append_fmt(js,
			       "{ \"jsonrpc\": \"2.0\", \"id\" : %s,"
			       " \"error\" : "
			       "{ \"code\" : %d,"
			       " \"message\" : \"%s\" } }\n\n",
			       id, JSONRPC2_INVALID_REQUEST, error);

	json_stream_close(js, NULL);
}

struct json_stream *json_stream_raw_for_cmd(struct command *cmd)
{
	struct json_stream *js;

	/* If they still care about the result, attach it to them. */
	if (cmd->jcon)
		js = jcon_new_json_stream(cmd, cmd->jcon, cmd);
	else
		js = new_json_stream(cmd, cmd, NULL);

	assert(!cmd->have_json_stream);
	cmd->have_json_stream = true;
	return js;
}

static struct json_stream *json_start(struct command *cmd)
{
	struct json_stream *js = json_stream_raw_for_cmd(cmd);

	json_stream_append_fmt(js, "{ \"jsonrpc\": \"2.0\", \"id\" : %s, ",
			       cmd->id);
	return js;
}

struct json_stream *json_stream_success(struct command *cmd)
{
	struct json_stream *r = json_start(cmd);
	json_stream_append(r, "\"result\" : ");
	return r;
}

struct json_stream *json_stream_fail_nodata(struct command *cmd,
					    int code,
					    const char *errmsg)
{
	struct json_stream *r = json_start(cmd);
	struct json_escaped *e = json_partial_escape(tmpctx, errmsg);

	assert(code);

	json_stream_append_fmt(r, " \"error\" : "
			  "{ \"code\" : %d,"
			  " \"message\" : \"%s\"", code, e->s);
	return r;
}

struct json_stream *json_stream_fail(struct command *cmd,
				     int code,
				     const char *errmsg)
{
	struct json_stream *r = json_stream_fail_nodata(cmd, code, errmsg);

	json_stream_append(r, ", \"data\" : ");
	return r;
}

/* We return struct command_result so command_fail return value has a natural
 * sink; we don't actually use the result. */
static struct command_result *
parse_request(struct json_connection *jcon, const jsmntok_t tok[])
{
	const jsmntok_t *method, *id, *params;
	struct command *c;
	struct command_result *res;

	if (tok[0].type != JSMN_OBJECT) {
		json_command_malformed(jcon, "null",
				       "Expected {} for json command");
		return NULL;
	}

	method = json_get_member(jcon->buffer, tok, "method");
	params = json_get_member(jcon->buffer, tok, "params");
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

	/* Allocate the command off of the `jsonrpc` object and not
	 * the connection since the command may outlive `conn`. */
	c = tal(jcon->ld->jsonrpc, struct command);
	c->jcon = jcon;
	c->ld = jcon->ld;
	c->pending = false;
	c->have_json_stream = false;
	c->id = tal_strndup(c,
			    json_tok_full(jcon->buffer, id),
			    json_tok_full_len(id));
	c->mode = CMD_NORMAL;
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

	c->json_cmd = find_cmd(jcon->ld->jsonrpc, jcon->buffer, method);
	if (!c->json_cmd) {
		return command_fail(
		    c, JSONRPC2_METHOD_NOT_FOUND, "Unknown command '%.*s'",
		    method->end - method->start, jcon->buffer + method->start);
	}
	if (c->json_cmd->deprecated && !deprecated_apis) {
		return command_fail(c, JSONRPC2_METHOD_NOT_FOUND,
				    "Command '%.*s' is deprecated",
				    method->end - method->start,
				    jcon->buffer + method->start);
	}

	db_begin_transaction(jcon->ld->wallet->db);
	res = c->json_cmd->dispatch(c, jcon->buffer, tok, params);
	db_commit_transaction(jcon->ld->wallet->db);

	assert(res == &param_failed
	       || res == &complete
	       || res == &pending
	       || res == &unknown);

	/* If they didn't complete it, they must call command_still_pending.
	 * If they completed it, it's freed already. */
	if (res == &pending)
		assert(c->pending);
	list_for_each(&jcon->commands, c, list)
		assert(c->pending);
	return res;
}

/* Mutual recursion */
static struct io_plan *stream_out_complete(struct io_conn *conn,
					   struct json_stream *js,
					   struct json_connection *jcon);

static struct io_plan *start_json_stream(struct io_conn *conn,
					 struct json_connection *jcon)
{
	/* If something has created an output buffer, start streaming. */
	if (tal_count(jcon->js_arr))
		return json_stream_output(jcon->js_arr[0], conn,
					  stream_out_complete, jcon);

	/* Tell reader it can run next command. */
	io_wake(conn);

	/* Wait for attach_json_stream */
	return io_out_wait(conn, jcon, start_json_stream, jcon);
}

/* Command has completed writing, and we've written it all out to conn. */
static struct io_plan *stream_out_complete(struct io_conn *conn,
					   struct json_stream *js,
					   struct json_connection *jcon)
{
	jcon_remove_json_stream(jcon, js);
	tal_free(js);

	if (jcon->stop) {
		log_unusual(jcon->log, "JSON-RPC shutdown");
		/* Return us to toplevel lightningd.c */
		io_break(jcon->ld);
		return io_close(conn);
	}

	/* Wait for more output. */
	return start_json_stream(conn, jcon);
}

static struct io_plan *read_json(struct io_conn *conn,
				 struct json_connection *jcon)
{
	jsmntok_t *toks;
	bool valid;

	if (jcon->len_read)
		log_io(jcon->log, LOG_IO_IN, "",
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

	toks = json_parse_input(jcon->buffer, jcon->buffer, jcon->used, &valid);
	if (!toks) {
		if (!valid) {
			log_unusual(jcon->log,
				    "Invalid token in json input: '%.*s'",
				    (int)jcon->used, jcon->buffer);
			json_command_malformed(
			    jcon, "null",
			    "Invalid token in json input");
			return io_halfclose(conn);
		}
		/* We need more. */
		goto read_more;
	}

	/* Empty buffer? (eg. just whitespace). */
	if (tal_count(toks) == 1) {
		jcon->used = 0;
		goto read_more;
	}

	parse_request(jcon, toks);

	/* Remove first {}. */
	memmove(jcon->buffer, jcon->buffer + toks[0].end,
		tal_count(jcon->buffer) - toks[0].end);
	jcon->used -= toks[0].end;

	/* If we have more to process, try again.  FIXME: this still gets
	 * first priority in io_loop, so can starve others.  Hack would be
	 * a (non-zero) timer, but better would be to have io_loop avoid
	 * such livelock */
	if (jcon->used) {
		tal_free(toks);
		jcon->len_read = 0;
		return io_always(conn, read_json, jcon);
	}

read_more:
	tal_free(toks);
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
	jcon->stop = false;
	jcon->js_arr = tal_arr(jcon, struct json_stream *, 0);
	jcon->len_read = 0;
	list_head_init(&jcon->commands);

	/* We want to log on destruction, so we free this in destructor. */
	jcon->log = new_log(ld->log_book, ld->log_book, "%sjcon fd %i:",
			    log_prefix(ld->log), io_conn_fd(conn));

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

void jsonrpc_setup(struct lightningd *ld)
{
	struct json_command **commands = get_cmdlist();

	ld->jsonrpc = tal(ld, struct jsonrpc);
	strmap_init(&ld->jsonrpc->usagemap);
	ld->jsonrpc->commands = tal_arr(ld->jsonrpc, struct json_command *, 0);
	ld->jsonrpc->log = new_log(ld->jsonrpc, ld->log_book, "jsonrpc");
	for (size_t i=0; i<num_cmdlist; i++) {
		if (!jsonrpc_command_add_perm(ld, ld->jsonrpc, commands[i]))
			fatal("Cannot add duplicate command %s",
			      commands[i]->name);
	}
	ld->jsonrpc->rpc_listener = NULL;
}

bool command_usage_only(const struct command *cmd)
{
	return cmd->mode == CMD_USAGE;
}

void command_set_usage(struct command *cmd, const char *usage TAKES)
{
	usage = tal_strdup(cmd->ld, usage);
	if (!strmap_add(&cmd->ld->jsonrpc->usagemap, cmd->json_cmd->name, usage))
		fatal("Two usages for command %s?", cmd->json_cmd->name);
}

bool command_check_only(const struct command *cmd)
{
	return cmd->mode == CMD_CHECK;
}

void jsonrpc_listen(struct jsonrpc *jsonrpc, struct lightningd *ld)
{
	struct sockaddr_un addr;
	int fd, old_umask;
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

	/* This file is only rw by us! */
	old_umask = umask(0177);
	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)))
		err(1, "Binding rpc socket to '%s'", rpc_filename);
	umask(old_umask);

	if (listen(fd, 1) != 0)
		err(1, "Listening on '%s'", rpc_filename);
	jsonrpc->rpc_listener = io_new_listener(
		ld->rpc_filename, fd, incoming_jcon_connected, ld);
	log_debug(jsonrpc->log, "Listening on '%s'", ld->rpc_filename);
}

/**
 * segwit_addr_net_decode - Try to decode a Bech32 address and detect
 * testnet/mainnet/regtest
 *
 * This processes the address and returns a string if it is a Bech32
 * address specified by BIP173. The string is set whether it is
 * testnet ("tb"),  mainnet ("bc"), or regtest ("bcrt")
 * It does not check, witness version and program size restrictions.
 *
 *  Out: witness_version: Pointer to an int that will be updated to contain
 *                 the witness program version (between 0 and 16 inclusive).
 *       witness_program: Pointer to a buffer of size 40 that will be updated
 *                 to contain the witness program bytes.
 *       witness_program_len: Pointer to a size_t that will be updated to
 *                 contain the length of bytes in witness_program.
 *  In:  addrz:    Pointer to the null-terminated address.
 *  Returns string containing the human readable segment of bech32 address
 */
static const char* segwit_addr_net_decode(int *witness_version,
				   uint8_t *witness_program,
				   size_t *witness_program_len,
				   const char *addrz)
{
	const char *network[] = { "bc", "tb", "bcrt" };
	for (int i = 0; i < sizeof(network) / sizeof(*network); ++i) {
		if (segwit_addr_decode(witness_version,
				       witness_program, witness_program_len,
				       network[i], addrz))
			return network[i];
	}

	return NULL;
}

enum address_parse_result
json_tok_address_scriptpubkey(const tal_t *cxt,
			      const struct chainparams *chainparams,
			      const char *buffer,
			      const jsmntok_t *tok, const u8 **scriptpubkey)
{
	struct bitcoin_address destination;
	int witness_version;
	/* segwit_addr_net_decode requires a buffer of size 40, and will
	 * not write to the buffer if the address is too long, so a buffer
	 * of fixed size 40 will not overflow. */
	uint8_t witness_program[40];
	size_t witness_program_len;

	char *addrz;
	const char *bip173;

	bool parsed;
	bool right_network;
	u8 addr_version;

	parsed =
	    ripemd160_from_base58(&addr_version, &destination.addr,
				  buffer + tok->start, tok->end - tok->start);

	if (parsed) {
		if (addr_version == chainparams->p2pkh_version) {
			*scriptpubkey = scriptpubkey_p2pkh(cxt, &destination);
			return ADDRESS_PARSE_SUCCESS;
		} else if (addr_version == chainparams->p2sh_version) {
			*scriptpubkey =
			    scriptpubkey_p2sh_hash(cxt, &destination.addr);
			return ADDRESS_PARSE_SUCCESS;
		} else {
			return ADDRESS_PARSE_WRONG_NETWORK;
		}
		/* Insert other parsers that accept pointer+len here. */
	}

	/* Generate null-terminated address. */
	addrz = tal_dup_arr(cxt, char, buffer + tok->start, tok->end - tok->start, 1);
	addrz[tok->end - tok->start] = '\0';

	bip173 = segwit_addr_net_decode(&witness_version, witness_program,
					&witness_program_len, addrz);

	if (bip173) {
		bool witness_ok = false;
		if (witness_version == 0 && (witness_program_len == 20 ||
					     witness_program_len == 32)) {
			witness_ok = true;
		}
		/* Insert other witness versions here. */

		if (witness_ok) {
			*scriptpubkey = scriptpubkey_witness_raw(cxt, witness_version,
								 witness_program, witness_program_len);
			parsed = true;
			right_network = streq(bip173, chainparams->bip173_name);
		}
	}
	/* Insert other parsers that accept null-terminated string here. */

	tal_free(addrz);

	if (parsed) {
		if (right_network)
			return ADDRESS_PARSE_SUCCESS;
		else
			return ADDRESS_PARSE_WRONG_NETWORK;
	}

	return ADDRESS_PARSE_UNRECOGNIZED;
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
	json_stream_append(n->stream, "\n\n");
}

struct jsonrpc_request *jsonrpc_request_start_(
    const tal_t *ctx, const char *method, struct log *log,
    void (*response_cb)(const char *buffer, const jsmntok_t *toks,
			const jsmntok_t *idtok, void *),
    void *response_cb_arg)
{
	struct jsonrpc_request *r = tal(ctx, struct jsonrpc_request);
	static u64 next_request_id = 0;
	r->id = next_request_id++;
	r->response_cb = response_cb;
	r->response_cb_arg = response_cb_arg;
	r->method = NULL;
	r->stream = new_json_stream(r, NULL, log);

	/* If no method is specified we don't prefill the JSON-RPC
	 * request with the header. This serves as an escape hatch to
	 * get a raw request, but get a valid request-id assigned. */
	if (method != NULL) {
		r->method = tal_strdup(r, method);
		json_object_start(r->stream, NULL);
		json_add_string(r->stream, "jsonrpc", "2.0");
		json_add_u64(r->stream, "id", r->id);
		json_add_string(r->stream, "method", method);
		json_object_start(r->stream, "params");
	}

	return r;
}

void jsonrpc_request_end(struct jsonrpc_request *r)
{
	json_object_end(r->stream); /* closes '.params' */
	json_object_end(r->stream); /* closes '.' */
	json_stream_append(r->stream, "\n\n");
}

/* We add this destructor as a canary to detect cmd failing. */
static void destroy_command_canary(struct command *cmd, bool *failed)
{
	*failed = true;
}

static struct command_result *json_check(struct command *cmd,
					 const char *buffer,
					 const jsmntok_t *obj UNNEEDED,
					 const jsmntok_t *params)
{
	jsmntok_t *mod_params;
	const jsmntok_t *name_tok;
	bool failed;
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

	json_tok_remove(&mod_params, (jsmntok_t *)name_tok, 1);

	cmd->mode = CMD_CHECK;
	failed = false;
	tal_add_destructor2(cmd, destroy_command_canary, &failed);
	res = cmd->json_cmd->dispatch(cmd, buffer, mod_params, mod_params);

	/* CMD_CHECK always makes it "fail" parameter parsing. */
	assert(res == &param_failed);

	if (failed)
		return res;

	response = json_stream_success(cmd);
	json_object_start(response, NULL);
	json_add_string(response, "command_to_check", cmd->json_cmd->name);
	json_object_end(response);
	return command_success(cmd, response);
}

static const struct json_command check_command = {
	"check",
	json_check,
	"Don't run {command_to_check}, just verify parameters.",
	.verbose = "check command_to_check [parameters...]\n"
};

AUTODATA(json_command, &check_command);

#if DEVELOPER
void jsonrpc_remove_memleak(struct htable *memtable,
			    const struct jsonrpc *jsonrpc)
{
	memleak_remove_strmap(memtable, &jsonrpc->usagemap);
}
#endif /* DEVELOPER */
