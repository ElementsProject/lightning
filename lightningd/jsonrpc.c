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
/* eg: { "method" : "dev-echo", "params" : [ "hello", "Arabella!" ], "id" : "1" } */
#include <arpa/inet.h>
#include <bitcoin/address.h>
#include <bitcoin/base58.h>
#include <bitcoin/script.h>
#include <ccan/array_size/array_size.h>
#include <ccan/err/err.h>
#include <ccan/io/io.h>
#include <ccan/str/hex/hex.h>
#include <ccan/tal/str/str.h>
#include <common/bech32.h>
#include <common/memleak.h>
#include <common/timeout.h>
#include <common/version.h>
#include <common/wallet_tx.h>
#include <common/wireaddr.h>
#include <errno.h>
#include <fcntl.h>
#include <lightningd/chaintopology.h>
#include <lightningd/json.h>
#include <lightningd/json_escaped.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/jsonrpc_errors.h>
#include <lightningd/log.h>
#include <lightningd/options.h>
#include <lightningd/param.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>

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
};

/* The command itself usually owns the stream, because jcon may get closed.
 * The command transfers ownership once it's done though. */
static struct json_stream *jcon_new_json_stream(const tal_t *ctx,
						struct json_connection *jcon,
						struct command *writer)
{
	/* Wake writer to start streaming, in case it's not already. */
	io_wake(jcon);

	/* FIXME: Keep streams around for recycling. */
	return *tal_arr_expand(&jcon->js_arr) = new_json_stream(ctx, writer);
}

static void jcon_remove_json_stream(struct json_connection *jcon,
				    struct json_stream *js)
{
	for (size_t i = 0; i < tal_count(jcon->js_arr); i++) {
		if (js != jcon->js_arr[i])
			continue;

		memmove(jcon->js_arr + i,
			jcon->js_arr + i + 1,
			(tal_count(jcon->js_arr) - i - 1)
			* sizeof(jcon->js_arr[i]));
		tal_resize(&jcon->js_arr, tal_count(jcon->js_arr)-1);
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

static void json_help(struct command *cmd,
		      const char *buffer, const jsmntok_t *params);

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

static void json_stop(struct command *cmd,
		      const char *buffer UNUSED, const jsmntok_t *params UNUSED)
{
	struct json_stream *response;

	if (!param(cmd, buffer, params, NULL))
		return;

	/* This can't have closed yet! */
	cmd->jcon->stop = true;
	response = json_stream_success(cmd);
	json_add_string(response, NULL, "Shutting down");
	command_success(cmd, response);
}

static const struct json_command stop_command = {
	"stop",
	json_stop,
	"Shut down the lightningd process"
};
AUTODATA(json_command, &stop_command);

#if DEVELOPER
static void json_rhash(struct command *cmd,
		       const char *buffer, const jsmntok_t *params)
{
	struct json_stream *response;
	struct sha256 *secret;

	if (!param(cmd, buffer, params,
		   p_req("secret", json_tok_sha256, &secret),
		   NULL))
		return;

	/* Hash in place. */
	sha256(secret, secret, sizeof(*secret));
	response = json_stream_success(cmd);
	json_object_start(response, NULL);
	json_add_hex(response, "rhash", secret, sizeof(*secret));
	json_object_end(response);
	command_success(cmd, response);
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
	command_success(sc->cmd, sc->js);
}

static void slowcmd_start(struct slowcmd *sc)
{
	sc->js = json_stream_success(sc->cmd);
	new_reltimer(&sc->cmd->ld->timers, sc, time_from_msec(*sc->msec),
		     slowcmd_finish, sc);
}

static void json_slowcmd(struct command *cmd,
			 const char *buffer, const jsmntok_t *params)
{
	struct slowcmd *sc = tal(cmd, struct slowcmd);

	sc->cmd = cmd;
	if (!param(cmd, buffer, params,
		   p_opt_def("msec", json_tok_number, &sc->msec, 1000),
		   NULL))
		return;

	new_reltimer(&cmd->ld->timers, sc, time_from_msec(0), slowcmd_start, sc);
	command_still_pending(cmd);
}

static const struct json_command dev_slowcmd_command = {
	"dev-slowcmd",
	json_slowcmd,
	"Torture test for slow commands, optional {msec}"
};
AUTODATA(json_command, &dev_slowcmd_command);

static void json_crash(struct command *cmd UNUSED,
		       const char *buffer UNUSED, const jsmntok_t *params UNUSED)
{
	if (!param(cmd, buffer, params, NULL))
		return;

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
	cmd->mode = CMD_USAGE;
	json_command->dispatch(cmd, NULL, NULL);
	usage = tal_fmt(cmd, "%s %s", json_command->name, cmd->usage);

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

static void json_help(struct command *cmd,
		      const char *buffer, const jsmntok_t *params)
{
	struct json_stream *response;
	const jsmntok_t *cmdtok;
	struct json_command **commands = cmd->ld->jsonrpc->commands;

	if (!param(cmd, buffer, params,
		   p_opt("command", json_tok_tok, &cmdtok),
		   NULL))
		return;

	if (cmdtok) {
		for (size_t i = 0; i < tal_count(commands); i++) {
			if (json_tok_streq(buffer, cmdtok, commands[i]->name)) {
				response = json_stream_success(cmd);
				json_add_help_command(cmd, response, commands[i]);
				goto done;
			}
		}
		command_fail(cmd, JSONRPC2_METHOD_NOT_FOUND,
			     "Unknown command '%.*s'",
			     cmdtok->end - cmdtok->start,
			     buffer + cmdtok->start);
		return;
	}

	response = json_stream_success(cmd);
	json_object_start(response, NULL);
	json_array_start(response, "help");
	for (size_t i=0; i<tal_count(commands); i++) {
		json_add_help_command(cmd, response, commands[i]);
	}
	json_array_end(response);
	json_object_end(response);

done:
	command_success(cmd, response);
}

static const struct json_command *find_cmd(const struct jsonrpc *rpc,
					   const char *buffer,
					   const jsmntok_t *tok)
{
	struct json_command **commands = rpc->commands;

	/* commands[i] can be NULL if the plugin that registered it
	 * was killed, commands[i]->name can be NULL in test code. */
	for (size_t i = 0; i < tal_count(commands); i++)
		if (commands[i] && commands[i]->name &&
		    json_tok_streq(buffer, tok, commands[i]->name))
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

void command_success(struct command *cmd, struct json_stream *result)
{
	assert(cmd);
	assert(cmd->have_json_stream);
	json_stream_append(result, " }\n\n");
	json_stream_close(result, cmd);
	if (cmd->ok)
		*(cmd->ok) = true;

	/* If we have a jcon, it will free result for us. */
	if (cmd->jcon)
		tal_steal(cmd->jcon, result);

	tal_free(cmd);
}

void command_failed(struct command *cmd, struct json_stream *result)
{
	assert(cmd->have_json_stream);
	/* Have to close error */
	json_stream_append(result, " } }\n\n");
	json_stream_close(result, cmd);
	if (cmd->ok)
		*(cmd->ok) = false;
	/* If we have a jcon, it will free result for us. */
	if (cmd->jcon)
		tal_steal(cmd->jcon, result);

	tal_free(cmd);
}

void PRINTF_FMT(3, 4) command_fail(struct command *cmd, int code,
				   const char *fmt, ...)
{
	const char *errmsg;
	struct json_stream *r;
	va_list ap;

	va_start(ap, fmt);
	errmsg = tal_vfmt(cmd, fmt, ap);
	va_end(ap);
	r = json_stream_fail_nodata(cmd, code, errmsg);

	command_failed(cmd, r);
}

void command_still_pending(struct command *cmd)
{
	notleak_with_children(cmd);
	notleak(cmd->jcon);
	cmd->pending = true;
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

static struct json_stream *attach_json_stream(struct command *cmd)
{
	struct json_stream *js;

	/* If they still care about the result, attach it to them. */
	if (cmd->jcon)
		js = jcon_new_json_stream(cmd, cmd->jcon, cmd);
	else
		js = new_json_stream(cmd, cmd);

	assert(!cmd->have_json_stream);
	cmd->have_json_stream = true;
	return js;
}

static struct json_stream *json_start(struct command *cmd)
{
	struct json_stream *js = attach_json_stream(cmd);

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

	assert(code);
	assert(errmsg);

	json_stream_append_fmt(r, " \"error\" : "
			  "{ \"code\" : %d,"
			  " \"message\" : \"%s\"", code, errmsg);
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

static void parse_request(struct json_connection *jcon, const jsmntok_t tok[])
{
	const jsmntok_t *method, *id, *params;
	struct command *c;

	if (tok[0].type != JSMN_OBJECT) {
		json_command_malformed(jcon, "null",
				       "Expected {} for json command");
		return;
	}

	method = json_get_member(jcon->buffer, tok, "method");
	params = json_get_member(jcon->buffer, tok, "params");
	id = json_get_member(jcon->buffer, tok, "id");

	if (!id) {
		json_command_malformed(jcon, "null", "No id");
		return;
	}
	if (id->type != JSMN_STRING && id->type != JSMN_PRIMITIVE) {
		json_command_malformed(jcon, "null",
				       "Expected string/primitive for id");
		return;
	}

	/* Allocate the command off of the `jsonrpc` object and not
	 * the connection since the command may outlive `conn`. */
	c = tal(jcon->ld->jsonrpc, struct command);
	c->jcon = jcon;
	c->ld = jcon->ld;
	c->pending = false;
	c->have_json_stream = false;
	c->id = tal_strndup(c,
			    json_tok_contents(jcon->buffer, id),
			    json_tok_len(id));
	c->mode = CMD_NORMAL;
	c->ok = NULL;
	list_add_tail(&jcon->commands, &c->list);
	tal_add_destructor(c, destroy_command);

	if (!method || !params) {
		command_fail(c, JSONRPC2_INVALID_REQUEST,
			     method ? "No params" : "No method");
		return;
	}

	if (method->type != JSMN_STRING) {
		command_fail(c, JSONRPC2_INVALID_REQUEST,
			     "Expected string for method");
		return;
	}

        c->json_cmd = find_cmd(jcon->ld->jsonrpc, jcon->buffer, method);
        if (!c->json_cmd) {
		command_fail(c, JSONRPC2_METHOD_NOT_FOUND,
			     "Unknown command '%.*s'",
			     method->end - method->start,
			     jcon->buffer + method->start);
		return;
	}
	if (c->json_cmd->deprecated && !deprecated_apis) {
		command_fail(c, JSONRPC2_METHOD_NOT_FOUND,
			     "Command '%.*s' is deprecated",
			      method->end - method->start,
			      jcon->buffer + method->start);
		return;
	}

	db_begin_transaction(jcon->ld->wallet->db);
	c->json_cmd->dispatch(c, jcon->buffer, params);
	db_commit_transaction(jcon->ld->wallet->db);

	/* If they didn't complete it, they must call command_still_pending.
	 * If they completed it, it's freed already. */
	list_for_each(&jcon->commands, c, list)
		assert(c->pending);
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

	toks = json_parse_input(jcon->buffer, jcon->used, &valid);
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

	jcon = tal(conn, struct json_connection);
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

bool jsonrpc_command_add(struct jsonrpc *rpc, struct json_command *command)
{
	size_t count = tal_count(rpc->commands);

	/* Check that we don't clobber a method */
	for (size_t i = 0; i < count; i++)
		if (rpc->commands[i] != NULL &&
		    streq(rpc->commands[i]->name, command->name))
			return false;

	*tal_arr_expand(&rpc->commands) = command;
	return true;
}

void jsonrpc_command_remove(struct jsonrpc *rpc, const char *method)
{
	// FIXME: Currently leaves NULL entries in the table, if we
	// restart plugins we should shift them out.
	for (size_t i=0; i<tal_count(rpc->commands); i++) {
		struct json_command *cmd = rpc->commands[i];
		if (cmd && streq(cmd->name, method)) {
			rpc->commands[i] = tal_free(cmd);
		}
	}
}

struct jsonrpc *jsonrpc_new(const tal_t *ctx, struct lightningd *ld)
{
	struct jsonrpc *jsonrpc = tal(ctx, struct jsonrpc);
	struct json_command **commands = get_cmdlist();

	jsonrpc->commands = tal_arr(jsonrpc, struct json_command *, 0);
	jsonrpc->log = new_log(jsonrpc, ld->log_book, "jsonrpc");
	for (size_t i=0; i<num_cmdlist; i++) {
		jsonrpc_command_add(jsonrpc, commands[i]);
	}
	jsonrpc->rpc_listener = NULL;
	return jsonrpc;
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
	struct bitcoin_address p2pkh_destination;
	struct ripemd160 p2sh_destination;
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
	bool testnet;

	parsed = false;
	if (bitcoin_from_base58(&testnet, &p2pkh_destination,
				buffer + tok->start, tok->end - tok->start)) {
		*scriptpubkey = scriptpubkey_p2pkh(cxt, &p2pkh_destination);
		parsed = true;
		right_network = (testnet == chainparams->testnet);
	} else if (p2sh_from_base58(&testnet, &p2sh_destination,
				    buffer + tok->start, tok->end - tok->start)) {
		*scriptpubkey = scriptpubkey_p2sh_hash(cxt, &p2sh_destination);
		parsed = true;
		right_network = (testnet == chainparams->testnet);
	}
	/* Insert other parsers that accept pointer+len here. */

	if (parsed) {
		if (right_network)
			return ADDRESS_PARSE_SUCCESS;
		else
			return ADDRESS_PARSE_WRONG_NETWORK;
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

bool json_tok_wtx(struct wallet_tx * tx, const char * buffer,
                  const jsmntok_t *sattok, u64 max)
{
        if (json_tok_streq(buffer, sattok, "all")) {
                tx->all_funds = true;
		tx->amount = max;
        } else if (!json_to_u64(buffer, sattok, &tx->amount)) {
                command_fail(tx->cmd, JSONRPC2_INVALID_PARAMS,
			     "Invalid satoshis");
                return false;
	} else if (tx->amount > max) {
                command_fail(tx->cmd, FUND_MAX_EXCEEDED,
			     "Amount exceeded %"PRIu64, max);
                return false;
	}
        return true;
}
