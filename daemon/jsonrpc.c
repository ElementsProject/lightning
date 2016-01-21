/* Code for JSON_RPC API */
/* eg: { "method" : "dev-echo", "params" : [ "hello", "Arabella!" ], "id" : "1" } */
#include "json.h"
#include "jsonrpc.h"
#include "lightningd.h"
#include "log.h"
#include <ccan/array_size/array_size.h>
#include <ccan/err/err.h>
#include <ccan/io/io.h>
#include <ccan/tal/str/str.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>

struct json_output {
	struct list_node list;
	const char *json;
};

static void finish_jcon(struct io_conn *conn, struct json_connection *jcon)
{
	log_info(jcon->log, "Closing (%s)", strerror(errno));
}

static char *json_help(struct json_connection *jcon,
		       const jsmntok_t *params,
		       struct json_result *response);

static const struct json_command help_command = {
	"help",
	json_help,
	"describe commands",
	"[<command>] if specified gives details about a single command."
};

static char *json_echo(struct json_connection *jcon,
		       const jsmntok_t *params,
		       struct json_result *response)
{
	json_object_start(response, NULL);
	json_add_num(response, "num", params->size);
	json_add_literal(response, "echo",
			 json_tok_contents(jcon->buffer, params),
			 json_tok_len(params));
	json_object_end(response);
	return NULL;
}

static const struct json_command echo_command = {
	"dev-echo",
	json_echo,
	"echo parameters",
	"Simple echo test for developers"
};

static char *json_stop(struct json_connection *jcon,
		       const jsmntok_t *params,
		       struct json_result *response)
{
	jcon->stop = true;
	json_add_string(response, NULL, "Shutting down");
	return NULL;
}

static const struct json_command stop_command = {
	"stop",
	json_stop,
	"Shutdown the lightningd process",
	"What part of shutdown wasn't clear?"
};

struct log_info {
	enum log_level level;
	struct json_result *response;
	unsigned int num_skipped;
};

static void add_skipped(struct log_info *info)
{
	if (info->num_skipped) {
		json_array_start(info->response, NULL);
		json_add_string(info->response, "type", "SKIPPED");
		json_add_num(info->response, "num_skipped", info->num_skipped);
		json_array_end(info->response);
		info->num_skipped = 0;
	}
}

static void json_add_time(struct json_result *result, const char *fieldname,
			  struct timespec ts)
{
	char timebuf[100];

	sprintf(timebuf, "%lu.%09u",
		(unsigned long)ts.tv_sec,
		(unsigned)ts.tv_nsec);
	json_add_string(result, fieldname, timebuf);
}

static void log_to_json(unsigned int skipped,
			struct timerel diff,
			enum log_level level,
			const char *prefix,
			const char *log,
			struct log_info *info)
{
	info->num_skipped += skipped;

	if (level < info->level) {
		info->num_skipped++;
		return;
	}

	add_skipped(info);

	json_array_start(info->response, NULL);
	json_add_string(info->response, "type",
			level == LOG_BROKEN ? "BROKEN"
			: level == LOG_UNUSUAL ? "UNUSUAL"
			: level == LOG_INFORM ? "INFO"
			: level == LOG_DBG ? "DEBUG"
			: level == LOG_IO ? "IO"
			: "UNKNOWN");
	json_add_time(info->response, "time", diff.ts);
	json_add_string(info->response, "source", prefix);
	if (level == LOG_IO) {
		if (log[0])
			json_add_string(info->response, "direction", "IN");
		else
			json_add_string(info->response, "direction", "OUT");

		json_add_hex(info->response, "data", log+1, tal_count(log)-1);
	} else
		json_add_string(info->response, "log", log);

	json_array_end(info->response);
}

static char *json_getlog(struct json_connection *jcon,
			 const jsmntok_t *params,
			 struct json_result *response)
{
	struct log_info info;
	struct log_record *lr = jcon->state->log_record;
	jsmntok_t *level;

	json_get_params(jcon->buffer, params, "level", &level, NULL);

	info.response = response;
	info.num_skipped = 0;

	if (!level)
		info.level = LOG_INFORM;
	else if (json_tok_streq(jcon->buffer, level, "io"))
		info.level = LOG_IO;
	else if (json_tok_streq(jcon->buffer, level, "debug"))
		info.level = LOG_DBG;
	else if (json_tok_streq(jcon->buffer, level, "info"))
		info.level = LOG_INFORM;
	else if (json_tok_streq(jcon->buffer, level, "unusual"))
		info.level = LOG_UNUSUAL;
	else
		return "Invalid level param";

	json_object_start(response, NULL);
	json_add_time(response, "creation_time", log_init_time(lr)->ts);
	json_add_num(response, "bytes_used", (unsigned int)log_used(lr));
	json_add_num(response, "bytes_max", (unsigned int)log_max_mem(lr));
	json_object_start(response, "log");
	log_each_line(lr, log_to_json, &info);
	json_object_end(response);
	json_object_end(response);
	return NULL;
}

static const struct json_command getlog_command = {
	"getlog",
	json_getlog,
	"Get logs, with optional level: [io|debug|info|unusual]",
	"Returns log array"
};

static const struct json_command *cmdlist[] = {
	&help_command,
	&stop_command,
	&getlog_command,
	&connect_command,
	/* Developer/debugging options. */
	&echo_command,
};

static char *json_help(struct json_connection *jcon,
		       const jsmntok_t *params,
		       struct json_result *response)
{
	unsigned int i;

	json_array_start(response, NULL);
	for (i = 0; i < ARRAY_SIZE(cmdlist); i++) {
		json_add_object(response,
				"command", JSMN_STRING,
				cmdlist[i]->name,
				"description", JSMN_STRING,
				cmdlist[i]->description,
				NULL);
	}
	json_array_end(response);
	return NULL;
}

static const struct json_command *find_cmd(const char *buffer,
					   const jsmntok_t *tok)
{
	unsigned int i;

	/* cmdlist[i]->name can be NULL in test code. */
	for (i = 0; i < ARRAY_SIZE(cmdlist); i++)
		if (cmdlist[i]->name
		    && json_tok_streq(buffer, tok, cmdlist[i]->name))
			return cmdlist[i];
	return NULL;
}

/* Returns NULL if it's a fatal error. */
static char *parse_request(struct json_connection *jcon, const jsmntok_t tok[])
{
	const jsmntok_t *method, *id, *params;
	const struct json_command *cmd;
	char *error;
	struct json_result *result;

	if (tok[0].type != JSMN_OBJECT) {
		log_unusual(jcon->log, "Expected {} for json command");
		return NULL;
	}

	method = json_get_member(jcon->buffer, tok, "method");
	params = json_get_member(jcon->buffer, tok, "params");
	id = json_get_member(jcon->buffer, tok, "id");

	if (!id || !method || !params) {
		log_unusual(jcon->log, "json: No %s",
			    !id ? "id" : (!method ? "method" : "params"));
		return NULL;
	}

	if (id->type != JSMN_STRING && id->type != JSMN_PRIMITIVE) {
		log_unusual(jcon->log, "Expected string/primitive for id");
		return NULL;
	}

	if (method->type != JSMN_STRING) {
		log_unusual(jcon->log, "Expected string for method");
		return NULL;
	}

	cmd = find_cmd(jcon->buffer, method);
	if (!cmd) {
		return tal_fmt(jcon,
			      "{ \"result\" : null,"
			      " \"error\" : \"Unknown command '%.*s'\","
			      " \"id\" : %.*s }\n",
			      (int)(method->end - method->start),
			      jcon->buffer + method->start,
			      json_tok_len(id),
			      json_tok_contents(jcon->buffer, id));
	}

	if (params->type != JSMN_ARRAY && params->type != JSMN_OBJECT) {
		log_unusual(jcon->log, "Expected array or object for params");
		return NULL;
	}

	result = new_json_result(jcon);
	error = cmd->dispatch(jcon, params, result);
	if (error) {
		char *quote;

		/* Remove " */
		while ((quote = strchr(error, '"')) != NULL)
			*quote = '\'';

		return tal_fmt(jcon,
			      "{ \"result\" : null,"
			      " \"error\" : \"%s\","
			      " \"id\" : %.*s }\n",
			      error,
			      json_tok_len(id),
			      json_tok_contents(jcon->buffer, id));
	}
	return tal_fmt(jcon,
		       "{ \"result\" : %s,"
		       " \"error\" : null,"
		       " \"id\" : %.*s }\n",
		       json_result_string(result),
		       json_tok_len(id),
		       json_tok_contents(jcon->buffer, id));
}

static struct io_plan *write_json(struct io_conn *conn,
				  struct json_connection *jcon)
{
	struct json_output *out;
	
	out = list_pop(&jcon->output, struct json_output, list);
	if (!out) {
		if (jcon->stop) {
			log_unusual(jcon->log, "JSON-RPC shutdown");
			/* Return us to toplevel lightningd.c */
			io_break(jcon->state);
			return io_close(conn);
		}

		/* Reader can go again now. */
		io_wake(jcon);
		return io_out_wait(conn, jcon, write_json, jcon);
	}

	jcon->outbuf = tal_steal(jcon, out->json);
	tal_free(out);

	log_io(jcon->log, false, jcon->outbuf, strlen(jcon->outbuf));
	return io_write(conn,
			jcon->outbuf, strlen(jcon->outbuf), write_json, jcon);
}

static struct io_plan *read_json(struct io_conn *conn,
				 struct json_connection *jcon)
{
	jsmntok_t *toks;
	bool valid;
	struct json_output *out;

	log_io(jcon->log, true, jcon->buffer + jcon->used, jcon->len_read);

	/* Resize larger if we're full. */
	jcon->used += jcon->len_read;
	if (jcon->used == tal_count(jcon->buffer))
		tal_resize(&jcon->buffer, jcon->used * 2);

again:
	toks = json_parse_input(jcon->buffer, jcon->used, &valid);
	if (!toks) {
		if (!valid) {
			log_unusual(jcon->state->base_log,
				    "Invalid token in json input: '%.*s'",
				    (int)jcon->used, jcon->buffer);
			return io_close(conn);
		}
		/* We need more. */
		goto read_more;
	}

	/* Empty buffer? (eg. just whitespace). */
	if (tal_count(toks) == 1) {
		jcon->used = 0;
		goto read_more;
	}

	out = tal(jcon, struct json_output);
	out->json = parse_request(jcon, toks);
	if (!out->json)
		return io_close(conn);

	/* Remove first {}. */
	memmove(jcon->buffer, jcon->buffer + toks[0].end,
		tal_count(jcon->buffer) - toks[0].end);
	jcon->used -= toks[0].end;
	tal_free(toks);

	/* Queue for writing, and wake writer. */
	list_add_tail(&jcon->output, &out->list);
	io_wake(jcon);

	/* See if we can parse the rest. */
	goto again;

read_more:
	tal_free(toks);
	return io_read_partial(conn, jcon->buffer + jcon->used,
			       tal_count(jcon->buffer) - jcon->used,
			       &jcon->len_read, read_json, jcon);
}

static struct io_plan *jcon_connected(struct io_conn *conn,
				      struct lightningd_state *state)
{
	struct json_connection *jcon;

	jcon = tal(state, struct json_connection);
	jcon->state = state;
	jcon->used = 0;
	jcon->len_read = 64;
	jcon->buffer = tal_arr(jcon, char, jcon->len_read);
	jcon->stop = false;
	jcon->log = new_log(jcon, state->log_record, "%sjcon fd %i:",
			    log_prefix(state->base_log), io_conn_fd(conn));
	list_head_init(&jcon->output);

	io_set_finish(conn, finish_jcon, jcon);

	return io_duplex(conn,
			 io_read_partial(conn, jcon->buffer,
					 tal_count(jcon->buffer),
					 &jcon->len_read, read_json, jcon),
			 write_json(conn, jcon));
}

static struct io_plan *incoming_jcon_connected(struct io_conn *conn,
					       struct lightningd_state *state)
{
	log_info(state->base_log, "Connected json input");
	return jcon_connected(conn, state);
}

void setup_jsonrpc(struct lightningd_state *state, const char *rpc_filename)
{
	struct sockaddr_un addr;
	int fd, old_umask;

	if (streq(rpc_filename, ""))
		return;

	if (streq(rpc_filename, "/dev/tty")) {
		fd = open(rpc_filename, O_RDWR);
		if (fd == -1)
			err(1, "Opening %s", rpc_filename);
		io_new_conn(state, fd, jcon_connected, state);
		return;
	}

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
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

	io_new_listener(state, fd, incoming_jcon_connected, state);
}
