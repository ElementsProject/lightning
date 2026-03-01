/* This plugin provides RPC access to the reckless standalone utility.
 */

#include "config.h"
#include <arpa/inet.h>
#include <ccan/array_size/array_size.h>
#include <ccan/io/io.h>
#include <ccan/membuf/membuf.h>
#include <ccan/pipecmd/pipecmd.h>
#include <ccan/tal/str/str.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <common/memleak.h>
#include <errno.h>
#include <netinet/in.h>
#include <plugins/libplugin.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>

static struct plugin *plugin;

struct reckless {
	struct command *cmd;
	int stdinfd;
	int stdoutfd;
	int stderrfd;
	int logfd;
	char *stdoutbuf;
	char *stderrbuf;
	size_t stdout_read;	/* running total */
	size_t stdout_new;	/* new since last read */
	size_t stderr_read;
	size_t stderr_new;
	pid_t pid;
	char *process_failed;

	MEMBUF(char) logbuf;
	/* Amount just read by io_read_partial */
	size_t logbytes_read;
};

struct lconfig {
	char *lightningdir;
	char *config;
	char *network;
} lconfig;

static struct io_plan *reckless_in_init(struct io_conn *conn,
					struct reckless *reckless)
{
	return io_write(conn, "Y", 1, io_close_cb, NULL);
}

static void reckless_send_yes(struct reckless *reckless)
{
	io_new_conn(reckless, reckless->stdinfd, reckless_in_init, reckless);
}

static struct io_plan *read_more(struct io_conn *conn, struct reckless *rkls)
{
	rkls->stdout_read += rkls->stdout_new;
	while (rkls->stdout_read >= tal_count(rkls->stdoutbuf))
		tal_resizez(&rkls->stdoutbuf, tal_count(rkls->stdoutbuf) * 2);
	return io_read_partial(conn, rkls->stdoutbuf + rkls->stdout_read,
			       tal_count(rkls->stdoutbuf) - rkls->stdout_read,
			       &rkls->stdout_new, read_more, rkls);
}

static void dup_listavailable_result(struct reckless *reckless,
				     struct json_stream *response,
				     char *reckless_result,
				     const jsmntok_t *results_tok)
{
	json_array_start(response, "result");
	size_t plugins, requirements;
	const jsmntok_t *result, *requirement, *requirements_tok;
	const char *plugin_name, *short_description, *long_description, *entrypoint;

	json_for_each_arr(plugins, result, results_tok) {
		json_object_start(response, NULL);

		json_scan(tmpctx, reckless_result, result,
			  "{name:%,"
			  "short_description:%,"
			  "long_description:%,"
			  "entrypoint:%}",
			  JSON_SCAN_TAL(tmpctx, json_strdup, &plugin_name),
			  JSON_SCAN_TAL(tmpctx, json_strdup, &short_description),
			  JSON_SCAN_TAL(tmpctx, json_strdup, &long_description),
			  JSON_SCAN_TAL(tmpctx, json_strdup, &entrypoint));

		json_add_string(response, "name", plugin_name);
		if (!streq(short_description, "null"))
			json_add_string(response, "short_description", short_description);
		if (!streq(long_description, "null"))
			json_add_string(response, "long_description", long_description);
		json_add_string(response, "entypoint", entrypoint);

		json_array_start(response, "requirements");
		requirements_tok = json_get_member(reckless_result, result, "requirements");
		if (requirements_tok) {
			json_for_each_arr(requirements, requirement, requirements_tok) {
				json_add_string(response, NULL,
						json_strdup(tmpctx, reckless_result, requirement));
			}
		}
		json_array_end(response);

		json_object_end(response);
	}
	json_array_end(response);
}

static struct command_result *reckless_result(struct reckless *reckless)
{
	struct json_stream *response;
	if (reckless->process_failed) {
		response = jsonrpc_stream_fail(reckless->cmd,
					       PLUGIN_ERROR,
					       reckless->process_failed);
		return command_finished(reckless->cmd, response);
	}

	/* The reckless utility outputs utf-8 and ends the transmission with
	 * \u0004, which jsmn is unable to parse. */
	const jsmntok_t *results, *result, *logs, *log, *conf, *next;
	size_t i;
	jsmn_parser parser;
	jsmntok_t *toks;
	toks = tal_arr(reckless, jsmntok_t, 5000);
	jsmn_init(&parser);
	int res;
	res = jsmn_parse(&parser, reckless->stdoutbuf,
			 strlen(reckless->stdoutbuf), toks, tal_count(toks));
	const char *err;
	if (res == JSMN_ERROR_INVAL)
		err = tal_fmt(tmpctx, "reckless returned invalid character in json "
			      "output. (total length %lu)", strlen(reckless->stdoutbuf));
	else if (res == JSMN_ERROR_PART)
		err = tal_fmt(tmpctx, "reckless returned partial output");
	else if (res == JSMN_ERROR_NOMEM )
		err = tal_fmt(tmpctx, "insufficient tokens to parse "
			      "reckless output.");
	else
		err = NULL;

	if (err) {
		if (res == JSMN_ERROR_INVAL)
			plugin_log(plugin, LOG_BROKEN, "invalid char in json");
		response = jsonrpc_stream_fail(reckless->cmd, PLUGIN_ERROR,
					       err);
		return command_finished(reckless->cmd, response);
	}

	response = jsonrpc_stream_success(reckless->cmd);
	results = json_get_member(reckless->stdoutbuf, toks, "result");
	next = json_get_arr(results, 0);
	conf = json_get_member(reckless->stdoutbuf, results, "requested_lightning_conf");
	if (conf) {
		plugin_log(plugin, LOG_DBG, "ingesting listconfigs output");
		json_object_start(response, "result");
		json_for_each_obj(i, result, results) {
			json_add_tok(response, json_strdup(tmpctx, reckless->stdoutbuf, result), result+1, reckless->stdoutbuf);
		}
		json_object_end(response);

	} else if (next && next->type == JSMN_OBJECT) {
		plugin_log(plugin, LOG_DBG, "ingesting listavailable output");
		dup_listavailable_result(reckless, response, reckless->stdoutbuf, results);

	} else {
		json_array_start(response, "result");
		json_for_each_arr(i, result, results) {
			json_add_string(response,
					NULL,
					json_strdup(reckless, reckless->stdoutbuf,
						    result));
		}
		json_array_end(response);
	}
	json_array_start(response, "log");
	logs = json_get_member(reckless->stdoutbuf, toks, "log");
	json_for_each_arr(i, log, logs) {
		json_add_string(response,
				NULL,
				json_strdup(reckless, reckless->stdoutbuf,
					    log));
	}
	json_array_end(response);

	return command_finished(reckless->cmd, response);
}

static struct command_result *reckless_fail(struct reckless *reckless,
					    char *err)
{
	struct json_stream *resp;
	resp = jsonrpc_stream_fail(reckless->cmd, PLUGIN_ERROR, err);
	return command_finished(reckless->cmd, resp);
}

/* Regurgitates the syntax error reported by the utility */
static struct command_result *fail_bad_usage(struct reckless *reckless)
{
	char **lines;
	lines = tal_strsplit(reckless, reckless->stderrbuf, "\n", STR_EMPTY_OK);
	if (lines != NULL)
	{
		/* The last line of reckless output contains the usage error.
		 * Capture it for the user. */
		int i = 0;
		while (lines[i + 1] != NULL)
			i++;
		return reckless_fail(reckless, lines[i]);
	}
	return reckless_fail(reckless, "the reckless process has crashed");
}

static void reckless_conn_finish(struct io_conn *conn,
				 struct reckless *reckless)
{
	io_close(conn);
	/* FIXME: avoid EBADFD - leave stdin fd open? */
	if (errno && errno != 9)
		plugin_log(plugin, LOG_DBG, "err: %s", strerror(errno));
	struct pollfd pfd = { .fd = reckless->logfd, .events = POLLIN };
	poll(&pfd, 1, 20); // wait for any remaining log data

	/* Close the log streaming socket. */
	if (reckless->logfd) {
		if (close(reckless->logfd) != 0)
			plugin_log(plugin, LOG_DBG, "closing log socket failed: %s", strerror(errno));
		reckless->logfd = 0;
	}

	if (reckless->pid > 0) {
		int status = 0;
		pid_t p;
		p = waitpid(reckless->pid, &status, WNOHANG);
		/* Did the reckless process exit? */
		if (p != reckless->pid && reckless->pid) {
			plugin_log(plugin, LOG_DBG, "reckless failed to exit, "
				   "killing now.");
			kill(reckless->pid, SIGKILL);
			reckless_fail(reckless, "reckless process hung");
		/* Reckless process exited and with normal status? */
		} else if (WIFEXITED(status) && !WEXITSTATUS(status)) {
			plugin_log(plugin, LOG_DBG,
				   "Reckless subprocess complete");
			reckless_result(reckless);
		/* Don't try to process json if python raised an error. */
		} else {
			plugin_log(plugin, LOG_DBG, "%s", reckless->stderrbuf);
			plugin_log(plugin, LOG_DBG,
				   "Reckless process has crashed (%i).",
				   WEXITSTATUS(status));
			char * err;
			if (WEXITSTATUS(status) == 2)
				fail_bad_usage(reckless);
			else {
				if (reckless->process_failed)
					err = reckless->process_failed;
				else
					err = tal_strdup(tmpctx, "the reckless process "
							 "has crashed");
				reckless_fail(reckless, err);
				plugin_log(plugin, LOG_UNUSUAL,
					   "The reckless subprocess has failed.");
			}
		}
	}
	tal_free(reckless);
}

static struct io_plan *conn_init(struct io_conn *conn, struct reckless *rkls)
{
	io_set_finish(conn, reckless_conn_finish, rkls);
	return read_more(conn, rkls);
}

static void stderr_conn_finish(struct io_conn *conn, void *reckless UNUSED)
{
       io_close(conn);
}

static struct io_plan *stderr_read_more(struct io_conn *conn,
                                       struct reckless *rkls)
{
	rkls->stderr_read += rkls->stderr_new;
	if (rkls->stderr_read * 2 > tal_count(rkls->stderrbuf))
		tal_resize(&rkls->stderrbuf, rkls->stderr_read * 2);
	if (strends(rkls->stderrbuf, "[Y] to create one now.\n")) {
		plugin_log(plugin, LOG_DBG, "confirming config creation");
		reckless_send_yes(rkls);
	}
	/* Old version of reckless installed? */
	if (strstr(rkls->stderrbuf, "error: unrecognized arguments: --json")) {
		plugin_log(plugin, LOG_DBG, "Reckless call failed due to old "
			   "installed version.");
		rkls->process_failed = tal_strdup(plugin, "The installed "
						  "reckless utility is out of "
						  "date. Please update to use "
						  "the RPC plugin.");
	}
	return io_read_partial(conn, rkls->stderrbuf + rkls->stderr_read,
			       tal_count(rkls->stderrbuf) - rkls->stderr_read,
			       &rkls->stderr_new, stderr_read_more, rkls);
}

static struct io_plan *stderr_conn_init(struct io_conn *conn,
					struct reckless *reckless)
{
	io_set_finish(conn, stderr_conn_finish, NULL);
	return stderr_read_more(conn, reckless);
}

static bool is_single_arg_cmd(const char *command) {
	if (strcmp(command, "listconfig"))
		return true;
	if (strcmp(command, "listavailable"))
		return true;
	if (strcmp(command, "listinstalled"))
		return true;
	return false;
}

static void log_notify(const char *log_line, size_t len)
{
	struct json_stream *js = plugin_notification_start(NULL, "reckless_log");
	json_add_stringn(js, "log", log_line, len);
	plugin_notification_end(plugin, js);
}

static void log_conn_finish(struct io_conn *conn, struct reckless *reckless)
{
	io_close(conn);
	reckless->logfd = 0;

}

/* len does NOT include the \n */
static const char *get_line(const struct reckless *rkls, size_t *len)
{
	const char *line = membuf_elems(&rkls->logbuf);
	const char *eol = memchr(line, '\n', membuf_num_elems(&rkls->logbuf));

	if (eol) {
		*len = eol - line;
		return line;
	}
	return NULL;
}

static struct io_plan *log_read_more(struct io_conn *conn,
				     struct reckless *rkls)
{
	size_t len;
	const char *line;

	/* We read some more stuff in! */
	membuf_added(&rkls->logbuf, rkls->logbytes_read);
	rkls->logbytes_read = 0;

	while ((line = get_line(rkls, &len)) != NULL) {
		plugin_log(plugin, LOG_DBG, "reckless utility: %.*s", (int)len, line);
		log_notify(line, len);
		membuf_consume(&rkls->logbuf, len + 1);
	}

	/* Make sure there's more room */
	membuf_prepare_space(&rkls->logbuf, 4096);

	return io_read_partial(conn,
			       membuf_space(&rkls->logbuf),
			       membuf_num_space(&rkls->logbuf),
			       &rkls->logbytes_read,
			       log_read_more, rkls);
}

static struct io_plan *log_conn_init(struct io_conn *conn, struct reckless *rkls)
{
	io_set_finish(conn, log_conn_finish, rkls);
	return log_read_more(conn, rkls);
}

static int open_socket(int *port)
{
	int sock;
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		plugin_log(plugin, LOG_UNUSUAL, "could not open socket for "
			   "streaming logs");
		return -1;
	}
	struct sockaddr_in ai;
	ai.sin_family = AF_INET;
	ai.sin_port = htons(0);
	inet_pton(AF_INET, "127.0.0.1", &ai.sin_addr);

	if (bind(sock, (struct sockaddr *)&ai, sizeof(ai)) < 0) {
		plugin_log(plugin, LOG_UNUSUAL, "failed to bind socket: %s", strerror(errno));
		close(sock);
		return -1;
	}

	socklen_t len = sizeof(ai);
	if (getsockname(sock, (struct sockaddr *)&ai, &len) < 0) {
		plugin_log(plugin, LOG_DBG, "couldn't retrieve socket port");
		return -1;
	}
	*port = ntohs(ai.sin_port);

	if (listen(sock, 64) != 0) {
		plugin_log(plugin, LOG_UNUSUAL, "failed to listen on socket: %s", strerror(errno));
		close(sock);
		return -1;
	}

	return sock;
}

static struct command_result *reckless_call(struct command *cmd,
					    const char *subcommand,
					    const char *target,
					    const char *target2)
{
	if (!is_single_arg_cmd(subcommand)) {
		if (!subcommand || !target)
			return command_fail(cmd, PLUGIN_ERROR, "invalid reckless call");
	}
	int sock;
	int *port = tal(tmpctx, int);
	sock = open_socket(port);
	if (sock < 0)
		plugin_log(plugin, LOG_BROKEN, "not streaming logs "
			   "from reckless utility");

	char **my_call;
	my_call = tal_arrz(tmpctx, char *, 0);
	tal_arr_expand(&my_call, "reckless");
	tal_arr_expand(&my_call, "-v");
	tal_arr_expand(&my_call, "--json");
	tal_arr_expand(&my_call, "-l");
	tal_arr_expand(&my_call, lconfig.lightningdir);
	tal_arr_expand(&my_call, "--network");
	tal_arr_expand(&my_call, lconfig.network);
	if (sock > 0) {
		tal_arr_expand(&my_call, "--logging-port");
		tal_arr_expand(&my_call, tal_fmt(tmpctx, "%i", *port));
	}

	if (lconfig.config) {
		tal_arr_expand(&my_call, "--conf");
		tal_arr_expand(&my_call, lconfig.config);
	}
	tal_arr_expand(&my_call, (char *) subcommand);
	if (target)
		tal_arr_expand(&my_call, (char *) target);
	if (target2)
		tal_arr_expand(&my_call, (char *) target2);
	tal_arr_expand(&my_call, NULL);
	struct reckless *reckless;
	reckless = tal(NULL, struct reckless);
	reckless->cmd = cmd;
	reckless->stdoutbuf = tal_arrz(reckless, char, 4096);
	reckless->stderrbuf = tal_arrz(reckless, char, 4096);
	reckless->stdout_read = 0;
	reckless->stdout_new = 0;
	reckless->stderr_read = 0;
	reckless->stderr_new = 0;
	reckless->process_failed = NULL;
	reckless->logfd = sock;
	membuf_init(&reckless->logbuf,
		    tal_arr(reckless, char, 10),
		    10, membuf_tal_resize);
	reckless->logbytes_read = 0;

	char * full_cmd;
	full_cmd = tal_fmt(tmpctx, "calling:");
	for (int i=0; i<tal_count(my_call); i++)
		tal_append_fmt(&full_cmd, " %s", my_call[i]);
	plugin_log(plugin, LOG_DBG, "%s", full_cmd);
	tal_free(full_cmd);

	reckless->pid = pipecmdarr(&reckless->stdinfd, &reckless->stdoutfd,
				   &reckless->stderrfd, my_call);

	if (reckless->pid < 0) {
		return command_fail(cmd, LIGHTNINGD, "reckless failed: %s",
				    strerror(errno));
	}

	if (sock > 0)
		io_new_listener(reckless, reckless->logfd,
				log_conn_init, reckless);
	io_new_conn(reckless, reckless->stdoutfd, conn_init, reckless);
	io_new_conn(reckless, reckless->stderrfd, stderr_conn_init, reckless);

	tal_free(my_call);
	return command_still_pending(cmd);
}

static struct command_result *json_reckless(struct command *cmd,
					    const char *buf,
					    const jsmntok_t *params)
{
	const char *command;
	const char *target;
	const char *target2;
	/* Allow check command to evaluate. */
	if (!param(cmd, buf, params,
		   p_req("command", param_string, &command),
		   p_opt("target/subcommand", param_string, &target),
		   p_opt("target", param_string, &target2),
		   NULL))
		return command_param_failed();
	return reckless_call(cmd, command, target, target2);
}

static const char *init(struct command *init_cmd,
			const char *buf UNUSED,
			const jsmntok_t *config UNUSED)
{
	plugin = init_cmd->plugin;
	rpc_scan(init_cmd, "listconfigs",
		 take(json_out_obj(NULL, NULL, NULL)),
		 "{configs:{"
		 "conf?:{value_str:%},"
		 "lightning-dir:{value_str:%},"
		 "network:{value_str:%}"
		 "}}",
		 JSON_SCAN_TAL(plugin, json_strdup, &lconfig.config),
		 JSON_SCAN_TAL(plugin, json_strdup, &lconfig.lightningdir),
		 JSON_SCAN_TAL(plugin, json_strdup, &lconfig.network));
	/* These lightning config parameters need to stick around for each
	 * reckless call. */
	if (lconfig.config)
		notleak(lconfig.config);
	notleak(lconfig.lightningdir);
	notleak(lconfig.network);
	plugin_log(plugin, LOG_DBG, "plugin initialized!");
	plugin_log(plugin, LOG_DBG, "lightning-dir: %s", lconfig.lightningdir);
	return NULL;
}

static const struct plugin_command commands[] = {
	{
		"reckless",
		json_reckless,
	},
};

static const char *notifications[] = {
	"reckless_log",
};

int main(int argc, char **argv)
{
	setup_locale();

	plugin_main(argv, init, NULL, PLUGIN_RESTARTABLE, true,
		    NULL,
		    commands, ARRAY_SIZE(commands),
		    NULL, 0,	/* Notifications */
		    NULL, 0,	/* Hooks */
		    notifications, ARRAY_SIZE(notifications),	/* Notification topics */
		    NULL);	/* plugin options */

	return 0;
}

