/* This plugin provides RPC access to the reckless standalone utility.
 */

#include "config.h"
#include <ccan/array_size/array_size.h>
#include <ccan/io/io.h>
#include <ccan/pipecmd/pipecmd.h>
#include <ccan/str/str.h>
#include <ccan/tal/str/str.h>
#include <common/json_param.h>
#include <common/json_parse_simple.h>
#include <common/json_stream.h>
#include <common/memleak.h>
#include <errno.h>
#include <plugins/libplugin.h>
#include <signal.h>

static struct plugin *plugin;

struct reckless {
	struct command *cmd;
	int stdinfd;
	int stdoutfd;
	int stderrfd;
	char *stdoutbuf;
	char *stderrbuf;
	size_t stdout_read;	/* running total */
	size_t stdout_new;	/* new since last read */
	size_t stderr_read;
	size_t stderr_new;
	pid_t pid;
	char *process_failed;
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
	if (rkls->stdout_read == tal_count(rkls->stdoutbuf))
		tal_resize(&rkls->stdoutbuf, rkls->stdout_read * 2);
	return io_read_partial(conn, rkls->stdoutbuf + rkls->stdout_read,
			       tal_count(rkls->stdoutbuf) - rkls->stdout_read,
			       &rkls->stdout_new, read_more, rkls);
}

static struct command_result *reckless_result(struct io_conn *conn,
					      struct reckless *reckless)
{
	struct json_stream *response;
	if (reckless->process_failed) {
		response = jsonrpc_stream_fail(reckless->cmd,
					       PLUGIN_ERROR,
					       reckless->process_failed);
		return command_finished(reckless->cmd, response);
	}
	const jsmntok_t *results, *result, *logs, *log;
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
			      "output");
	else if (res == JSMN_ERROR_PART)
		err = tal_fmt(tmpctx, "reckless returned partial output");
	else if (res == JSMN_ERROR_NOMEM )
		err = tal_fmt(tmpctx, "insufficient tokens to parse "
			      "reckless output.");
	else
		err = NULL;

	if (err) {
		plugin_log(plugin, LOG_UNUSUAL, "failed to parse json: %s", err);
		response = jsonrpc_stream_fail(reckless->cmd, PLUGIN_ERROR,
					       err);
		return command_finished(reckless->cmd, response);
	}

	response = jsonrpc_stream_success(reckless->cmd);
	json_array_start(response, "result");
	results = json_get_member(reckless->stdoutbuf, toks, "result");
	json_for_each_arr(i, result, results) {
		json_add_string(response,
				NULL,
				json_strdup(reckless, reckless->stdoutbuf,
					    result));
	}
	json_array_end(response);
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

static void reckless_conn_finish(struct io_conn *conn,
				 struct reckless *reckless)
{
	/* FIXME: avoid EBADFD - leave stdin fd open? */
	if (errno && errno != 9)
		plugin_log(plugin, LOG_DBG, "err: %s", strerror(errno));
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
				   "Reckless subprocess complete: %s",
				   reckless->stdoutbuf);
			reckless_result(conn, reckless);
		/* Don't try to process json if python raised an error. */
		} else {
			plugin_log(plugin, LOG_DBG,
				   "Reckless process has crashed (%i).",
				   WEXITSTATUS(status));
			char * err;
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
	io_close(conn);
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
	if (rkls->stderr_read == tal_count(rkls->stderrbuf))
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

static struct command_result *reckless_call(struct command *cmd,
					    const char *subcommand,
					    const char *target,
					    const char *target2)
{
	if (!subcommand || !target)
		return command_fail(cmd, PLUGIN_ERROR, "invalid reckless call");
	char **my_call;
	my_call = tal_arrz(tmpctx, char *, 0);
	tal_arr_expand(&my_call, "reckless");
	tal_arr_expand(&my_call, "-v");
	tal_arr_expand(&my_call, "--json");
	tal_arr_expand(&my_call, "-l");
	tal_arr_expand(&my_call, lconfig.lightningdir);
	tal_arr_expand(&my_call, "--network");
	tal_arr_expand(&my_call, lconfig.network);
	if (lconfig.config) {
		tal_arr_expand(&my_call, "--conf");
		tal_arr_expand(&my_call, lconfig.config);
	}
	tal_arr_expand(&my_call, (char *) subcommand);
	tal_arr_expand(&my_call, (char *) target);
	if (target2)
		tal_arr_expand(&my_call, (char *) target2);
	tal_arr_expand(&my_call, NULL);
	struct reckless *reckless;
	reckless = tal(NULL, struct reckless);
	reckless->cmd = cmd;
	reckless->stdoutbuf = tal_arrz(reckless, char, 1024);
	reckless->stderrbuf = tal_arrz(reckless, char, 1024);
	reckless->stdout_read = 0;
	reckless->stdout_new = 0;
	reckless->stderr_read = 0;
	reckless->stderr_new = 0;
	reckless->process_failed = NULL;
	char * full_cmd;
	full_cmd = tal_fmt(tmpctx, "calling:");
	for (int i=0; i<tal_count(my_call); i++)
		tal_append_fmt(&full_cmd, " %s", my_call[i]);
	plugin_log(plugin, LOG_DBG, "%s", full_cmd);
	tal_free(full_cmd);

	reckless->pid = pipecmdarr(&reckless->stdinfd, &reckless->stdoutfd,
				   &reckless->stderrfd, my_call);

	/* FIXME: fail if invalid pid*/
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
		   p_req("target/subcommand", param_string, &target),
		   p_opt("target", param_string, &target2),
		   NULL))
		return command_param_failed();
	return reckless_call(cmd, command, target, target2);
}

static const char *init(struct plugin *p,
			const char *buf UNUSED,
			const jsmntok_t *config UNUSED)
{
	plugin = p;
	rpc_scan(p, "listconfigs",
		 take(json_out_obj(NULL, NULL, NULL)),
		 "{configs:{"
		 "conf?:{value_str:%},"
		 "lightning-dir:{value_str:%},"
		 "network:{value_str:%}"
		 "}}",
		 JSON_SCAN_TAL(p, json_strdup, &lconfig.config),
		 JSON_SCAN_TAL(p, json_strdup, &lconfig.lightningdir),
		 JSON_SCAN_TAL(p, json_strdup, &lconfig.network));
	/* These lightning config parameters need to stick around for each
	 * reckless call. */
	if (lconfig.config)
		notleak(lconfig.config);
	notleak(lconfig.lightningdir);
	notleak(lconfig.network);
	plugin_log(p, LOG_DBG, "plugin initialized!");
	plugin_log(p, LOG_DBG, "lightning-dir: %s", lconfig.lightningdir);
	return NULL;
}

static const struct plugin_command commands[] = {
	{
		"reckless",
		json_reckless,
	},
};

int main(int argc, char **argv)
{
	setup_locale();

	plugin_main(argv, init, NULL, PLUGIN_RESTARTABLE, true,
		    NULL,
		    commands, ARRAY_SIZE(commands),
		    NULL, 0,	/* Notifications */
		    NULL, 0,	/* Hooks */
		    NULL, 0,	/* Notification topics */
		    NULL);	/* plugin options */

	return 0;
}

