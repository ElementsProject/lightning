#include <ccan/err/err.h>
#include <ccan/intmap/intmap.h>
#include <ccan/membuf/membuf.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/strmap/strmap.h>
#include <ccan/tal/str/str.h>
#include <ccan/timer/timer.h>
#include <common/daemon.h>
#include <common/utils.h>
#include <errno.h>
#include <poll.h>
#include <plugins/libplugin.h>
#include <stdarg.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#define READ_CHUNKSIZE 4096

/* Tracking requests */
static UINTMAP(struct out_req *) out_reqs;
static u64 next_outreq_id;

/* Map from json command names to usage strings: we don't put this inside
 * struct json_command as it's good practice to have those const. */
static STRMAP(const char *) usagemap;

/* Timers */
static struct timers timers;
static size_t in_timer;

bool deprecated_apis;

struct plugin_timer {
	struct timer timer;
	struct command_result *(*cb)(void);
};

struct plugin_conn {
	int fd;
	MEMBUF(char) mb;
};

/* Connection to make RPC requests. */
static struct plugin_conn rpc_conn;

struct command {
	u64 id;
	const char *methodname;
	bool usage_only;
};

struct out_req {
	/* The unique id of this request. */
	u64 id;
	/* The command which is why we're calling this rpc. */
	struct command *cmd;
	/* The callback when we get a response. */
	struct command_result *(*cb)(struct command *command,
				     const char *buf,
				     const jsmntok_t *result,
				     void *arg);
	/* The callback when we get an error. */
	struct command_result *(*errcb)(struct command *command,
					const char *buf,
					const jsmntok_t *error,
					void *arg);
	void *arg;
};

/* command_result is mainly used as a compile-time check to encourage you
 * to return as soon as you get one (and not risk use-after-free of command).
 * Here we use two values: complete (cmd freed) an pending (still going) */
struct command_result {
	char c;
};
static struct command_result complete, pending;

struct command_result *command_param_failed(void)
{
	return &complete;
}

/* Realloc helper for tal membufs */
static void *membuf_tal_realloc(struct membuf *mb, void *rawelems,
				size_t newsize)
{
	char *p = rawelems;

	tal_resize(&p, newsize);
	return p;
}

static int read_json(struct plugin_conn *conn)
{
	char *end;

	/* We rely on the double-\n marker which only terminates JSON top
	 * levels.  Thanks lightningd! */
	while ((end = memmem(membuf_elems(&conn->mb),
			     membuf_num_elems(&conn->mb), "\n\n", 2))
	       == NULL) {
		ssize_t r;

		/* Make sure we've room for at least READ_CHUNKSIZE. */
		membuf_prepare_space(&conn->mb, READ_CHUNKSIZE);
		r = read(conn->fd, membuf_space(&conn->mb),
			 membuf_num_space(&conn->mb));
		/* lightningd goes away, we go away. */
		if (r == 0)
			exit(0);
		if (r < 0)
			plugin_err("Reading JSON input: %s", strerror(errno));
		membuf_added(&conn->mb, r);
	}

	return end + 2 - membuf_elems(&conn->mb);
}

static struct command *read_json_request(const tal_t *ctx,
					 struct plugin_conn *conn,
					 struct plugin_conn *rpc,
					 const jsmntok_t **params,
					 int *reqlen)
{
	const jsmntok_t *toks, *id, *method;
	bool valid;
	struct command *cmd = tal(ctx, struct command);

	*reqlen = read_json(conn);
	toks = json_parse_input(cmd, membuf_elems(&conn->mb), *reqlen, &valid);
	if (!valid)
		plugin_err("Malformed JSON input '%.*s'",
			   *reqlen, membuf_elems(&conn->mb));

	if (toks[0].type != JSMN_OBJECT)
		plugin_err("Malformed JSON command '%*.s' is not an object",
			   *reqlen, membuf_elems(&conn->mb));

	method = json_get_member(membuf_elems(&conn->mb), toks, "method");
	*params = json_get_member(membuf_elems(&conn->mb), toks, "params");
	/* FIXME: Notifications don't have id! */
	id = json_get_member(membuf_elems(&conn->mb), toks, "id");
	if (!json_to_u64(membuf_elems(&conn->mb), id, &cmd->id))
		plugin_err("JSON id '%*.s' is not a number",
			   id->end - id->start,
			   membuf_elems(&conn->mb) + id->start);
	cmd->usage_only = false;
	cmd->methodname = json_strdup(cmd, membuf_elems(&conn->mb), method);

	return cmd;
}

/* I stole this trick from @wythe (Mark Beckwith); its ugliness is beautiful */
static void vprintf_json(int fd, const char *fmt_single_ticks, va_list ap)
{
	char *json, *p;
	size_t n;

	json = tal_vfmt(NULL, fmt_single_ticks, ap);

	for (n = 0, p = strchr(json, '\''); p; p = strchr(json, '\'')) {
		*p = '"';
		n++;
	}
	/* Don't put stray single-ticks in like this comment does! */
	assert(n % 2 == 0);
	write_all(fd, json, strlen(json));
	tal_free(json);
}

static PRINTF_FMT(2,3) void printf_json(int fd,
					const char *fmt_single_ticks, ...)
{
	va_list ap;

	va_start(ap, fmt_single_ticks);
	vprintf_json(fd, fmt_single_ticks, ap);
	va_end(ap);
}

/* param.c is insistant on functions returning 'struct command_result'; we
 * just always return NULL. */
static struct command_result *WARN_UNUSED_RESULT end_cmd(struct command *cmd)
{
	tal_free(cmd);
	return &complete;
}

static struct command_result *WARN_UNUSED_RESULT
command_done_ok(struct command *cmd, const char *result)
{
	printf_json(STDOUT_FILENO,
		    "{ 'jsonrpc': '2.0', "
		    "'id': %"PRIu64", "
		    "'result': { %s } }\n\n",
		    cmd->id, result);
	return end_cmd(cmd);
}

struct command_result *command_done_err(struct command *cmd,
					int code,
					const char *errmsg,
					const char *data)
{
	printf_json(STDOUT_FILENO,
		    "{ 'jsonrpc': '2.0', "
		    "'id': %"PRIu64", "
		    " 'error' : "
		    " { 'code' : %d,"
		    " 'message' : '%s'",
		    cmd->id, code, errmsg);
	if (data)
		printf_json(STDOUT_FILENO,
			    ", 'data': %s", data);
	printf_json(STDOUT_FILENO, " } }\n\n");
	return end_cmd(cmd);
}

static struct command_result *WARN_UNUSED_RESULT
command_done_raw(struct command *cmd,
		 const char *label,
		 const char *str, int size)
{
	printf_json(STDOUT_FILENO,
		    "{ 'jsonrpc': '2.0', "
		    "'id': %"PRIu64", "
		    " '%s' : %.*s }\n\n",
		    cmd->id, label, size, str);
	return end_cmd(cmd);
}

struct command_result *timer_complete(void)
{
	assert(in_timer > 0);
	in_timer--;
	return &complete;
}

struct command_result *command_success(struct command *cmd, const char *result)
{
	return command_done_raw(cmd, "result", result, strlen(result));
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
				    int code, const char *fmt, ...)
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
	if (!strmap_add(&usagemap, cmd->methodname, usage))
		plugin_err("Two usages for command %s?", cmd->methodname);
}

/* Reads rpc reply and returns tokens, setting contents to 'error' or
 * 'result' (depending on *error). */
static const jsmntok_t *read_rpc_reply(const tal_t *ctx,
				       struct plugin_conn *rpc,
				       const jsmntok_t **contents,
				       bool *error,
				       int *reqlen)
{
	const jsmntok_t *toks;
	bool valid;

	*reqlen = read_json(rpc);

	toks = json_parse_input(ctx, membuf_elems(&rpc->mb), *reqlen, &valid);
	if (!valid)
		plugin_err("Malformed JSON reply '%.*s'",
			   *reqlen, membuf_elems(&rpc->mb));

	*contents = json_get_member(membuf_elems(&rpc->mb), toks, "error");
	if (*contents)
		*error = true;
	else {
		*contents = json_get_member(membuf_elems(&rpc->mb), toks,
					    "result");
		if (!*contents)
			plugin_err("JSON reply with no 'result' nor 'error'? '%.*s'",
				   *reqlen, membuf_elems(&rpc->mb));
		*error = false;
	}
	return toks;
}

/* Synchronous routine to send command and extract single field from response */
const char *rpc_delve(const tal_t *ctx,
		      const char *method, const char *params,
		      struct plugin_conn *rpc, const char *guide)
{
	bool error;
	const jsmntok_t *contents, *t;
	int reqlen;
	const char *ret;

	printf_json(rpc->fd,
		    "{ 'method': '%s', 'id': 0, 'params': { %s } }",
		    method, params);

	read_rpc_reply(tmpctx, rpc, &contents, &error, &reqlen);
	if (error)
		plugin_err("Got error reply to %s: '%.*s'",
		     method, reqlen, membuf_elems(&rpc->mb));

	t = json_delve(membuf_elems(&rpc->mb), contents, guide);
	if (!t)
		plugin_err("Could not find %s in reply to %s: '%.*s'",
		     guide, method, reqlen, membuf_elems(&rpc->mb));

	ret = json_strdup(ctx, membuf_elems(&rpc->mb), t);
	membuf_consume(&rpc->mb, reqlen);
	return ret;
}

static void handle_rpc_reply(struct plugin_conn *rpc)
{
	int reqlen;
	const jsmntok_t *toks, *contents, *t;
	struct out_req *out;
	struct command_result *res;
	u64 id;
	bool error;

	toks = read_rpc_reply(tmpctx, rpc, &contents, &error, &reqlen);

	t = json_get_member(membuf_elems(&rpc->mb), toks, "id");
	if (!t)
		plugin_err("JSON reply without id '%.*s'",
			   reqlen, membuf_elems(&rpc->mb));
	if (!json_to_u64(membuf_elems(&rpc->mb), t, &id))
		plugin_err("JSON reply without numeric id '%.*s'",
			   reqlen, membuf_elems(&rpc->mb));
	out = uintmap_get(&out_reqs, id);
	if (!out)
		plugin_err("JSON reply with unknown id '%.*s' (%"PRIu64")",
			   reqlen, membuf_elems(&rpc->mb), id);

	/* We want to free this if callback doesn't. */
	tal_steal(tmpctx, out);
	uintmap_del(&out_reqs, out->id);

	if (error)
		res = out->errcb(out->cmd, membuf_elems(&rpc->mb), contents,
				 out->arg);
	else
		res = out->cb(out->cmd, membuf_elems(&rpc->mb), contents,
			      out->arg);

	assert(res == &pending || res == &complete);
	membuf_consume(&rpc->mb, reqlen);
}

struct command_result *
send_outreq_(struct command *cmd,
	     const char *method,
	     struct command_result *(*cb)(struct command *command,
					  const char *buf,
					  const jsmntok_t *result,
					  void *arg),
	     struct command_result *(*errcb)(struct command *command,
					     const char *buf,
					     const jsmntok_t *result,
					     void *arg),
	     void *arg,
	     const char *paramfmt_single_ticks, ...)
{
	va_list ap;
	struct out_req *out = tal(cmd, struct out_req);
	out->id = next_outreq_id++;
	out->cmd = cmd;
	out->cb = cb;
	out->errcb = errcb;
	out->arg = arg;
	uintmap_add(&out_reqs, out->id, out);

	printf_json(rpc_conn.fd,
		    "{ 'method': '%s', 'id': %"PRIu64", 'params': {",
		    method, out->id);
	va_start(ap, paramfmt_single_ticks);
	vprintf_json(rpc_conn.fd, paramfmt_single_ticks, ap);
	va_end(ap);
	printf_json(rpc_conn.fd, "} }");
	return &pending;
}

static struct command_result *
handle_getmanifest(struct command *getmanifest_cmd,
		   const struct plugin_command *commands,
		   size_t num_commands,
		   const struct plugin_option *opts)
{
	char *params = tal_strdup(getmanifest_cmd,
				  "'options': [");

	for (size_t i = 0; i < tal_count(opts); i++) {
		tal_append_fmt(&params, "{ 'name': '%s',"
			       "    'type': 'string',"
			       "    'description': '%s' }%s",
			       opts[i].name,
			       opts[i].description,
			       i == tal_count(opts) - 1 ? "" : ",\n");
	}

	tal_append_fmt(&params,
		       "],\n"
		       "'rpcmethods': [ ");

	for (size_t i = 0; i < num_commands; i++) {
		tal_append_fmt(&params, "{ 'name': '%s',"
			       "    'usage': '%s',"
			       "    'description': '%s'",
			       commands[i].name,
			       strmap_get(&usagemap, commands[i].name),
			       commands[i].description);
		if (commands[i].long_description)
			tal_append_fmt(&params,
				       "   'long_description': '%s'",
				       commands[i].long_description);
		tal_append_fmt(&params,
			       "}%s", i == num_commands - 1 ? "" : ",\n");
	}
	tal_append_fmt(&params, " ]");
	return command_done_ok(getmanifest_cmd, params);
}

static struct command_result *handle_init(struct command *init_cmd,
					  const char *buf,
					  const jsmntok_t *params,
					  const struct plugin_option *opts,
					  void (*init)(struct plugin_conn *))
{
	const jsmntok_t *rpctok, *dirtok, *opttok, *t;
	struct sockaddr_un addr;
	size_t i;
	char *dir;

	/* Move into lightning directory: other files are relative */
	dirtok = json_delve(buf, params, ".configuration.lightning-dir");
	dir = json_strdup(tmpctx, buf, dirtok);
	if (chdir(dir) != 0)
		plugin_err("chdir to %s: %s", dir, strerror(errno));

	rpctok = json_delve(buf, params, ".configuration.rpc-file");
	rpc_conn.fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (rpctok->end - rpctok->start + 1 > sizeof(addr.sun_path))
		plugin_err("rpc filename '%.*s' too long",
			   rpctok->end - rpctok->start,
			   buf + rpctok->start);
	memcpy(addr.sun_path, buf + rpctok->start, rpctok->end - rpctok->start);
	addr.sun_path[rpctok->end - rpctok->start] = '\0';
	addr.sun_family = AF_UNIX;

	if (connect(rpc_conn.fd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
		plugin_err("Connecting to '%.*s': %s",
			   rpctok->end - rpctok->start, buf + rpctok->start,
			   strerror(errno));

	deprecated_apis = streq(rpc_delve(tmpctx, "listconfigs",
					  "'config': 'allow-deprecated-apis'",
					  &rpc_conn,
					  ".allow-deprecated-apis"),
				"true");

	opttok = json_get_member(buf, params, "options");
	json_for_each_obj(i, t, opttok) {
		char *opt = json_strdup(NULL, buf, t);
		for (size_t i = 0; i < tal_count(opts); i++) {
			char *problem;
			if (!streq(opts[i].name, opt))
				continue;
			problem = opts[i].handle(json_strdup(opt, buf, t+1),
						 opts[i].arg);
			if (problem)
				plugin_err("option '%s': %s",
					   opts[i].name, problem);
			break;
		}
		tal_free(opt);
	}

	if (init)
		init(&rpc_conn);

	return command_done_ok(init_cmd, "");
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

char *charp_option(const char *arg, char **p)
{
	*p = tal_strdup(NULL, arg);
	return NULL;
}

static void handle_new_command(const tal_t *ctx,
			       struct plugin_conn *request_conn,
			       struct plugin_conn *rpc_conn,
			       const struct plugin_command *commands,
			       size_t num_commands)
{
	struct command *cmd;
	const jsmntok_t *params;
	int reqlen;

	cmd = read_json_request(ctx, request_conn, rpc_conn, &params, &reqlen);
	for (size_t i = 0; i < num_commands; i++) {
		if (streq(cmd->methodname, commands[i].name)) {
			commands[i].handle(cmd, membuf_elems(&request_conn->mb),
					   params);
			membuf_consume(&request_conn->mb, reqlen);
			return;
		}
	}

	plugin_err("Unknown command '%s'", cmd->methodname);
}

static void setup_command_usage(const struct plugin_command *commands,
				size_t num_commands)
{
	struct command *usage_cmd = tal(tmpctx, struct command);

	/* This is how common/param can tell it's just a usage request */
	usage_cmd->usage_only = true;
	for (size_t i = 0; i < num_commands; i++) {
		struct command_result *res;

		usage_cmd->methodname = commands[i].name;
		res = commands[i].handle(usage_cmd, NULL, NULL);
		assert(res == NULL);
		assert(strmap_get(&usagemap, commands[i].name));
	}
}

static void call_plugin_timer(struct plugin_conn *rpc, struct timer *timer)
{
	struct plugin_timer *t = container_of(timer, struct plugin_timer, timer);

	in_timer++;
	/* Free this if they don't. */
	tal_steal(tmpctx, t);
	t->cb();
}

static void destroy_plugin_timer(struct plugin_timer *timer)
{
	timer_del(&timers, &timer->timer);
}

struct plugin_timer *plugin_timer(struct plugin_conn *rpc, struct timerel t,
				  struct command_result *(*cb)(void))
{
	struct plugin_timer *timer = tal(NULL, struct plugin_timer);
	timer->cb = cb;
	timer_init(&timer->timer);
	timer_addrel(&timers, &timer->timer, t);
	tal_add_destructor(timer, destroy_plugin_timer);
	return timer;
}

static void plugin_logv(enum log_level l, const char *fmt, va_list ap)
{
	char *message;

	printf_json(STDOUT_FILENO,
		    "{ 'jsonrpc': '2.0', "
		    "'method': 'log', "
		    "'params': { 'level': '%s', 'message': \"",
		    l == LOG_DBG ? "debug"
		    : l == LOG_INFORM ? "info"
		    : l == LOG_UNUSUAL ? "warn"
		    : "error");

	message = tal_vfmt(NULL, fmt, ap);
	write_all(STDOUT_FILENO, message, strlen(message));
	printf_json(STDOUT_FILENO, "\" } }\n\n");
	tal_free(message);
}

void NORETURN plugin_err(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	plugin_logv(LOG_BROKEN, fmt, ap);
	va_end(ap);
	va_start(ap, fmt);
	errx(1, "%s", tal_vfmt(NULL, fmt, ap));
	va_end(ap);
}

void plugin_log(enum log_level l, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	plugin_logv(l, fmt, ap);
	va_end(ap);
}

void plugin_main(char *argv[],
		 void (*init)(struct plugin_conn *rpc),
		 const struct plugin_command *commands,
		 size_t num_commands, ...)
{
	struct plugin_conn request_conn;
	const tal_t *ctx = tal(NULL, char);
	struct command *cmd;
	const jsmntok_t *params;
	int reqlen;
	struct pollfd fds[2];
	struct plugin_option *opts = tal_arr(ctx, struct plugin_option, 0);
	va_list ap;
	const char *optname;

	setup_locale();

	daemon_maybe_debug(argv);

	/* Note this already prints to stderr, which is enough for now */
	daemon_setup(argv[0], NULL, NULL);

	setup_command_usage(commands, num_commands);

	timers_init(&timers, time_mono());
	membuf_init(&rpc_conn.mb,
		    tal_arr(ctx, char, READ_CHUNKSIZE), READ_CHUNKSIZE,
		    membuf_tal_realloc);
	request_conn.fd = STDIN_FILENO;
	membuf_init(&request_conn.mb,
		    tal_arr(ctx, char, READ_CHUNKSIZE), READ_CHUNKSIZE,
		    membuf_tal_realloc);
	uintmap_init(&out_reqs);

	va_start(ap, num_commands);
	while ((optname = va_arg(ap, const char *)) != NULL) {
		struct plugin_option o;
		o.name = optname;
		o.description = va_arg(ap, const char *);
		o.handle = va_arg(ap, char *(*)(const char *str, void *arg));
		o.arg = va_arg(ap, void *);
		tal_arr_expand(&opts, o);
	}
	va_end(ap);

	cmd = read_json_request(tmpctx, &request_conn, NULL,
				&params, &reqlen);
	if (!streq(cmd->methodname, "getmanifest"))
		plugin_err("Expected getmanifest not %s", cmd->methodname);

	membuf_consume(&request_conn.mb, reqlen);
	handle_getmanifest(cmd, commands, num_commands, opts);

	cmd = read_json_request(tmpctx, &request_conn, &rpc_conn,
				&params, &reqlen);
	if (!streq(cmd->methodname, "init"))
		plugin_err("Expected init not %s", cmd->methodname);

	handle_init(cmd, membuf_elems(&request_conn.mb),
		    params, opts, init);
	membuf_consume(&request_conn.mb, reqlen);

	/* Set up fds for poll. */
	fds[0].fd = STDIN_FILENO;
	fds[0].events = POLLIN;
	fds[1].fd = rpc_conn.fd;
	fds[1].events = POLLIN;

	for (;;) {
		struct timer *expired;
		struct timemono now, first;
		int t;

		clean_tmpctx();

		/* If we already have some input, process now. */
		if (membuf_num_elems(&request_conn.mb) != 0) {
			handle_new_command(ctx, &request_conn, &rpc_conn,
					   commands, num_commands);
			continue;
		}
		if (membuf_num_elems(&rpc_conn.mb) != 0) {
			handle_rpc_reply(&rpc_conn);
			continue;
		}

		/* Handle any timeouts */
		now = time_mono();
		expired = timers_expire(&timers, now);
		if (expired) {
			call_plugin_timer(&rpc_conn, expired);
			continue;
		}

		/* If we have a pending timer, timeout then */
		if (timer_earliest(&timers, &first))
			t = time_to_msec(timemono_between(first, now));
		else
			t = -1;

		/* Otherwise, we poll. */
		poll(fds, 2, t);

		if (fds[0].revents & POLLIN)
			handle_new_command(ctx, &request_conn, &rpc_conn,
					   commands, num_commands);
		if (fds[1].revents & POLLIN)
			handle_rpc_reply(&rpc_conn);
	}
}
