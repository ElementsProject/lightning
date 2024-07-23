/*
 * Helper to submit via JSON-RPC and get back response.
 */
#include "config.h"
#include "config_cli.h"
#include <ccan/asort/asort.h>
#include <ccan/err/err.h>
#include <ccan/json_escape/json_escape.h>
#include <ccan/opt/opt.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/tal/path/path.h>
#include <ccan/tal/str/str.h>
#include <common/configdir.h>
#include <common/json_command.h>
#include <common/node_id.h>
#include <common/status_levels.h>
#include <common/utils.h>
#include <common/version.h>
#include <libgen.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#define NO_ERROR 0
#define ERROR_FROM_LIGHTNINGD 1
#define ERROR_TALKING_TO_LIGHTNINGD 2
#define ERROR_USAGE 3

struct netaddr;

/* Returns number of tokens digested */
static size_t human_readable(const char *buffer, const jsmntok_t *t, char term)
{
	size_t i, n;

	switch (t->type) {
	case JSMN_PRIMITIVE:
	case JSMN_STRING:
		for (i = t->start; i < t->end; i++) {
			/* We only translate \n and \t. */
			if (buffer[i] == '\\' && i + 1 < t->end) {
				if (buffer[i+1] == 'n') {
					fputc('\n', stdout);
					i++;
					continue;
				} else if (buffer[i+1] == 't') {
					fputc('\t', stdout);
					i++;
					continue;
				}
			}
			fputc(buffer[i], stdout);
		}
		fputc(term, stdout);
		return 1;
	case JSMN_ARRAY:
		n = 1;
		for (i = 0; i < t->size; i++)
			n += human_readable(buffer, t + n, '\n');
		return n;
	case JSMN_OBJECT:
		/* Elide single-field objects */
		if (t->size == 1)
			return human_readable(buffer, t + 2, '\n') + 2;
		n = 1;
		for (i = 0; i < t->size; i++) {
			n += human_readable(buffer, t + n, '=');
			n += human_readable(buffer, t + n, '\n');
		}
		return n;
	case JSMN_UNDEFINED:
		break;
	}
	abort();
}

/* Returns number of tokens digested */
static size_t flat_json(const char *prefix,
			const char *buffer, const jsmntok_t *t)
{
	size_t i, n;
	char *p;

	switch (t->type) {
	case JSMN_PRIMITIVE:
	case JSMN_STRING:
		printf("%s=%.*s\n",
		       prefix, t->end - t->start, buffer + t->start);
		return 1;
	case JSMN_ARRAY:
		n = 1;
		for (i = 0; i < t->size; i++) {
			p = tal_fmt(NULL, "%s[%zi]", prefix, i);
			n += flat_json(p, buffer, t + n);
			tal_free(p);
		}
		return n;
	case JSMN_OBJECT:
		n = 1;
		for (i = 0; i < t->size; i++) {
			if (streq(prefix, ""))
				p = tal_fmt(NULL, "%.*s",
					    t[n].end - t[n].start,
					    buffer + t[n].start);
			else
				p = tal_fmt(NULL, "%s.%.*s", prefix,
					    t[n].end - t[n].start,
					    buffer + t[n].start);
			n++;
			n += flat_json(p, buffer, t + n);
			tal_free(p);
		}
		return n;
	case JSMN_UNDEFINED:
		break;
	}
	abort();
}

static int compare_tok(const jsmntok_t *a, const jsmntok_t *b,
		       const char *buffer)
{
	int a_len = a->end - a->start, b_len = b->end - b->start, min_len, cmp;

	if (a_len > b_len)
		min_len = b_len;
	else
		min_len = a_len;

	cmp = memcmp(buffer + a->start, buffer + b->start, min_len);
	if (cmp != 0)
		return cmp;
	/* If equal, shorter one wins. */
	return a_len - b_len;
}

static int compare_help(const jsmntok_t *const *a,
			const jsmntok_t *const *b,
			char *buffer)
{
	const jsmntok_t *cat_a, *cat_b;
	bool a_is_developer, b_is_developer;
	int cmp;

	cat_a = json_get_member(buffer, *a, "category");
	cat_b = json_get_member(buffer, *b, "category");

	/* Just in case it's an older lightningd! */
	if (!cat_a)
		goto same_category;

	/* We always tweak "developer" category to last. */
	a_is_developer = json_tok_streq(buffer, cat_a, "developer");
	b_is_developer = json_tok_streq(buffer, cat_b, "developer");

	if (a_is_developer && b_is_developer)
		cmp = 0;
	else if (a_is_developer)
		cmp = 1;
	else if (b_is_developer)
		cmp = -1;
	else
		/* Otherwise we order category alphabetically. */
		cmp = compare_tok(cat_a, cat_b, buffer);

	if (cmp != 0)
		return cmp;

	/* After category, we order by name */
same_category:
	return compare_tok(json_get_member(buffer, *a, "command"),
			   json_get_member(buffer, *b, "command"),
			   buffer);
}

static void human_help(char *buffer, const jsmntok_t *result)
{
	unsigned int i;
	/* `curr` is used as a temporary token */
	const jsmntok_t *curr;
	/* Contains all commands objects, which have the following structure :
	 * {
	 *     "command": "The command name and usage"
	 * }
	 */
	const jsmntok_t * help_array = json_get_member(buffer, result, "help");
	const jsmntok_t **help = tal_arr(NULL, const jsmntok_t *,
					 help_array->size);

	/* Populate an array for easy sorting with asort */
	json_for_each_arr(i, curr, help_array)
		help[i] = curr;

	asort(help, tal_count(help), compare_help, buffer);

	for (i = 0; i < tal_count(help); i++) {
		const jsmntok_t *command;
		command = json_get_member(buffer, help[i], "command");
		printf("%.*s\n\n",
		       command->end - command->start, buffer + command->start);
	}
	tal_free(help);

	printf("---\nrun `lightning-cli help <command>` for more information on a specific command\n");
}

enum format {
	JSON,
	HUMAN,
	HELPLIST,
	FLAT,
	DEFAULT_FORMAT,
	RAW
};

static char *opt_set_human(enum format *format)
{
	*format = HUMAN;
	return NULL;
}

static char *opt_set_flat(enum format *format)
{
	*format = FLAT;
	return NULL;
}

static char *opt_set_json(enum format *format)
{
	*format = JSON;
	return NULL;
}

static char *opt_set_raw(enum format *format)
{
	*format = RAW;
	return NULL;
}

enum input {
	KEYWORDS,
	ORDERED,
	DEFAULT_INPUT
};

static char *opt_set_keywords(enum input *input)
{
	*input = KEYWORDS;
	return NULL;
}

static char *opt_set_ordered(enum input *input)
{
	*input = ORDERED;
	return NULL;
}

static bool is_literal(const char *arg)
{
	size_t arglen = strlen(arg);
	if (arglen == 0) {
		return false;
	}
	return strspn(arg, "0123456789.") == arglen
		|| streq(arg, "true")
		|| streq(arg, "false")
		|| streq(arg, "null")
		|| (arg[0] == '{' && arg[arglen - 1] == '}')
		|| (arg[0] == '[' && arg[arglen - 1] == ']')
		|| (arg[0] == '"' && arg[arglen - 1] == '"');
}

static void add_input(char **cmd, const char *input,
		      int i, int argc)
{
	/* Numbers, bools, objects and arrays are left unquoted,
	 * and quoted things left alone. */
	if (is_literal(input))
		tal_append_fmt(cmd, "%s", input);
	else
		tal_append_fmt(cmd, "\"%s\"", json_escape(*cmd, input)->s);
	if (i != argc - 1)
		tal_append_fmt(cmd, ", ");
}

static void
try_exec_man (const char *page, char *relative_to) {
	int status;

	switch (fork()) {
	case -1:
		err(1, "Forking man command");
	case 0:
		/* child, run man command. */
		if (relative_to != NULL) {
			page = tal_fmt(page, "%s/../doc/%s.7", relative_to, page);
			execlp("man", "man", "-l", page, (char *)NULL);
		}
		else {
			execlp("man", "man", page, (char *)NULL);
		}

		err(1, "Running man command");
	default:
		break;
	}

	wait(&status);
	if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
		exit(0);
}

static void print_json(const char *str, const jsmntok_t *tok, const char *indent)
{
	size_t i;
	const jsmntok_t *t;
	bool first;
	char next_indent[strlen(indent) + 3 + 1];

	memset(next_indent, ' ', sizeof(next_indent)-1);
	next_indent[sizeof(next_indent)-1] = '\0';

	switch (tok->type) {
	case JSMN_PRIMITIVE:
	case JSMN_STRING:
		printf("%.*s", json_tok_full_len(tok), json_tok_full(str, tok));
		return;

	case JSMN_ARRAY:
		first = true;
		json_for_each_arr(i, t, tok) {
			if (first)
				printf("[\n%s", next_indent);
			else
				printf(",\n%s", next_indent);
			print_json(str, t, next_indent);
			first = false;
		}
		if (first)
			printf("[]");
		else
			printf("\n%s]", indent);
		return;

	case JSMN_OBJECT:
		first = true;
		json_for_each_obj(i, t, tok) {
			if (first)
				printf("{\n%s", next_indent);
			else
				printf(",\n%s", next_indent);
			print_json(str, t, next_indent);
			printf(": ");
			print_json(str, t + 1, next_indent);
			first = false;
		}
		if (first)
			printf("{}");
		else
			printf("\n%s}", indent);
		return;
	case JSMN_UNDEFINED:
		break;
	}
	abort();
}

/* Always returns a positive number < len.  len must be > 0! */
static size_t read_nofail(int fd, void *buf, size_t len)
{
	ssize_t i;
	assert(len > 0);

	i = cli_read(fd, buf, len);
	if (i == 0)
		errx(ERROR_TALKING_TO_LIGHTNINGD,
		     "reading response: socket closed");
	else if (i < 0)
		err(ERROR_TALKING_TO_LIGHTNINGD, "reading response");
	return i;
}

/* We rely on the fact that lightningd terminates all JSON RPC responses with
 * "\n\n", so we can stream even if we can't parse. */
static void oom_dump(int fd, char *resp, size_t off)
{
	warnx("Out of memory: sending raw output");

	/* Note: resp does not already end in '\n\n', and resp_len is > 0 */
	do {
		/* Keep last char, to avoid splitting \n\n */
		write_all(STDOUT_FILENO, resp, off-1);
		resp[0] = resp[off-1];
		off = 1 + read_nofail(fd, resp + 1, tal_bytelen(resp) - 1);
	} while (resp[off-2] != '\n' || resp[off-1] != '\n');
	write_all(STDOUT_FILENO, resp, off-1);
	/* We assume giant answer means "success" */
	exit(0);
}

/* We want to return failure if tal_resize fails */
static void tal_error(const char *msg)
{
	if (streq(msg, "Reallocation failure"))
		return;
	abort();
}

static enum format delete_format_hint(const char *resp, jsmntok_t **toks)
{
	const jsmntok_t *result = json_get_member(resp, *toks, "result");
	const jsmntok_t *hint;
	enum format format = JSON;

	if (!result)
		return format;

	hint = json_get_member(resp, result, "format-hint");
	if (!hint)
		return format;

	if (json_tok_streq(resp, hint, "simple"))
		format = HUMAN;

	/* Don't let hint appear in the output! */
        /* Note the aritmetic on *toks for const-washing */
	json_tok_remove(toks, *toks + (result - *toks), hint-1, 1);
	return format;
}

static enum format choose_format(const char *resp,
				 jsmntok_t **toks,
				 const char *method,
				 const char *command,
				 enum format format)
{
	/* If they specify a format, that's what we use. */
	if (format != DEFAULT_FORMAT) {
		/* But humans don't want to see the format hint! */
		if (format == HUMAN)
			delete_format_hint(resp, toks);
		return format;
	}

	/* This works best when we order it. */
	if (streq(method, "help") && command == NULL)
		format = HELPLIST;
	else
		format = delete_format_hint(resp, toks);

	return format;
}

static bool handle_notify(const char *buf, jsmntok_t *toks,
			  enum log_level notification_level,
			  bool *last_was_progress)
{
	const jsmntok_t *id, *method, *params;

	if (toks->type != JSMN_OBJECT)
		return false;

	id = json_get_member(buf, toks, "id");
	if (id)
		return false;

	method = json_get_member(buf, toks, "method");
	if (!method)
		return false;

	params = json_get_member(buf, toks, "params");
	if (!params)
		return false;

	/* Print nothing if --notifications=none */
	if (notification_level == LOG_LEVEL_MAX + 1)
		return true;

	/* We try to be robust if malformed */
	if (json_tok_streq(buf, method, "message")) {
		const jsmntok_t *message, *leveltok;
		enum log_level level;

		leveltok = json_get_member(buf, params, "level");
		if (!leveltok
		    || !log_level_parse(buf + leveltok->start,
					leveltok->end - leveltok->start,
					&level)
		    || level < notification_level)
			return true;

		if (*last_was_progress)
			printf("\n");
		*last_was_progress = false;
		message = json_get_member(buf, params, "message");
		if (!message)
			return true;

		printf("# %.*s\n",
		       message->end - message->start,
		       buf + message->start);
	} else if (json_tok_streq(buf, method, "progress")) {
		const jsmntok_t *num, *total, *stage;
		u32 n, tot;
		char bar[60 + 1];
		char totstr[STR_MAX_CHARS(u32)];

		num = json_get_member(buf, params, "num");
		total = json_get_member(buf, params, "total");
		if (!num || !total)
			return true;
		if (!json_to_u32(buf, num, &n)
		    || !json_to_u32(buf, total, &tot))
			return true;

		/* Ph3ar my gui skillz! */
		printf("\r# ");
		stage = json_get_member(buf, params, "stage");
		if (stage) {
			u32 stage_num, stage_total;
			json_to_u32(buf, json_get_member(buf, stage, "num"),
				    &stage_num);
			json_to_u32(buf, json_get_member(buf, stage, "total"),
				    &stage_total);
			snprintf(totstr, sizeof(totstr), "%u", stage_total);
			printf("Stage %*u/%s ",
			       (int)strlen(totstr), stage_num+1, totstr);
		}
		snprintf(totstr, sizeof(totstr), "%u", tot);
		printf("%*u/%s ", (int)strlen(totstr), n+1, totstr);
		memset(bar, ' ', sizeof(bar)-1);
		memset(bar, '=', (double)(sizeof(bar)-1) / (tot-1) * n);
		bar[sizeof(bar)-1] = '\0';
		printf("|%s|", bar);
		/* Leave bar there if it's finished. */
		if (n+1 == tot) {
			printf("\n");
			*last_was_progress = false;
		} else {
			fflush(stdout);
			*last_was_progress = true;
		}
	}

	return true;
}

static void enable_notifications(int fd)
{
	const char *enable;
	char rbuf[100];

	enable = tal_fmt(tmpctx,
			 "{\"jsonrpc\":\"2.0\","
			 "\"method\":\"notifications\","
			 "\"id\":\"cli:notifications#%i\","
			 "\"params\":{\"enable\":true}}",
			 getpid());
	if (!write_all(fd, enable, strlen(enable)))
		err(ERROR_TALKING_TO_LIGHTNINGD, "Writing enable command");

	/* We get a very simple response, ending in \n\n. */
	memset(rbuf, 0, sizeof(rbuf));
	while (!strends(rbuf, "\n\n")) {
		size_t len = strlen(rbuf);
		if (cli_read(fd, rbuf + len, sizeof(rbuf) - len) <= 0)
			err(ERROR_TALKING_TO_LIGHTNINGD,
			    "Reading enable response");
	}
}

static char *opt_set_level(const char *arg, enum log_level *level)
{
	if (streq(arg, "none"))
		*level = LOG_LEVEL_MAX + 1;
	else if (!log_level_parse(arg, strlen(arg), level))
		return "Invalid level";
	return NULL;
}

static bool opt_show_level(char *buf, size_t len, const enum log_level *level)
{
	if (*level == LOG_LEVEL_MAX + 1)
		strncpy(buf, "none", len);
	else
		strncpy(buf, log_level_name(*level), len);
	return true;
}

/* The standard opt_log_stderr_exit exits with status 1 */
static void opt_log_stderr_exit_usage(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
	exit(ERROR_USAGE);
}

struct commando {
	const char *peer_id;
	const char *rune;
};

static char *opt_set_commando(const char *arg, struct commando **commando)
{
	size_t idlen = strcspn(arg, ":");
	*commando = tal(NULL, struct commando);

	/* We don't use common/node_id.c here, to keep dependencies minimal */
	if (idlen != PUBKEY_CMPR_LEN * 2)
		return "Invalid peer id";
	(*commando)->peer_id = tal_strndup(*commando, arg, idlen);

	if (arg[idlen] == '\0')
		(*commando)->rune = NULL;
	else
		(*commando)->rune = tal_strdup(*commando, arg + idlen + 1);

	return NULL;
}

int main(int argc, char *argv[])
{
	setup_locale();

	int fd;
	size_t off;
	const char *method;
	char *cmd, *resp, *idstr;
	struct sockaddr_un addr;
	jsmntok_t *toks;
	const jsmntok_t *result, *error, *id;
	const tal_t *ctx = tal(NULL, char);
	char *config_filename, *base_dir, *net_dir, *rpc_filename;
	jsmn_parser parser;
	int parserr;
	enum format format = DEFAULT_FORMAT;
	enum input input = DEFAULT_INPUT;
	enum log_level notification_level = LOG_INFORM;
	bool last_was_progress = false;
	char *command = NULL, *filter = NULL;
	struct commando *commando = NULL;

	err_set_progname(argv[0]);
	jsmn_init(&parser);

	tal_set_backend(NULL, NULL, NULL, tal_error);

	setup_option_allocators();

	opt_exitcode = ERROR_USAGE;
	minimal_config_opts(ctx, argc, argv, &config_filename, &base_dir,
			    &net_dir, &rpc_filename);

	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "<command> [<params>...]", "Show this message. Use the command help (without hyphens -- \"lightning-cli help\") to get a list of all RPC commands");
	opt_register_noarg("-H|--human-readable", opt_set_human, &format,
			   "Human-readable output");
	opt_register_noarg("-F|--flat", opt_set_flat, &format,
			   "Flatten output ('x.y.x=' format)");
	opt_register_noarg("-J|--json", opt_set_json, &format,
			   "JSON output (default unless 'help')");
	opt_register_noarg("-R|--raw", opt_set_raw, &format,
			   "Raw, unformatted JSON output");
	opt_register_noarg("-k|--keywords", opt_set_keywords, &input,
			   "Use format key=value for <params>");
	opt_register_noarg("-o|--order", opt_set_ordered, &input,
			   "Use params in order for <params>");
	opt_register_arg("-N|--notifications", opt_set_level,
			 opt_show_level, &notification_level,
			 "Set notification level, or none");
	opt_register_arg("-l|--filter", opt_set_charp,
			 opt_show_charp, &filter,
			 "Set JSON reply filter");
	opt_register_arg("-c|--commando", opt_set_commando,
			 NULL, &commando,
			 "Send this as a commando command to nodeid:rune");

	opt_early_parse(argc, argv, opt_log_stderr_exit_usage);
	opt_parse(&argc, argv, opt_log_stderr_exit_usage);

	/* Make sure this is parented correctly if set! */
	tal_steal(ctx, commando);

	method = argv[1];
	if (!method) {
		char *usage = opt_usage(argv[0], NULL);
		printf("%s\n", usage);
		tal_free(usage);
		printf("Querying lightningd for available RPC commands (\"lightning-cli help\"):\n\n");
		method = "help";
	}

	/* Launch a manpage if we have a help command with an argument. We do
	 * not need to have lightningd running in this case. */
	if (streq(method, "help") && format == DEFAULT_FORMAT && argc >= 3 && !commando) {
		command = argv[2];
		char *page = tal_fmt(ctx, "lightning-%s", command);

		try_exec_man(page, NULL);

		/* Try to find the page relative to this executable.
		 * This handles the common scenario where lightning-cli
		 * was built from source and hasn't been installed yet */
		try_exec_man(page, dirname(argv[0]));

		tal_free(page);
	}

	/* If an absolute path to the RPC socket is given, it takes over other
	 * configuration options. */
	if (path_is_abs(rpc_filename)) {
		net_dir = path_dirname(ctx, rpc_filename);
		rpc_filename = path_basename(ctx, rpc_filename);
	}

	if (chdir(net_dir) != 0)
		err(ERROR_TALKING_TO_LIGHTNINGD, "Moving into '%s'",
		    net_dir);

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (strlen(rpc_filename) + 1 > sizeof(addr.sun_path))
		errx(ERROR_USAGE, "rpc filename '%s' too long", rpc_filename);
	strcpy(addr.sun_path, rpc_filename);
	addr.sun_family = AF_UNIX;

	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
		err(ERROR_TALKING_TO_LIGHTNINGD,
		    "Connecting to '%s'", rpc_filename);

	/* We use weird methodnames in test_misc.py::test_cli(), and then
	 * complain the cln mangles it.  So omit method in that case */
	if (json_escape_needed(method, strlen(method)))
		idstr = tal_fmt(ctx, "cli:weirdmethod!#%i", getpid());
	else
		idstr = tal_fmt(ctx, "cli:%s#%i", method, getpid());

	/* FIXME: commando should support notifications! */
	if (notification_level <= LOG_LEVEL_MAX && !commando)
		enable_notifications(fd);

	cmd = tal_fmt(ctx,
		      "{ \"jsonrpc\" : \"2.0\", \"method\" : \"%s\", \"id\" : \"%s\",",
		      commando ? "commando" : json_escape(ctx, method)->s,
		      idstr);
	if (filter && !commando)
		tal_append_fmt(&cmd, "\"filter\": %s,", filter);
	tal_append_fmt(&cmd, " \"params\" :");

	if (commando) {
		tal_append_fmt(&cmd, "{"
			       " \"peer_id\": \"%s\","
			       " \"method\": \"%s\",",
			       commando->peer_id,
			       json_escape(ctx, method)->s);
		if (filter) {
			tal_append_fmt(&cmd, "\"filter\": %s,", filter);
		}
		if (commando->rune) {
			tal_append_fmt(&cmd, " \"rune\": \"%s\",",
				       commando->rune);
		}
		tal_append_fmt(&cmd, " \"params\": ");
	}

	if (input == DEFAULT_INPUT) {
		/* Hacky autodetect; only matters if more than single arg */
		if (argc > 2 && strchr(argv[2], '='))
			input = KEYWORDS;
		else
			input = ORDERED;
	}

	if (input == KEYWORDS) {
		tal_append_fmt(&cmd, "{ ");
		for (size_t i = 2; i < argc; i++) {
			const char *eq = strchr(argv[i], '=');

			if (!eq)
				err(ERROR_USAGE, "Expected key=value in '%s'",
				    argv[i]);

			tal_append_fmt(&cmd, "\"%.*s\" : ",
				       (int)(eq - argv[i]), argv[i]);

			add_input(&cmd, eq + 1, i, argc);
		}
		tal_append_fmt(&cmd, "} }");
	} else {
		tal_append_fmt(&cmd, "[ ");
		for (size_t i = 2; i < argc; i++)
			add_input(&cmd, argv[i], i, argc);
		tal_append_fmt(&cmd, "] }");
	}

	/* For commando, "params" we just populated is inside real "params" */
	if (commando)
		tal_append_fmt(&cmd, "}");

	toks = json_parse_simple(ctx, cmd, strlen(cmd));
	if (toks == NULL)
		errx(ERROR_USAGE,
		     "Some parameters are malformed, cannot create a valid "
		     "JSON-RPC request: %s",
		     cmd);
	tal_free(toks);

	if (!write_all(fd, cmd, strlen(cmd)))
		err(ERROR_TALKING_TO_LIGHTNINGD, "Writing command");

	/* Start with 1000 characters, 100 tokens. */
	resp = tal_arr(ctx, char, 1000);
	toks = tal_arr(ctx, jsmntok_t, 100);
	toks[0].type = JSMN_UNDEFINED;

	off = 0;
	parserr = 0;
	while (parserr <= 0) {
		/* Read more if parser says, or we have 0 tokens. */
		if (parserr == 0 || parserr == JSMN_ERROR_PART) {
			ssize_t i = cli_read(fd, resp + off, tal_bytelen(resp) - 1 - off);
			if (i == 0)
				errx(ERROR_TALKING_TO_LIGHTNINGD,
				     "reading response: socket closed");
			else if (i < 0)
				err(ERROR_TALKING_TO_LIGHTNINGD,
				    "reading response");
			off += i;
			/* NUL terminate */
			resp[off] = '\0';
		}

		/* (Continue) parsing */
		parserr = jsmn_parse(&parser, resp, off, toks, tal_count(toks));

		switch (parserr) {
		case JSMN_ERROR_INVAL:
			errx(ERROR_TALKING_TO_LIGHTNINGD,
			     "Malformed response '%s'", resp);
		case JSMN_ERROR_NOMEM:
			/* Need more tokens, double it */
			if (!tal_resize(&toks, tal_count(toks) * 2))
				oom_dump(fd, resp, off);
			break;
		case JSMN_ERROR_PART:
			/* We may actually have a complete token! */
			if (toks[0].type == JSMN_UNDEFINED || toks[0].end == -1) {
				/* Need more data: make room if necessary */
				if (off == tal_bytelen(resp) - 1) {
					if (!tal_resize(&resp, tal_count(resp) * 2))
						oom_dump(fd, resp, off);
				}
				break;
			}
			/* Otherwise fall through... */
		default:
			if (handle_notify(resp, toks, notification_level,
					  &last_was_progress)) {
				/* +2 for \n\n */
				size_t len = toks[0].end - toks[0].start + 2;
				memmove(resp, resp + len, off - len);
				off -= len;
				jsmn_init(&parser);
				toks[0].type = JSMN_UNDEFINED;
				/* Don't force another read! */
				parserr = JSMN_ERROR_NOMEM;
			}
		}
	}

	if (toks->type != JSMN_OBJECT)
		errx(ERROR_TALKING_TO_LIGHTNINGD,
		     "Non-object response '%s'", resp);

	if (last_was_progress)
		printf("\n");

	/* This can reallocate toks, so call before getting pointers to tokens */
	format = choose_format(resp, &toks, method, command, format);
	result = json_get_member(resp, toks, "result");
	error = json_get_member(resp, toks, "error");
	if (!error && !result)
		errx(ERROR_TALKING_TO_LIGHTNINGD,
		     "Either 'result' or 'error' must be returned in response '%s'", resp);
	id = json_get_member(resp, toks, "id");
	if (!id)
		errx(ERROR_TALKING_TO_LIGHTNINGD,
		     "Missing 'id' in response '%s'", resp);
	if (!json_tok_streq(resp, id, idstr))
		errx(ERROR_TALKING_TO_LIGHTNINGD,
		     "Incorrect 'id' (%.*s) in response: %.*s",
		     json_tok_full_len(id), json_tok_full(resp, id),
		     json_tok_full_len(toks), json_tok_full(resp, toks));

	if (!error || json_tok_is_null(resp, error)) {
		switch (format) {
		case HELPLIST:
			human_help(resp, result);
			break;
		case HUMAN:
			human_readable(resp, result, '\n');
			break;
		case FLAT:
			flat_json("", resp, result);
			break;
		case JSON:
			print_json(resp, result, "");
			printf("\n");
			break;
		case RAW:
			printf("%.*s\n",
			       json_tok_full_len(result),
			       json_tok_full(resp, result));
			break;
		default:
			abort();
		}
		tal_free(ctx);
		opt_free_table();
		return NO_ERROR;
	}

	if (format == RAW)
		printf("%.*s\n",
		       json_tok_full_len(error), json_tok_full(resp, error));
	else {
		print_json(resp, error, "");
		printf("\n");
	}
	tal_free(ctx);
	opt_free_table();
	return ERROR_FROM_LIGHTNINGD;
}
