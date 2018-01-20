/*
 * Helper to submit via JSON-RPC and get back response.
 */
#include <ccan/err/err.h>
#include <ccan/opt/opt.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/str/str.h>
#include <ccan/tal/str/str.h>
#include <common/configdir.h>
#include <common/json.h>
#include <common/version.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#define NO_ERROR 0
#define ERROR_FROM_LIGHTNINGD 1
#define ERROR_TALKING_TO_LIGHTNINGD 2
#define ERROR_USAGE 3

/* Tal wrappers for opt. */
static void *opt_allocfn(size_t size)
{
	return tal_alloc_(NULL, size, false, false,
			  TAL_LABEL("opt_allocfn", ""));
}

static void *tal_reallocfn(void *ptr, size_t size)
{
	if (!ptr)
		return opt_allocfn(size);
	tal_resize_(&ptr, 1, size, false);
	return ptr;
}

static void tal_freefn(void *ptr)
{
	tal_free(ptr);
}

struct netaddr;
char *netaddr_name(const tal_t *ctx, const struct netaddr *a);
char *netaddr_name(const tal_t *ctx, const struct netaddr *a)
{
	return NULL;
}

int main(int argc, char *argv[])
{
	int fd, i, off;
	const char *method;
	char *cmd, *resp, *idstr, *rpc_filename;
	struct sockaddr_un addr;
	jsmntok_t *toks;
	const jsmntok_t *result, *error, *id;
	char *lightning_dir;
	const tal_t *ctx = tal(NULL, char);
	jsmn_parser parser;
	jsmnerr_t parserr;

	err_set_progname(argv[0]);
	jsmn_init(&parser);

	opt_set_alloc(opt_allocfn, tal_reallocfn, tal_freefn);
	configdir_register_opts(ctx, &lightning_dir, &rpc_filename);

	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "<command> [<params>...]", "Show this message\t use the command help (without hyphen) to get a list of all commands");
	opt_register_version();

	opt_early_parse(argc, argv, opt_log_stderr_exit);
	opt_parse(&argc, argv, opt_log_stderr_exit);

	method = argv[1];
	if (!method)
		errx(ERROR_USAGE, "Need at least one argument\n%s",
		     opt_usage(argv[0], NULL));

	if (chdir(lightning_dir) != 0)
		err(ERROR_TALKING_TO_LIGHTNINGD, "Moving into '%s'",
		    lightning_dir);

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (strlen(rpc_filename) + 1 > sizeof(addr.sun_path))
		errx(ERROR_USAGE, "rpc filename '%s' too long", rpc_filename);
	strcpy(addr.sun_path, rpc_filename);
	addr.sun_family = AF_UNIX;

	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
		err(ERROR_TALKING_TO_LIGHTNINGD,
		    "Connecting to '%s'", rpc_filename);

	idstr = tal_fmt(ctx, "lightning-cli-%i", getpid());
	cmd = tal_fmt(ctx,
		      "{ \"method\" : \"%s\", \"id\" : \"%s\", \"params\" : [ ",
		      method, idstr);

	for (i = 2; i < argc; i++) {
		/* Numbers, bools, objects and arrays are left unquoted,
		 * and quoted things left alone. */
		if (strspn(argv[i], "0123456789") == strlen(argv[i])
		    || streq(argv[i], "true")
		    || streq(argv[i], "false")
		    || argv[i][0] == '{'
		    || argv[i][0] == '['
		    || argv[i][0] == '"')
			tal_append_fmt(&cmd, "%s", argv[i]);
		else
			tal_append_fmt(&cmd, "\"%s\"", argv[i]);
		if (i != argc - 1)
			tal_append_fmt(&cmd, ", ");
	}
	tal_append_fmt(&cmd, "] }");

	if (!write_all(fd, cmd, strlen(cmd)))
		err(ERROR_TALKING_TO_LIGHTNINGD, "Writing command");

	/* Start with 1000 characters, 100 tokens. */
	resp = tal_arr(ctx, char, 1000);
	toks = tal_arr(ctx, jsmntok_t, 100);
	off = 0;
	parserr = 0;
	while (parserr <= 0) {
		/* Read more if parser says, or we have 0 tokens. */
		if (parserr == 0 || parserr == JSMN_ERROR_PART) {
			i = read(fd, resp + off, tal_count(resp) - 1 - off);
			if (i <= 0)
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
			tal_resize(&toks, tal_count(toks) * 2);
			break;
		case JSMN_ERROR_PART:
			/* Need more data: make room if necessary */
			if (off == tal_count(resp) - 1)
				tal_resize(&resp, tal_count(resp) * 2);
			break;
		}
	}

	if (toks->type != JSMN_OBJECT)
		errx(ERROR_TALKING_TO_LIGHTNINGD,
		     "Non-object response '%s'", resp);

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
		     "Incorrect 'id' in response: %.*s",
		     json_tok_len(id), json_tok_contents(resp, id));

	if (!error || json_tok_is_null(resp, error)) {
		printf("%.*s\n",
		       json_tok_len(result),
		       json_tok_contents(resp, result));
		tal_free(ctx);
		opt_free_table();
		return 0;
	}

	printf("%.*s\n",
	       json_tok_len(error), json_tok_contents(resp, error));
	tal_free(ctx);
	opt_free_table();
	return 1;
}
