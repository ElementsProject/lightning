/* Code for JSON_RPC API */
/* eg: { "method" : "dev-echo", "params" : [ "hello", "Arabella!" ], "id" : "1" } */
#include <arpa/inet.h>
#include <bitcoin/address.h>
#include <bitcoin/base58.h>
#include <bitcoin/script.h>
#include <ccan/array_size/array_size.h>
#include <ccan/err/err.h>
#include <ccan/io/backend.h>
#include <ccan/io/io.h>
#include <ccan/str/hex/hex.h>
#include <ccan/tal/str/str.h>
#include <common/bech32.h>
#include <common/memleak.h>
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
#include <lightningd/lightningd.h>
#include <lightningd/log.h>
#include <lightningd/options.h>
#include <lightningd/param.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>

/* Realloc helper for tal membufs */
static void *membuf_tal_realloc(struct membuf *mb,
				void *rawelems, size_t newsize)
{
	char *p = rawelems;

	tal_resize(&p, newsize);
	return p;
}

/* jcon and cmd have separate lifetimes: we detach them on either destruction */
static void destroy_jcon(struct json_connection *jcon)
{
	if (jcon->command) {
		log_debug(jcon->log, "Abandoning command");
		jcon->command->jcon = NULL;
	}

	/* Make sure this happens last! */
	tal_free(jcon->log);
}

/* FIXME: This, or something prettier (io_replan?) belong in ccan/io! */
static void adjust_io_write(struct io_conn *conn, ptrdiff_t delta)
{
	conn->plan[IO_OUT].arg.u1.cp += delta;
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

static void json_getinfo(struct command *cmd,
			 const char *buffer UNUSED, const jsmntok_t *params UNUSED)
{
	struct json_stream *response;

	if (!param(cmd, buffer, params, NULL))
		return;

	response = json_stream_success(cmd);
	json_object_start(response, NULL);
	json_add_pubkey(response, "id", &cmd->ld->id);
	json_add_string(response, "alias", (const char *)cmd->ld->alias);
	json_add_hex_talarr(response, "color", cmd->ld->rgb);
	if (cmd->ld->listen) {
		/* These are the addresses we're announcing */
		json_array_start(response, "address");
		for (size_t i = 0; i < tal_count(cmd->ld->announcable); i++)
			json_add_address(response, NULL, cmd->ld->announcable+i);
		json_array_end(response);

		/* This is what we're actually bound to. */
		json_array_start(response, "binding");
		for (size_t i = 0; i < tal_count(cmd->ld->binding); i++)
			json_add_address_internal(response, NULL,
						  cmd->ld->binding+i);
		json_array_end(response);
	}
	json_add_string(response, "version", version());
	json_add_num(response, "blockheight", get_block_height(cmd->ld->topology));
	json_add_string(response, "network", get_chainparams(cmd->ld)->network_name);
	json_add_u64(response, "msatoshi_fees_collected",
		     wallet_total_forward_fees(cmd->ld->wallet));
	json_object_end(response);
	command_success(cmd, response);
}

static const struct json_command getinfo_command = {
	"getinfo",
	json_getinfo,
	"Show information about this node"
};
AUTODATA(json_command, &getinfo_command);

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
	unsigned int i;
	struct json_stream *response;
	struct json_command **cmdlist = get_cmdlist();
	const jsmntok_t *cmdtok;

	if (!param(cmd, buffer, params,
		   p_opt("command", json_tok_tok, &cmdtok),
		   NULL))
		return;

	if (cmdtok) {
		for (i = 0; i < num_cmdlist; i++) {
			if (json_tok_streq(buffer, cmdtok, cmdlist[i]->name)) {
				response = json_stream_success(cmd);
				json_add_help_command(cmd, response, cmdlist[i]);
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
	for (i = 0; i < num_cmdlist; i++) {
		json_add_help_command(cmd, response, cmdlist[i]);
	}
	json_array_end(response);
	json_object_end(response);

done:
	command_success(cmd, response);
}

static const struct json_command *find_cmd(const char *buffer,
					   const jsmntok_t *tok)
{
	unsigned int i;
	struct json_command **cmdlist = get_cmdlist();

	/* cmdlist[i]->name can be NULL in test code. */
	for (i = 0; i < num_cmdlist; i++)
		if (cmdlist[i]->name
		    && json_tok_streq(buffer, tok, cmdlist[i]->name))
			return cmdlist[i];
	return NULL;
}

/* Make sure jcon->outbuf has room for len */
static void json_connection_mkroom(struct json_connection *jcon, size_t len)
{
	ptrdiff_t delta = membuf_prepare_space(&jcon->outbuf, len);

	/* If io_write is in progress, we shift it to point to new buffer pos */
	if (io_lock_taken(jcon->lock))
		adjust_io_write(jcon->conn, delta);
}

void jcon_append(struct json_connection *jcon, const char *str)
{
	size_t len = strlen(str);

	json_connection_mkroom(jcon, len);
	memcpy(membuf_add(&jcon->outbuf, len), str, len);

	/* Wake writer. */
	io_wake(jcon);
}

void jcon_append_vfmt(struct json_connection *jcon, const char *fmt, va_list ap)
{
	size_t fmtlen;
	va_list ap2;

	/* Make a copy in case we need it below. */
	va_copy(ap2, ap);

	/* Try printing in place first. */
	fmtlen = vsnprintf(membuf_space(&jcon->outbuf),
			   membuf_num_space(&jcon->outbuf), fmt, ap);

	/* Horrible subtlety: vsnprintf *will* NUL terminate, even if it means
	 * chopping off the last character.  So if fmtlen ==
	 * membuf_num_space(&jcon->outbuf), the result was truncated! */
	if (fmtlen < membuf_num_space(&jcon->outbuf)) {
		membuf_added(&jcon->outbuf, fmtlen);
	} else {
		/* Make room for NUL terminator, even though we don't want it */
		json_connection_mkroom(jcon, fmtlen + 1);
		vsprintf(membuf_space(&jcon->outbuf), fmt, ap2);
		membuf_added(&jcon->outbuf, fmtlen);
	}

	va_end(ap2);

	/* Wake writer. */
	io_wake(jcon);
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

	assert(cmd->jcon->command == cmd);
	cmd->jcon->command = NULL;
}

/* FIXME: Remove result arg here! */
void command_success(struct command *cmd, struct json_stream *result)
{
	assert(cmd);
	assert(cmd->have_json_stream);
	if (cmd->jcon)
		jcon_append(cmd->jcon, " }\n\n");
	if (cmd->ok)
		*(cmd->ok) = true;
	tal_free(cmd);
}

/* FIXME: Remove result arg here! */
void command_failed(struct command *cmd, struct json_stream *result)
{
	assert(cmd->have_json_stream);
	/* Have to close error */
	if (cmd->jcon)
		jcon_append(cmd->jcon, " } }\n\n");
	if (cmd->ok)
		*(cmd->ok) = false;
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

static void jcon_start(struct json_connection *jcon, const char *id)
{
	jcon_append(jcon, "{ \"jsonrpc\": \"2.0\", \"id\" : ");
	jcon_append(jcon, id);
	jcon_append(jcon, ", ");
}

static void json_command_malformed(struct json_connection *jcon,
				   const char *id,
				   const char *error)
{
	jcon_start(jcon, id);
	jcon_append(jcon,
		    tal_fmt(tmpctx, " \"error\" : "
			    "{ \"code\" : %d,"
			    " \"message\" : \"%s\" } }\n\n",
			    JSONRPC2_INVALID_REQUEST, error));
}

/* Returns true if command already completed. */
static bool parse_request(struct json_connection *jcon, const jsmntok_t tok[])
{
	const jsmntok_t *method, *id, *params;
	struct command *c;

	if (tok[0].type != JSMN_OBJECT) {
		json_command_malformed(jcon, "null",
				       "Expected {} for json command");
		return true;
	}

	method = json_get_member(jcon->buffer, tok, "method");
	params = json_get_member(jcon->buffer, tok, "params");
	id = json_get_member(jcon->buffer, tok, "id");

	if (!id) {
		json_command_malformed(jcon, "null", "No id");
		return true;
	}
	if (id->type != JSMN_STRING && id->type != JSMN_PRIMITIVE) {
		json_command_malformed(jcon, "null",
				       "Expected string/primitive for id");
		return true;
	}

	/* This is a convenient tal parent for duration of command
	 * (which may outlive the conn!). */
	c = tal(jcon->ld->rpc_listener, struct command);
	c->jcon = jcon;
	c->ld = jcon->ld;
	c->pending = false;
	c->have_json_stream = false;
	c->id = tal_strndup(c,
			    json_tok_contents(jcon->buffer, id),
			    json_tok_len(id));
	c->mode = CMD_NORMAL;
	c->ok = NULL;
	jcon->command = c;
	tal_add_destructor(c, destroy_command);

	/* Write start of response: rest will be appended directly. */
	jcon_start(jcon, c->id);

	if (!method || !params) {
		command_fail(c, JSONRPC2_INVALID_REQUEST,
			     method ? "No params" : "No method");
		return true;
	}

	if (method->type != JSMN_STRING) {
		command_fail(c, JSONRPC2_INVALID_REQUEST,
			     "Expected string for method");
		return true;
	}

	c->json_cmd = find_cmd(jcon->buffer, method);
	if (!c->json_cmd) {
		command_fail(c, JSONRPC2_METHOD_NOT_FOUND,
			     "Unknown command '%.*s'",
			     method->end - method->start,
			     jcon->buffer + method->start);
		return true;
	}
	if (c->json_cmd->deprecated && !deprecated_apis) {
		command_fail(c, JSONRPC2_METHOD_NOT_FOUND,
			     "Command '%.*s' is deprecated",
			      method->end - method->start,
			      jcon->buffer + method->start);
		return true;
	}

	db_begin_transaction(jcon->ld->wallet->db);
	c->json_cmd->dispatch(c, jcon->buffer, params);
	db_commit_transaction(jcon->ld->wallet->db);

	/* If they didn't complete it, they must call command_still_pending */
	if (jcon->command == c)
		assert(c->pending);

	return jcon->command == NULL;
}

/* Mutual recursion */
static struct io_plan *locked_write_json(struct io_conn *conn,
					 struct json_connection *jcon);
static struct io_plan *write_json(struct io_conn *conn,
				  struct json_connection *jcon);

static struct io_plan *write_json_done(struct io_conn *conn,
				       struct json_connection *jcon)
{
	membuf_consume(&jcon->outbuf, jcon->out_amount);

 	/* If we have more to write, do it now. */
 	if (membuf_num_elems(&jcon->outbuf))
		return write_json(conn, jcon);

	if (jcon->stop) {
		log_unusual(jcon->log, "JSON-RPC shutdown");
		/* Return us to toplevel lightningd.c */
		io_break(jcon->ld);
		return io_close(conn);
	}

	/* If command is done and we've output everything, wake read_json
	 * for next command. */
	if (!jcon->command)
		io_wake(conn);

	io_lock_release(jcon->lock);
	/* Wait for more output. */
	return io_out_wait(conn, jcon, locked_write_json, jcon);
}

static struct io_plan *write_json(struct io_conn *conn,
				  struct json_connection *jcon)
{
	jcon->out_amount = membuf_num_elems(&jcon->outbuf);
	return io_write(conn,
			membuf_elems(&jcon->outbuf), jcon->out_amount,
			write_json_done, jcon);
}

static struct io_plan *locked_write_json(struct io_conn *conn,
					   struct json_connection *jcon)
{
	return io_lock_acquire_out(conn, jcon->lock, write_json, jcon);
}

static struct io_plan *read_json(struct io_conn *conn,
				 struct json_connection *jcon)
{
	jsmntok_t *toks;
	bool valid, completed;

	if (jcon->len_read)
		log_io(jcon->log, LOG_IO_IN, "",
		       jcon->buffer + jcon->used, jcon->len_read);

	/* Resize larger if we're full. */
	jcon->used += jcon->len_read;
	if (jcon->used == tal_count(jcon->buffer))
		tal_resize(&jcon->buffer, jcon->used * 2);

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

	completed = parse_request(jcon, toks);

	/* Remove first {}. */
	memmove(jcon->buffer, jcon->buffer + toks[0].end,
		tal_count(jcon->buffer) - toks[0].end);
	jcon->used -= toks[0].end;

	/* If we haven't completed, wait for cmd completion. */
	jcon->len_read = 0;
	if (!completed) {
		tal_free(toks);
		return io_wait(conn, conn, read_json, jcon);
	}

	/* If we have more to process, try again.  FIXME: this still gets
	 * first priority in io_loop, so can starve others.  Hack would be
	 * a (non-zero) timer, but better would be to have io_loop avoid
	 * such livelock */
	if (jcon->used) {
		tal_free(toks);
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
	jcon->lock = io_lock_new(jcon);
	membuf_init(&jcon->outbuf,
		    tal_arr(jcon, char, 64), 64, membuf_tal_realloc);
	jcon->len_read = 0;
	jcon->command = NULL;

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
			 io_out_wait(conn, jcon, locked_write_json, jcon));
}

static struct io_plan *incoming_jcon_connected(struct io_conn *conn,
					       struct lightningd *ld)
{
	/* Lifetime of JSON conn is limited to fd connect time. */
	return jcon_connected(notleak(conn), ld);
}

void setup_jsonrpc(struct lightningd *ld, const char *rpc_filename)
{
	struct sockaddr_un addr;
	int fd, old_umask;

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

	log_debug(ld->log, "Listening on '%s'", rpc_filename);
	ld->rpc_listener = io_new_listener(ld->rpc_filename, fd, incoming_jcon_connected, ld);
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
