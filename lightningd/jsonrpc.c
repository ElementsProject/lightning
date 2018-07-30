/* Code for JSON_RPC API */
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
#include <common/json_escaped.h>
#include <common/memleak.h>
#include <common/version.h>
#include <common/wallet_tx.h>
#include <common/wireaddr.h>
#include <errno.h>
#include <fcntl.h>
#include <lightningd/chaintopology.h>
#include <lightningd/json.h>
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

struct json_output {
	struct list_node list;
	const char *json;
};

/* jcon and cmd have separate lifetimes: we detach them on either destruction */
static void destroy_jcon(struct json_connection *jcon)
{
	struct command *cmd;

	list_for_each(&jcon->commands, cmd, list) {
		log_debug(jcon->log, "Abandoning command");
		cmd->jcon = NULL;
	}

	/* Make sure this happens last! */
	tal_free(jcon->log);
}

static void destroy_cmd(struct command *cmd)
{
	if (cmd->jcon)
		list_del_from(&cmd->jcon->commands, &cmd->list);
}

static void json_help(struct command *cmd,
		      const char *buffer, const jsmntok_t *params);

static const struct json_command help_command = {
	"help",
	json_help,
	"List available commands, or give verbose help on one command.",

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
	struct json_result *response = new_json_result(cmd);

	/* This can't have closed yet! */
	cmd->jcon->stop = true;
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
	struct json_result *response = new_json_result(cmd);
	struct sha256 secret;

	if (!param(cmd, buffer, params,
		   p_req("secret", json_tok_sha256, &secret),
		   NULL))
		return;

	/* Hash in place. */
	sha256(&secret, &secret, sizeof(secret));
	json_object_start(response, NULL);
	json_add_hex(response, "rhash", &secret, sizeof(secret));
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
	struct json_result *response = new_json_result(cmd);

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

static void json_help(struct command *cmd,
		      const char *buffer, const jsmntok_t *params)
{
	unsigned int i;
	struct json_result *response = new_json_result(cmd);
	struct json_command **cmdlist = get_cmdlist();
	const jsmntok_t *cmdtok;

	if (!param(cmd, buffer, params,
		   p_opt_tok("command", &cmdtok),
		   NULL))
		return;

	json_object_start(response, NULL);
	if (cmdtok) {
		for (i = 0; i < num_cmdlist; i++) {
			if (json_tok_streq(buffer, cmdtok, cmdlist[i]->name)) {
				if (!cmdlist[i]->verbose)
					json_add_string(response,
							"verbose",
							"HELP! Please contribute"
							" a description for this"
							" command!");
				else {
					struct json_escaped *esc;

					esc = json_escape(NULL,
							  cmdlist[i]->verbose);
					json_add_escaped_string(response,
								"verbose",
								take(esc));
				}
				goto done;
			}
		}
		command_fail(cmd, JSONRPC2_METHOD_NOT_FOUND,
			     "Unknown command '%.*s'",
			     cmdtok->end - cmdtok->start,
			     buffer + cmdtok->start);
		return;
	}

	json_array_start(response, "help");
	for (i = 0; i < num_cmdlist; i++) {
		json_add_object(response,
				"command", JSMN_STRING,
				cmdlist[i]->name,
				"description", JSMN_STRING,
				cmdlist[i]->description,
				NULL);
	}
	json_array_end(response);

done:
	json_object_end(response);
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

static void json_done(struct json_connection *jcon,
		      struct command *cmd,
		      const char *json TAKES)
{
	struct json_output *out = tal(jcon, struct json_output);
	out->json = tal_strdup(out, json);

	tal_free(cmd);

	/* Queue for writing, and wake writer. */
	list_add_tail(&jcon->output, &out->list);
	io_wake(jcon);
}

static void connection_complete_ok(struct json_connection *jcon,
				   struct command *cmd,
				   const char *id,
				   const struct json_result *result)
{
	assert(id != NULL);
	assert(result != NULL);

	/* This JSON is simple enough that we build manually */
	json_done(jcon, cmd, take(tal_fmt(jcon,
					  "{ \"jsonrpc\": \"2.0\", "
					  "\"result\" : %s,"
					  " \"id\" : %s }\n",
					  json_result_string(result), id)));
}

static void connection_complete_error(struct json_connection *jcon,
				      struct command *cmd,
				      const char *id,
				      const char *errmsg,
				      int code,
				      const struct json_result *data)
{
	struct json_escaped *esc;
	const char *data_str;

	esc = json_escape(tmpctx, errmsg);
	if (data)
		data_str = tal_fmt(tmpctx, ", \"data\" : %s",
				   json_result_string(data));
	else
		data_str = "";

	assert(id != NULL);

	json_done(jcon, cmd, take(tal_fmt(tmpctx,
					  "{ \"jsonrpc\": \"2.0\", "
					  " \"error\" : "
					  "{ \"code\" : %d,"
					  " \"message\" : \"%s\"%s },"
					  " \"id\" : %s }\n",
					  code,
					  esc->s,
					  data_str,
					  id)));
}

struct json_result *null_response(const tal_t *ctx)
{
	struct json_result *response;

	response = new_json_result(ctx);
	json_object_start(response, NULL);
	json_object_end(response);
	return response;
}

static bool cmd_in_jcon(const struct json_connection *jcon,
			const struct command *cmd)
{
	const struct command *i;

	list_for_each(&jcon->commands, i, list)
		if (i == cmd)
			return true;
	return false;
}

void command_success(struct command *cmd, struct json_result *result)
{
	struct json_connection *jcon = cmd->jcon;

	if (!jcon) {
		log_debug(cmd->ld->log,
			    "Command returned result after jcon close");
		tal_free(cmd);
		return;
	}
	assert(cmd_in_jcon(jcon, cmd));
	connection_complete_ok(jcon, cmd, cmd->id, result);
}

static void command_fail_v(struct command *cmd,
			   int code,
			   const struct json_result *data,
			   const char *fmt, va_list ap)
{
	char *error;
	struct json_connection *jcon = cmd->jcon;

	if (!jcon) {
		log_debug(cmd->ld->log,
			  "%s: Command failed after jcon close",
			  cmd->json_cmd->name);
		tal_free(cmd);
		return;
	}

	error = tal_vfmt(cmd, fmt, ap);

	/* cmd->json_cmd can be NULL, if we're failing for command not found! */
	log_debug(jcon->log, "Failing %s: %s",
		  cmd->json_cmd ? cmd->json_cmd->name : "invalid cmd",
		  error);

	assert(cmd_in_jcon(jcon, cmd));
	connection_complete_error(jcon, cmd, cmd->id, error, code, data);
}

void command_fail(struct command *cmd, int code, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	command_fail_v(cmd, code, NULL, fmt, ap);
	va_end(ap);
}

void command_fail_detailed(struct command *cmd,
			   int code, const struct json_result *data,
			   const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	command_fail_v(cmd, code, data, fmt, ap);
	va_end(ap);
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
	return connection_complete_error(jcon, NULL, id, error,
					 JSONRPC2_INVALID_REQUEST, NULL);
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

	/* This is a convenient tal parent for duration of command
	 * (which may outlive the conn!). */
	c = tal(jcon->ld->rpc_listener, struct command);
	c->jcon = jcon;
	c->ld = jcon->ld;
	c->pending = false;
	c->id = tal_strndup(c,
			    json_tok_contents(jcon->buffer, id),
			    json_tok_len(id));
	list_add(&jcon->commands, &c->list);
	tal_add_destructor(c, destroy_cmd);

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

	c->json_cmd = find_cmd(jcon->buffer, method);
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

	/* If they didn't complete it, they must call command_still_pending */
	if (cmd_in_jcon(jcon, c))
		assert(c->pending);
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
			io_break(jcon->ld);
			return io_close(conn);
		}

		/* Wait for more output. */
		return io_out_wait(conn, jcon, write_json, jcon);
	}

	jcon->outbuf = tal_steal(jcon, out->json);
	tal_free(out);

	log_io(jcon->log, LOG_IO_OUT, "", jcon->outbuf, strlen(jcon->outbuf));
	return io_write(conn,
			jcon->outbuf, strlen(jcon->outbuf), write_json, jcon);
}

static struct io_plan *read_json(struct io_conn *conn,
				 struct json_connection *jcon)
{
	jsmntok_t *toks;
	bool valid;

	log_io(jcon->log, LOG_IO_IN, "",
	       jcon->buffer + jcon->used, jcon->len_read);

	/* Resize larger if we're full. */
	jcon->used += jcon->len_read;
	if (jcon->used == tal_count(jcon->buffer))
		tal_resize(&jcon->buffer, jcon->used * 2);

again:
	toks = json_parse_input(jcon->buffer, jcon->used, &valid);
	if (!toks) {
		if (!valid) {
			log_unusual(jcon->ld->log,
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
	tal_free(toks);

	/* See if we can parse the rest. */
	goto again;

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
	jcon->ld = ld;
	jcon->used = 0;
	jcon->buffer = tal_arr(jcon, char, 64);
	jcon->stop = false;
	list_head_init(&jcon->commands);

	/* We want to log on destruction, so we free this in destructor. */
	jcon->log = new_log(ld->log_book, ld->log_book, "%sjcon fd %i:",
			    log_prefix(ld->log), io_conn_fd(conn));
	list_head_init(&jcon->output);

	tal_add_destructor(jcon, destroy_jcon);

	return io_duplex(conn,
			 io_read_partial(conn, jcon->buffer,
					 tal_count(jcon->buffer),
					 &jcon->len_read, read_json, jcon),
			 write_json(conn, jcon));
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

	if (streq(rpc_filename, ""))
		return;

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

bool json_tok_newaddr(const char *buffer, const jsmntok_t *tok, bool *is_p2wpkh)
{
	if (json_tok_streq(buffer, tok, "p2sh-segwit"))
		*is_p2wpkh = false;
	else if (json_tok_streq(buffer, tok, "bech32"))
		*is_p2wpkh = true;
	else
		return false;
	return true;
}

bool json_tok_wtx(struct wallet_tx * tx, const char * buffer,
                  const jsmntok_t *sattok, u64 max)
{
        if (json_tok_streq(buffer, sattok, "all")) {
                tx->all_funds = true;
		tx->amount = max;
        } else if (!json_tok_u64(buffer, sattok, &tx->amount)) {
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
