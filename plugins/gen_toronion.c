#include <arpa/inet.h>
#include <assert.h>
#include <ccan/array_size/array_size.h>
#include <ccan/cast/cast.h>
#include <ccan/err/err.h>
#include <ccan/intmap/intmap.h>
#include <ccan/io/io.h>
#include <ccan/json_out/json_out.h>
#include <ccan/rbuf/rbuf.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/str/hex/hex.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/tal/str/str.h>
#include <ccan/tal/str/str.h>
#include <common/amount.h>
#include <common/base64.h>
#include <common/bolt11.h>
#include <common/gossip_constants.h>
#include <common/pseudorand.h>
#include <common/type_to_string.h>
#include <common/type_to_string.h>
#include <common/utils.h>
#include <common/wireaddr.h>
#include <errno.h>
#include <fcntl.h>
#include <lightningd/log.h>
#include <netdb.h>
#include <netinet/in.h>
#include <plugins/libplugin.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <wire/onion_defs.h>


#define status_fmt(level, fmt, ...)					\
	do { printf((fmt) ,##__VA_ARGS__); printf("\n"); } while(0)


/* Public key of this node. */
static struct node_id my_id;
static unsigned int maxdelay_default;

static void tor_send_cmd(struct rbuf *rbuf, const char *cmd)
{
	//status_io(LOG_IO_OUT, "torcontrol", cmd, strlen(cmd));
	if (!write_all(rbuf->fd, cmd, strlen(cmd)))
		printf(
			      "Writing '%s' to Tor socket", cmd);

	//status_io(LOG_IO_OUT, "torcontrol", "\r\n", 2);
	if (!write_all(rbuf->fd, "\r\n", 2))
		printf(
			      "Writing CRLF to Tor socket");
}

static void *buf_resize(struct membuf *mb, void *buf, size_t len)
{
	tal_resize(&buf, len);
	return buf;
}


static char *tor_response_line(struct rbuf *rbuf)
{
	char *line;

	while ((line = rbuf_read_str(rbuf, '\n')) != NULL) {
		/* Weird response */
		if (!strstarts(line, "250 ") && !strstarts(line, "550 "))
		status_info("Tor gave unexpected response '%s'", line);

		/* Last line */
		if (strstarts(line, "250 "))
			break;

		return line + 4;
	}
	return NULL;
}

static char *tor_response_line_f(struct rbuf *rbuf)
{
	char *line;

	while ((line = rbuf_read_str(rbuf, '\n')) != NULL) {
		/* Weird response */
		if (!strstarts(line, "250 ") && !strstarts(line, "550 "))
		status_info("Tor gave unexpected response '%s'", line);

		/* Last line */
		if (strstarts(line, "250 ") || strstarts(line, "550 "))
			break;

		return line + 4;
	}
	return line + 4;
}


static void discard_remaining_response(struct rbuf *rbuf)
{
	while (tor_response_line(rbuf));
}




static char *make_fixed_onion(const tal_t *ctx,
				   struct rbuf *rbuf,
				   const struct wireaddr *local, const char *blob, u16 port)
{
	char *line;
	struct wireaddr *onion;
	char *blob64;
	char *name;

	blob64 =  b64_encode(tmpctx,(char *) blob, 64);

	tor_send_cmd(rbuf,
			   tal_fmt(tmpctx, "ADD_ONION ED25519-V3:%s Port=%d,%s Flags=DiscardPK",
					 blob64, port, "127.0.0.1:9735"/* fmt_wireaddr(tmpctx, local)*/));

	while ((line = tor_response_line_f(rbuf)) != NULL) {

		if (line && strstarts(line, "Onion address collision"))
			return NULL;

		if (!strstarts(line, "ServiceID="))
			continue;
		line += strlen("ServiceID=");
		/* Strip the trailing CR */
		if (strchr(line, '\r'))
			*strchr(line, '\r') = '\0';

		name = tal_fmt(ctx, "%s.onion", line);
		onion = tal(ctx, struct wireaddr);
		if (!parse_wireaddr(name, onion, DEFAULT_PORT, false, NULL))
			status_info(
				      "Tor gave bad onion name '%s'", name);
		status_info("New autotor service onion address: \"%s:%d\"", name, DEFAULT_PORT);
		discard_remaining_response(rbuf);
		return name;
	}
	return NULL;
}


static void negotiate_auth(struct rbuf *rbuf, const char *tor_password)
{
	char *line;

	tor_send_cmd(rbuf, "PROTOCOLINFO 1");

	while ((line = tor_response_line(rbuf)) != NULL) {
		const char *p;

		if (!strstarts(line, "AUTH METHODS="))
			continue;

		if (strstr(line, "NULL")) {
			discard_remaining_response(rbuf);
			tor_send_cmd(rbuf, "AUTHENTICATE");
			discard_remaining_response(rbuf);
			return;
		} else if (strstr(line, "HASHEDPASSWORD")
			   && strlen(tor_password)) {
			discard_remaining_response(rbuf);
			tor_send_cmd(rbuf,
				     tal_fmt(tmpctx, "AUTHENTICATE \"%s\"",
					     tor_password));
			discard_remaining_response(rbuf);
			return;
		} else if ((p = strstr(line, "COOKIEFILE=\"")) != NULL) {
			char *contents, *end;

			p += strlen("COOKIEFILE=\"");
			end = strstr(p, "\"");

			*end = '\0';

			contents = grab_file(tmpctx, p);
			if (!contents) {
				continue;
			}
			assert(tal_count(contents) != 0);
			discard_remaining_response(rbuf);
			tor_send_cmd(rbuf,
				     tal_fmt(tmpctx, "AUTHENTICATE %s",
					     tal_hexstr(tmpctx,
							contents,
							tal_count(contents)-1)));

			discard_remaining_response(rbuf);
			return;
		}
	}
}


/* Public key of this node. */
static struct node_id my_id;


static struct command_result *json_gen_toronion(struct command *cmd,
					     const char *buf,
					     const jsmntok_t *params)
{
	struct json_out *ret;
	const char *tor_password = "";
	int fd;
	const struct wireaddr *laddr;
	struct wireaddr service;
	struct addrinfo *ai_tor;
	struct rbuf rbuf;
	const char *buffer;
	const char *blob,*ip=NULL;
	char *onion;
	bool needed_dns = false;

	if (!param(cmd, buf, params,
		   p_req("params", param_string, &blob),
		   p_opt("ip", param_string, &ip), NULL))
			return command_param_failed();

	if (!parse_wireaddr((!ip ? "127.0.0.1:9151": ip),
				      &service, 9151,
				      &needed_dns,
				      NULL))
				       return command_param_failed();

	ai_tor = wireaddr_to_addrinfo(tmpctx, &service);

	fd = socket(ai_tor->ai_family, SOCK_STREAM, 0);
	if (fd < 0 )
		 err(1, "Creating stream socket for Tor");

	if (connect(fd, ai_tor->ai_addr, ai_tor->ai_addrlen) != 0) {
		err(1, "Connecting stream socket to Tor service");
	}

	buffer = tal_arr(tmpctx, char, rbuf_good_size(fd));
	rbuf_init(&rbuf, fd, (char *)buffer, tal_count(buffer), buf_resize+1);

	negotiate_auth(&rbuf, tor_password);
	onion  = make_fixed_onion(tmpctx, &rbuf, laddr, blob, 9735);

	close(fd);

	ret = json_out_new(NULL);
	json_out_start(ret, NULL, '{');
	json_out_start(ret, "onion_address", '[');
	json_out_start(ret, NULL, '{');
	json_out_addstr(ret, "address", tal_fmt(tmpctx,"%s", onion));
	json_out_addstr(ret, "from blob", tal_fmt(tmpctx,"%s", blob));
	json_out_addstr(ret, "base64 blob", tal_fmt(tmpctx,"%s", b64_encode(tmpctx,(char *) blob, 64)));

	json_out_end(ret, '}');
	json_out_end(ret, ']');
	json_out_end(ret, '}');

	return command_success_plugin(cmd, ret);
}



static void init(struct plugin_conn *rpc,
		  const char *buf UNUSED, const jsmntok_t *config UNUSED)
{
	const char *field;

	field = rpc_delve(tmpctx, "getinfo",
			  take(json_out_obj(NULL, NULL, NULL)), rpc, ".id");
	if (!node_id_from_hexstr(field, strlen(field), &my_id))
		plugin_err("getinfo didn't contain valid id: '%s'", field);

	field = rpc_delve(tmpctx, "listconfigs",
			  take(json_out_obj(NULL,
					    "config", "max-locktime-blocks")),
			  rpc, ".max-locktime-blocks");
	maxdelay_default = atoi(field);
}



static const struct plugin_command commands[] = { {
		"gen_toronion",
		"info",
		"Generate the onion",
		"Try so hard :-) but failed",
		json_gen_toronion
	}
};



int main(int argc, char *argv[])
{
	setup_locale();
	plugin_main(argv, init, PLUGIN_RESTARTABLE, commands, ARRAY_SIZE(commands), NULL);
}
