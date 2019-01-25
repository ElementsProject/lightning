#include <arpa/inet.h>
#include <ccan/err/err.h>
#include <ccan/str/str.h>
#include <ccan/tal/path/path.h>
#include <ccan/tal/str/str.h>
#include <common/configdir.h>
#include <common/json.h>
#include <common/utils.h>
#include <common/version.h>
#include <lightningd/bitcoin_rpc.h>
#include <lightningd/bitcoind.h>
#include <lightningd/log.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>

#define COOKIEAUTH_FILE ".cookie"

struct http_header {
	int status;
	int content_length;
};

static char encoding_table[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'};
static int mod_table[] = {0, 2, 1};

static char *base64_encode(const char *data, size_t input_len,
			   size_t *output_len)
{
	*output_len = 4 * ((input_len + 2) / 3);

	char *encoded_data = tal_arrz(NULL, char, *output_len + 1);
	if (encoded_data == NULL)
		return NULL;

	int i = 0, j = 0;
	for (i = 0, j = 0; i < input_len;) {
		uint32_t octet_a = i < input_len ? (unsigned char)data[i++] : 0;
		uint32_t octet_b = i < input_len ? (unsigned char)data[i++] : 0;
		uint32_t octet_c = i < input_len ? (unsigned char)data[i++] : 0;

		uint32_t triple =
		    (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

		encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
		encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
		encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
		encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
	}

	for (i = 0; i < mod_table[input_len % 3]; i++)
		encoded_data[*output_len - 1 - i] = '=';

	return encoded_data;
}

static struct http_header *parse_http_header(char *header_buffer)
{
	char *tmp_str;
	char **lines = NULL;
	unsigned int i;
	struct http_header *header = tal_arrz(NULL, struct http_header, 1);

	lines =
	    tal_strsplit(header_buffer, header_buffer, "\r\n", STR_NO_EMPTY);
	for (i = 0; lines[i] != NULL; i++) {
		if (strstr(lines[i], "Content-Lengt")) {
			tmp_str = strstr(lines[i], ": ");
			header->content_length = strtol(tmp_str + 2, NULL, 10);
			break;
		} else if (strstr(lines[i], "HTTP")) {
			tmp_str = strstr(lines[i], " ");
			header->status = strtol(tmp_str + 1, NULL, 10);
		}
	}

	tal_free(header_buffer);
	return header;
}

static void json_parse_reply(char *resp, size_t output_bytes,
			     struct bitcoin_rpc *brpc)
{
	jsmntok_t *toks;
	const jsmntok_t *resulttok, *errortok;
	bool valid;
	struct bitcoind *bitcoind = brpc->bitcoind;

	log_debug(bitcoind->log, "RPC: response %s", resp);

	toks = json_parse_input(brpc, resp, output_bytes, &valid);
	if (!toks) {
		log_unusual(bitcoind->log, "RPC: returned invalid json result,"
					   " is this a pruned node?");
		brpc->exitstatus = RPC_FAIL;
		return;
	}

	if (toks[0].type != JSMN_OBJECT) {
		log_unusual(bitcoind->log, "RPC gave non-object (%s)?", resp);
		brpc->exitstatus = RPC_FAIL;
		return;
	}

	errortok = json_get_member(resp, toks, "error");
	if (errortok) {
		brpc->errortok = errortok;
		if (json_tok_is_null(resp, errortok)) {
			resulttok = json_get_member(resp, toks, "result");
			/* no result-object */
			if (!resulttok || json_tok_is_null(resp, resulttok))
				brpc->exitstatus = RPC_ERROR;
			else {
				brpc->exitstatus = RPC_SUCCESS;
				brpc->resulttok = resulttok;
			}
		} else {
			brpc->exitstatus = RPC_ERROR;
			resulttok = json_get_member(resp, errortok, "code");
			if (resulttok) {
				const char *errorcode = tal_strndup(
				    resp, brpc->output + resulttok->start,
				    resulttok->end - resulttok->start);
				brpc->errorcode = atoi(errorcode);
			}
		}
	} else {
		/* 'error' must be returned in response */
		brpc->exitstatus = RPC_ERROR;
	}
}

static bool handle_http_header(char *header_buffer, struct bitcoin_rpc *brpc)
{
	struct bitcoind *bitcoind = brpc->bitcoind;
	struct http_header *header = parse_http_header(header_buffer);

	if (header->status == HTTP_UNAUTHORIZED) {
		brpc->exitstatus = RPC_FAIL;
		log_unusual(bitcoind->log, "RPC: Authorization failed: "
					   "Incorrect rpcuser or rpcpassword");
		tal_free(header);
		return false;
	} else if (header->status >= HTTP_BAD_REQUEST &&
		   header->status != HTTP_BAD_REQUEST &&
		   header->status != HTTP_NOT_FOUND &&
		   header->status != HTTP_INTERNAL_SERVER_ERROR) {
		brpc->exitstatus = RPC_FAIL;
		log_unusual(bitcoind->log, "RPC: server returned HTTP error %d",
			    header->status);
		tal_free(header);
		return false;
	}

	if (header->content_length == 0) {
		brpc->exitstatus = RPC_FAIL;
		log_unusual(bitcoind->log,
			    "Received response length is zero!! Exiting!!\n");
		tal_free(header);
		return false;
	}

	tal_free(header);
	return true;
}

bool handle_http_response(char *recv_buffer, struct bitcoin_rpc *brpc)
{
	int resp_offset;
	char *header_buffer;
	struct bitcoind *bitcoind = brpc->bitcoind;

	if (brpc->output_bytes == 0) {
		brpc->exitstatus = RPC_FAIL;
		log_unusual(bitcoind->log, "Recv buffer size is 0");
		return false;
	}

	resp_offset = (int)(strstr(recv_buffer, "\r\n\r\n") - recv_buffer) + 4;

	brpc->output_bytes -= resp_offset;
	brpc->output =
	    tal_strndup(brpc, recv_buffer + resp_offset, brpc->output_bytes);

	header_buffer = tal_strndup(brpc, recv_buffer, resp_offset);
	tal_free(recv_buffer);

	if (!handle_http_header(header_buffer, brpc))
		return false;

	json_parse_reply(brpc->output, brpc->output_bytes, brpc);

	return true;
}

static bool get_auth_cookie(struct bitcoind *bitcoind, char **cookie_out)
{
	FILE *fp;
	char *line = NULL;
	size_t len = 0;
	char *filename;

	if (bitcoind->rpccookiefile != NULL)
		filename = bitcoind->rpccookiefile;
	else
		filename =
		    path_join(tmpctx, bitcoind->datadir, COOKIEAUTH_FILE);

	fp = fopen(filename, "r");
	if (fp == NULL) {
		tal_free(filename);
		return false;
	}

	if (getline(&line, &len, fp) == -1) {
		tal_free(filename);
		return false;
	}

	if (line) {
		*cookie_out = tal_arrz(NULL, char, len + 1);
		memcpy(*cookie_out, line, len);
		free(line);
	}

	fclose(fp);
	return true;
}

bool init_rpc_header(struct bitcoind *bitcoind)
{
	size_t out_len = 0;
	char *base64;
	char *rpcusercolonpass = NULL;

	/* Get credentials */
	if (bitcoind->rpcpass == NULL) {
		/* Try fall back to cookie-based authentication if no password
		 * is provided */
		if (!get_auth_cookie(bitcoind, &rpcusercolonpass)) {
			log_unusual(
			    bitcoind->log,
			    "Could not locate RPC credentials. No "
			    "authentication cookie "
			    "could be found, and RPC password is not set. See "
			    "--bitcoin-rpcpassword and "
			    "--bitcoin-rpccookiefile");
			return false;
		}
	} else {
		rpcusercolonpass = tal_fmt(NULL, "%s:%s", bitcoind->rpcuser,
					   bitcoind->rpcpass);
	}

	base64 =
	    base64_encode(rpcusercolonpass, strlen(rpcusercolonpass), &out_len);

	bitcoind->rpcheader =
	    tal_fmt(bitcoind,
		    "POST / HTTP/1.1\r\nHost: %s\r\nConnection: "
		    "close\r\nAuthorization: Basic %s\r\n",
		    bitcoind->rpcconnect, base64);

	tal_free(rpcusercolonpass);
	tal_free(base64);

	return true;
}

bool rpc_request(struct bitcoin_rpc *brpc)
{
	int socket_fd;
	struct sockaddr_in rpc_server_addr_in;
	struct bitcoind *bitcoind = brpc->bitcoind;
	struct timeval timeout;

	socket_fd = socket(AF_INET, SOCK_STREAM, 0);
	bzero(&rpc_server_addr_in, sizeof(rpc_server_addr_in));
	rpc_server_addr_in.sin_family = AF_INET;
	rpc_server_addr_in.sin_port = htons(bitcoind->rpcport);
	inet_pton(AF_INET, (const char *)(bitcoind->rpcconnect),
		  &rpc_server_addr_in.sin_addr);

	timeout.tv_sec = bitcoind->rpcclienttimeout;
	timeout.tv_usec = 0;

	if (setsockopt(socket_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout,
		       sizeof(timeout)) < 0)
		log_unusual(bitcoind->log, "RPC: setsockopt failed\n");

	if (setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
		       sizeof(timeout)) < 0)
		log_unusual(bitcoind->log, "RPC: setsockopt failed\n");

	if (setsockopt(socket_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout,
		       sizeof(timeout)) < 0)
		log_unusual(bitcoind->log, "RPC: setsockopt failed\n");

	if (connect(socket_fd, (struct sockaddr *)&rpc_server_addr_in,
		    sizeof(rpc_server_addr_in)) < 0)
		log_unusual(bitcoind->log, "RPC: connect rpc server failed\n");

	char *get_command =
	    tal_fmt(brpc, "%sContent-Length: %zu\r\n\r\n%s\r\n",
		    bitcoind->rpcheader, strlen(brpc->request), brpc->request);

	if (send(socket_fd, get_command, strlen(get_command) + 1, 0) < 0) {
		log_unusual(bitcoind->log,
			    "RPC: failed to send rpc_request!\n");
		return false;
	}

	brpc->fd = socket_fd;
	tal_free(get_command);
	return true;
}
