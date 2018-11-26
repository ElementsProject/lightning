#include <ccan/err/err.h>
#include <ccan/str/str.h>
#include <ccan/tal/path/path.h>
#include <ccan/tal/str/str.h>
#include <common/configdir.h>
#include <common/json.h>
#include <common/utils.h>
#include <common/version.h>
#include <event2/buffer.h>
#include <event2/event.h>
#include <event2/http.h>
#include <event2/keyvalq_struct.h>
#include <lightningd/bitcoin_rpc.h>
#include <lightningd/bitcoind.h>
#include <lightningd/log.h>

#define DEFAULT_HTTP_CLIENT_TIMEOUT 900
#define COOKIEAUTH_FILE ".cookie"

static char encoding_table[] = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
				 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
				 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
				 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
				 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
				 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
				 'w', 'x', 'y', 'z', '0', '1', '2', '3',
				 '4', '5', '6', '7', '8', '9', '+', '/' };
static int mod_table[] = { 0, 2, 1 };

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

/** libevent event log callback */
static void libevent_log_cb(int severity, const char *msg)
{
#ifndef EVENT_LOG_ERR // EVENT_LOG_ERR was added in 2.0.19; but before then _EVENT_LOG_ERR existed.
#define EVENT_LOG_ERR _EVENT_LOG_ERR
#endif
	/* Ignore everything other than errors */
	printf("libevent error: %s\n", msg);
}

static const char *http_errorstring(int code)
{
	switch (code) {
#if LIBEVENT_VERSION_NUMBER >= 0x02010300
	case EVREQ_HTTP_TIMEOUT:
		return "timeout reached";
	case EVREQ_HTTP_EOF:
		return "EOF reached";
	case EVREQ_HTTP_INVALID_HEADER:
		return "error while reading header, or invalid header";
	case EVREQ_HTTP_BUFFER_ERROR:
		return "error encountered while reading or writing";
	case EVREQ_HTTP_REQUEST_CANCEL:
		return "request was canceled";
	case EVREQ_HTTP_DATA_TOO_LONG:
		return "response body is larger than allowed";
#endif
	default:
		return "unknown";
	}
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

static void json_parse_reply(char *resp, size_t output_bytes,
			     struct bitcoin_rpc *brpc)
{
	jsmntok_t *toks;
	const jsmntok_t *resulttok, *errortok;
	bool valid;
	struct bitcoind *bitcoind = brpc->bitcoind;

	log_debug(bitcoind->log, "RPC: response %s", resp);

	brpc->output = resp;
	brpc->output_bytes = output_bytes;

	toks = json_parse_input(resp, output_bytes, &valid);
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

static void http_request_done(struct evhttp_request *req, void *ctx)
{
	struct bitcoin_rpc *brpc = (struct bitcoin_rpc *)ctx;
	struct bitcoind *bitcoind = brpc->bitcoind;
	char *resp;
	int status;

	brpc->finished = true;

	status = evhttp_request_get_response_code(req);
	if (status == 0) {
		brpc->exitstatus = RPC_FAIL;
		log_unusual(
			bitcoind->log,
			"RPC: Could not connect to the server %s:%d, "
			"make sure the bitcoind server is running and that you "
			"are connecting to the correct RPC port",
			brpc->bitcoind->rpcconnect, brpc->bitcoind->rpcport);
		return;
	} else if (status == HTTP_UNAUTHORIZED) {
		brpc->exitstatus = RPC_FAIL;
		log_unusual(
			bitcoind->log,
			"RPC: Authorization failed: Incorrect rpcuser or rpcpassword");
		return;
	} else if (status >= HTTP_BAD_REQUEST && status != HTTP_BAD_REQUEST &&
		   status != HTTP_NOT_FOUND &&
		   status != HTTP_INTERNAL_SERVER_ERROR) {
		brpc->exitstatus = RPC_FAIL;
		log_unusual(bitcoind->log, "RPC: server returned HTTP error %d",
			    status);
		return;
	}

	struct evbuffer *buf = evhttp_request_get_input_buffer(req);
	if (buf) {
		size_t size = evbuffer_get_length(buf);
		char *data = (char *)evbuffer_pullup(buf, size);
		if (data) {
			resp = tal_arrz(brpc, char, (size + 1));
			memcpy(resp, data, size);
			evbuffer_drain(buf, size);
			json_parse_reply(resp, size, brpc);
		} else {
			brpc->exitstatus = RPC_FAIL;
		}
	}
}

#if LIBEVENT_VERSION_NUMBER >= 0x02010300
static void http_error_cb(enum evhttp_request_error err, void *ctx)
{
	struct bitcoin_rpc *brpc = (struct bitcoin_rpc *)ctx;
	log_unusual(brpc->bitcoind->log, "RPC: error code %d - \"%s\"", err,
		  http_errorstring(err));
}
#endif

bool rpc_request(struct bitcoin_rpc *brpc)
{
	struct bitcoind *bitcoind = brpc->bitcoind;

	event_set_log_callback(&libevent_log_cb);

#ifdef LIBEVENT_DBG
	event_enable_debug_logging(EVENT_DBG_ALL);
	event_enable_debug_mode();
#endif

	/* Obtain event base */
	struct event_base *base = event_base_new();
	if (base == NULL) {
		log_unusual(bitcoind->log, "create event base failed");
		return false;
	}
	brpc->base = (void *)base;

	struct evhttp_connection *evcon =
		evhttp_connection_base_new(base, NULL,
					   (const char *)(bitcoind->rpcconnect),
					   bitcoind->rpcport);
	if (evcon == NULL) {
		log_unusual(bitcoind->log, "create http connect failed");
		return false;
	}
	evhttp_connection_set_timeout(evcon, DEFAULT_HTTP_CLIENT_TIMEOUT);
	brpc->evcon = (void *)evcon;

	struct evhttp_request *req =
		evhttp_request_new(http_request_done, (void *)brpc);
	if (req == NULL) {
		log_unusual(bitcoind->log, "create http request failed");
		return false;
	}
#if LIBEVENT_VERSION_NUMBER >= 0x02010300
	evhttp_request_set_error_cb(req, http_error_cb);
#endif

	/* Get credentials */
	char *rpcusercolonpass = NULL;
	if (bitcoind->rpcpass == NULL) {
		/* Try fall back to cookie-based authentication if no password is provided */
		if (!get_auth_cookie(bitcoind, &rpcusercolonpass)) {
			log_unusual(
				bitcoind->log,
				"Could not locate RPC credentials. No authentication cookie "
				"could be found, and RPC password is not set. See "
				"--bitcoin-rpcpassword and --bitcoin-rpccookiefile");
			return false;
		}
	} else {
		rpcusercolonpass = tal_fmt(NULL, "%s:%s", bitcoind->rpcuser,
					   bitcoind->rpcpass);
	}

	struct evkeyvalq *output_headers =
		evhttp_request_get_output_headers(req);
	evhttp_add_header(output_headers, "Host", bitcoind->rpcconnect);
	evhttp_add_header(output_headers, "Connection", "close");

	size_t out_len = 0;
	char *base64 = base64_encode(rpcusercolonpass, strlen(rpcusercolonpass),
				     &out_len);
	char *head = tal_strcat(NULL, "Basic ", take(base64));
	evhttp_add_header(output_headers, "Authorization", head);
	tal_free(rpcusercolonpass);
	tal_free(head);

	/* Attach request data */
	struct evbuffer *output_buffer = evhttp_request_get_output_buffer(req);
	evbuffer_add(output_buffer, brpc->request, strlen(brpc->request));

	char *endpoint = "/";
	int r = evhttp_make_request(evcon, req, EVHTTP_REQ_POST, endpoint);
	if (r != 0) {
		log_unusual(bitcoind->log, "send http request failed");
		return false;
	}

	return true;
}
