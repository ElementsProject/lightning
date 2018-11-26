#ifndef LIGHTNING_LIGHTNINGD_BITCOIN_RPC_H
#define LIGHTNING_LIGHTNINGD_BITCOIN_RPC_H
#include "config.h"
#include "bitcoind.h"
#include <ccan/list/list.h>
#include <ccan/time/time.h>

enum RPCExitStatus {
	RPC_SUCCESS,
	RPC_ERROR,
	RPC_FAIL
};

/* HTTP status codes */
#define	HTTP_BAD_REQUEST 400
#define	HTTP_UNAUTHORIZED 401
#define	HTTP_FORBIDDEN 403
#define	HTTP_NOT_FOUND 404
#define	HTTP_BAD_METHOD 405
#define	HTTP_INTERNAL_SERVER_ERROR 500
#define	HTTP_SERVICE_UNAVAILABLE 503

/* Bitcoin RPC error codes */
enum RPCErrorCode {
	RPC_INVALID_PARAMETER =
		-8, /* Invalid, missing or duplicate parameter */
	RPC_CLIENT_IN_INITIAL_DOWNLOAD =
		-10, /* Still downloading initial blocks        */
	RPC_VERIFY_ALREADY_IN_CHAIN =
		-27, /* Transaction already in chain            */
	RPC_IN_WARMUP = -28, /* Client still warming up                 */

	RPC_TRANSACTION_ALREADY_IN_CHAIN = RPC_VERIFY_ALREADY_IN_CHAIN,
};

struct bitcoin_rpc {
	struct list_node list;
	struct bitcoind *bitcoind;
	enum RPCExitStatus exitstatus;
	int errorcode;
	bool rpc_error_ok;
	const char **args;
	char *cmd;
	char *request;
	struct timeabs start;
	enum bitcoind_prio prio;
	char *output;
	size_t output_bytes;
	bool (*process)(struct bitcoin_rpc *);
	void *cb;
	void *cb_arg;
	const jsmntok_t *resulttok;
	const jsmntok_t *errortok;
	void *base;
	void *evcon;
	void *response;
	bool finished;
	struct bitcoin_rpc **stopper;
};

bool rpc_request(struct bitcoin_rpc *brpc);

#endif /* LIGHTNING_LIGHTNINGD_BITCOIN_RPC_H */
