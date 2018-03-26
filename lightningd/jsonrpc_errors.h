/* lightningd/jsonrpc_errors.h
 * Lists error codes for JSON-RPC.
 */
#ifndef LIGHTNING_LIGHTNINGD_JSONRPC_ERRORS_H
#define LIGHTNING_LIGHTNINGD_JSONRPC_ERRORS_H
#include "config.h"

/* Standard errors defined by JSON-RPC 2.0 standard */
#define JSONRPC2_INVALID_REQUEST	-32600
#define JSONRPC2_METHOD_NOT_FOUND	-32601
#define JSONRPC2_INVALID_PARAMS		-32602

/* Errors from `pay`, `sendpay`, or `waitsendpay` commands */
#define PAY_IN_PROGRESS			200
#define PAY_RHASH_ALREADY_USED		201
#define PAY_UNPARSEABLE_ONION		202
#define PAY_DESTINATION_PERM_FAIL	203
#define PAY_TRY_OTHER_ROUTE		204
#define PAY_ROUTE_NOT_FOUND		205
#define PAY_ROUTE_TOO_EXPENSIVE		206
#define PAY_INVOICE_EXPIRED             207
#define PAY_NO_SUCH_PAYMENT		208
#define PAY_UNSPECIFIED_ERROR		209
#define PAY_STOPPED_RETRYING		210

#endif /* LIGHTNING_LIGHTNINGD_JSONRPC_ERRORS_H */
