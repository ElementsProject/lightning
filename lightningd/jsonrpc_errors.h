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

/* Uncategorized error.
 * FIXME: This should be replaced in all places
 * with a specific error code, and then removed.
 */
#define LIGHTNINGD                      -1

/* Developer error in the parameters to param() call */
#define PARAM_DEV_ERROR                 -2

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

/* `fundchannel` or `withdraw` errors */
#define FUND_MAX_EXCEEDED               300
#define FUND_CANNOT_AFFORD              301
#define FUND_OUTPUT_IS_DUST             302

/* Errors from `invoice` command */
#define INVOICE_LABEL_ALREADY_EXISTS	900
#define INVOICE_PREIMAGE_ALREADY_EXISTS	901

#endif /* LIGHTNING_LIGHTNINGD_JSONRPC_ERRORS_H */
