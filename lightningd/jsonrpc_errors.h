/* lightningd/jsonrpc_errors.h
 * Lists error codes for JSON-RPC.
 */
#ifndef LIGHTNING_LIGHTNINGD_JSONRPC_ERRORS_H
#define LIGHTNING_LIGHTNINGD_JSONRPC_ERRORS_H
#include "config.h"

/* Standad errors defined by JSON-RPC 2.0 standard */
#define JSONRPC2_INVALID_REQUEST	-32600
#define JSONRPC2_METHOD_NOT_FOUND	-32601
#define JSONRPC2_INVALID_PARAMS		-32602

#endif /* !defined (LIGHTNING_LIGHTNINGD_JSONRPC_ERRORS_H) */
