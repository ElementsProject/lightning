#ifndef LIGHTNING_PLUGINS_RENEPAY_UTILS_H
#define LIGHTNING_PLUGINS_RENEPAY_UTILS_H

#include "config.h"

struct renepay *get_renepay(struct plugin *plugin);

struct rpcbatch;

struct rpcbatch *
rpcbatch_new_(struct command *cmd,
	      struct command_result *(*finalcb)(struct command *, void *),
	      void *arg);

/* Returns a new rpcbatch object. This is meant to process multiple RPC calls
 * and execute a callback function after all of them have returned.
 *
 * @cmd: command involved in all RPC requests
 * @finalcb: after all RPCs have returned this function is called
 * @arg: argument passed to finalcb
 * */
#define rpcbatch_new(cmd, finalcb, arg)                                        \
	rpcbatch_new_((cmd),                                                   \
		      typesafe_cb_preargs(struct command_result *, void *,     \
					  (finalcb), (arg),                    \
					  struct command *command),            \
		      (arg))

struct out_req *add_to_rpcbatch_(
    struct rpcbatch *batch, const char *cmdname,
    struct command_result *(*cb)(struct command *, const char *, const char *,
				 const jsmntok_t *, void *arg),
    struct command_result *(*errcb)(struct command *, const char *,
				    const char *, const jsmntok_t *, void *arg),
    void *arg);

/* Append a new RPC request to this batch.
 *
 * @batch: RPC request batch
 * @cmdname: RPC name
 * @cb: callback function on success
 * @errcb: callback function on failure
 * @arg: callback functions argument
 * */
#define add_to_rpcbatch(batch, cmdname, cb, errcb, arg)                        \
	add_to_rpcbatch_(                                                      \
	    (batch), (cmdname),                                                \
	    typesafe_cb_preargs(struct command_result *, void *, (cb), (arg),  \
				struct command *command, const char *method,   \
				const char *buf, const jsmntok_t *result),     \
	    typesafe_cb_preargs(struct command_result *, void *, (errcb),      \
				(arg), struct command *command,                \
				const char *method, const char *buf,           \
				const jsmntok_t *result),                      \
	    (arg))

struct command_result *rpcbatch_done(struct rpcbatch *batch);

#endif /* LIGHTNING_PLUGINS_RENEPAY_UTILS_H */
