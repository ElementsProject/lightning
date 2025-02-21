#include "config.h"
#include <plugins/libplugin.h>
#include <plugins/renepay/utils.h>

struct renepay *get_renepay(struct plugin *plugin)
{
	return plugin_get_data(plugin, struct renepay);
}

struct rpcbatch {
	size_t num_remaining;
	struct command *cmd;
	struct command_result *(*finalcb)(struct command *, void *);
	void *arg;
};

struct rpcbatch_aux {
	struct rpcbatch *batch;
	void *arg;
	struct command_result *(*cb)(struct command *cmd, const char *,
				     const char *, const jsmntok_t *, void *);
	struct command_result *(*errcb)(struct command *cmd, const char *,
					const char *, const jsmntok_t *,
					void *);
};

struct rpcbatch *
rpcbatch_new_(struct command *cmd,
	      struct command_result *(*finalcb)(struct command *, void *),
	      void *arg)
{
	struct rpcbatch *batch = tal(cmd, struct rpcbatch);
	batch->num_remaining = 0;
	batch->cmd = cmd;
	batch->finalcb = finalcb;
	batch->arg = arg;
	return batch;
}

static struct command_result *batch_one_complete(struct rpcbatch *batch)
{
	assert(batch->num_remaining);
	if (--batch->num_remaining != 0)
		return command_still_pending(batch->cmd);
	struct command *cmd = batch->cmd;
	void *arg = batch->arg;
	struct command_result *(*finalcb)(struct command *, void *) =
	    batch->finalcb;
	tal_free(batch);
	return finalcb(cmd, arg);
}

static struct command_result *
batch_one_success(struct command *cmd, const char *method, const char *buf,
		  const jsmntok_t *result, struct rpcbatch_aux *aux)
{
	/* Little hack to get the value of "complete" from libplugin. */
	struct command_result *complete = command_param_failed();
	/* If this frees stuff (e.g. fails), just return */
	if (aux->cb && aux->cb(cmd, method, buf, result, aux->arg) == complete)
		return complete;
	struct rpcbatch *batch = aux->batch;
	tal_free(aux);
	return batch_one_complete(batch);
}

static struct command_result *
batch_one_failed(struct command *cmd, const char *method, const char *buf,
		 const jsmntok_t *result, struct rpcbatch_aux *aux)
{
	/* Little hack to get the value of "complete" from libplugin. */
	struct command_result *complete = command_param_failed();
	/* If this frees stuff (e.g. fails), just return */
	if (aux->errcb &&
	    aux->errcb(cmd, method, buf, result, aux->arg) == complete)
		return complete;
	struct rpcbatch *batch = aux->batch;
	tal_free(aux);
	return batch_one_complete(batch);
}

struct out_req *add_to_rpcbatch_(
    struct rpcbatch *batch, const char *cmdname,
    struct command_result *(*cb)(struct command *, const char *, const char *,
				 const jsmntok_t *, void *arg),
    struct command_result *(*errcb)(struct command *, const char *,
				    const char *, const jsmntok_t *, void *arg),
    void *arg)
{
	batch->num_remaining++;
	struct rpcbatch_aux *aux = tal(batch, struct rpcbatch_aux);
	aux->arg = arg;
	aux->batch = batch;
	aux->cb = cb;
	aux->errcb = errcb;
	return jsonrpc_request_start(batch->cmd, cmdname, batch_one_success,
				     batch_one_failed, aux);
}

/* Runs finalcb immediately if batch is empty. */
struct command_result *rpcbatch_done(struct rpcbatch *batch)
{
	/* Same path as completion */
	batch->num_remaining++;
	return batch_one_complete(batch);
}
