#include <ccan/array_size/array_size.h>
#include <ccan/tal/str/str.h>
#include <common/json_stream.h>
#include <plugins/libplugin.h>


const char *name_option;


static struct command_result *json_helloworld(struct command *cmd,
					      const char *buf,
					      const jsmntok_t *params)
{
	const char *name;

	if (!param(cmd, buf, params,
		   p_opt("name", param_string, &name),
		   NULL))
		return command_param_failed();

	if (!name)
		name = name_option ? name_option : tal_strdup(tmpctx, "world");

	return command_success_str(cmd, tal_fmt(tmpctx, "hello %s", name));
}

static struct command_result *
json_peer_connected(struct command *cmd,
		    const char *buf,
		    const jsmntok_t *params)
{
	const jsmntok_t *peertok, *idtok;
	struct json_stream *response;

	peertok = json_get_member(buf, params, "peer");
	assert(peertok);
	idtok = json_get_member(buf, peertok, "id");
	assert(idtok);
	plugin_log(cmd->plugin, LOG_INFORM, "%s peer_connected",
		   json_strdup(tmpctx, buf, idtok));

	response = jsonrpc_stream_success(cmd);
	json_add_string(response, "result", "continue");

	return command_finished(cmd, response);
}

static void json_connected(struct command *cmd,
			   const char *buf,
			   const jsmntok_t *params)
{
	const jsmntok_t *idtok = json_get_member(buf, params, "id");
	assert(idtok);
	plugin_log(cmd->plugin, LOG_INFORM, "%s connected",
		   json_strdup(tmpctx, buf, idtok));
}

static struct command_result *testrpc_cb(struct command *cmd,
					 const char *buf,
					 const jsmntok_t *params,
					 void *cb_arg UNUSED)
{
	int i = 0;
	const jsmntok_t *t;
	struct json_stream *response;

	response = jsonrpc_stream_success(cmd);
	json_for_each_obj(i, t, params)
		json_add_tok(response, json_strdup(tmpctx, buf, t), t+1, buf);

	return command_finished(cmd, response);
}

static struct command_result *json_testrpc(struct command *cmd,
					   const char *buf,
					   const jsmntok_t *params)
{
	struct out_req *req;

	if (!param(cmd, buf, params, NULL))
		return command_param_failed();

	req = jsonrpc_request_start(cmd->plugin, cmd, "getinfo", testrpc_cb,
				    testrpc_cb, NULL);
	return send_outreq(cmd->plugin, req);
}

static void init(struct plugin *p,
		  const char *buf UNUSED, const jsmntok_t *config UNUSED)
{
	plugin_log(p, LOG_DBG, "test_libplugin initialised!");
}

static const struct plugin_command commands[] = { {
		"helloworld",
		"utils",
		"Say hello to the world.",
		"Returns 'hello world' by default, 'hello {name}' if the name"
		" option was set, and 'hello {name}' if the name parameter "
		"was passed (takes over the option)",
		json_helloworld,
	},
	{
		"testrpc",
		"utils",
		"Makes a simple getinfo call, to test rpc socket.",
		"",
		json_testrpc,
	}
};

static const struct plugin_hook hooks[] = { {
		"peer_connected",
		json_peer_connected,
	}
};

static const struct plugin_notification notifs[] = { {
		"connect",
		json_connected,
	}
};

int main(int argc, char *argv[])
{
	setup_locale();
	plugin_main(argv, init, PLUGIN_RESTARTABLE, true, NULL,
		    commands, ARRAY_SIZE(commands),
	            notifs, ARRAY_SIZE(notifs), hooks, ARRAY_SIZE(hooks),
		    plugin_option("name",
				  "string",
				  "Who to say hello to.",
				  charp_option, &name_option),
		    NULL);
}
