#include <ccan/array_size/array_size.h>
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
	}
};

int main(int argc, char *argv[])
{
	setup_locale();
	plugin_main(argv, init, PLUGIN_RESTARTABLE, commands, ARRAY_SIZE(commands),
	            NULL, 0, NULL, 0,
		    plugin_option("name",
				  "string",
				  "Who to say hello to.",
				  charp_option, &name_option),
		    NULL);
}
