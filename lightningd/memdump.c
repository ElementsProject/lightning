/* Only possible if we're in developer mode. */
#ifdef DEVELOPER
#include <lightningd/jsonrpc.h>
#include <stdio.h>

static void json_add_ptr(struct json_result *response, const char *name,
			 const void *ptr)
{
	char ptrstr[STR_MAX_CHARS(void *)];
	sprintf(ptrstr, "%p", ptr);
	json_add_string(response, name, ptrstr);
}

static void add_memdump(struct json_result *response,
			const char *name, const tal_t *root,
			struct command *cmd)
{
	const tal_t *i;

	json_array_start(response, name);
	for (i = tal_first(root); i; i = tal_next(i)) {
		const char *name = tal_name(i);

		/* Don't try to dump this command! */
		if (i == cmd || i == cmd->jcon)
			continue;

		/* Don't dump logs, we know they grow. */
		if (name && streq(name, "struct log_book"))
			continue;

		json_object_start(response, NULL);
		json_add_ptr(response, "parent", tal_parent(i));
		json_add_ptr(response, "value", i);
		if (name)
			json_add_string(response, "label", name);

		if (tal_first(i))
			add_memdump(response, "children", i, cmd);
		json_object_end(response);
	}
	json_array_end(response);
}

static void json_memdump(struct command *cmd,
			 const char *buffer UNNEEDED,
			 const jsmntok_t *params UNNEEDED)
{
	struct json_result *response = new_json_result(cmd);

	add_memdump(response, NULL, NULL, cmd);

	command_success(cmd, response);
}

static const struct json_command dev_memdump_command = {
	"dev-memdump",
	json_memdump,
	"Dump the memory objects currently used",
	"Debugging tool for memory leaks"
};
AUTODATA(json_command, &dev_memdump_command);
#endif /* DEVELOPER */
