#include "lightningd/plugin_hook.h"

static struct plugin_hook *plugin_hook_by_name(const char *name)
{
	static struct plugin_hook **hooks = NULL;
	static size_t num_hooks;
	if (!hooks)
		hooks = autodata_get(hooks, &num_hooks);

	for (size_t i=0; i<num_hooks; i++)
		if (streq(hooks[i]->name, name))
			return hooks[i];
	return NULL;
}

bool plugin_hook_register(struct plugin *plugin, const char *method)
{
	struct plugin_hook *hook = plugin_hook_by_name(method);
	if (!hook) {
		/* No such hook name registered */
		return false;
	} else if (hook->plugin != NULL) {
		/* Another plugin already registered for this name */
		return false;
	}
	hook->plugin = plugin;
	return true;
}

/* FIXME(cdecker): Remove dummy hook, once we have a real one */
REGISTER_PLUGIN_HOOK(hello, NULL, void *, NULL, void *, NULL, void *);

void plugin_hook_call_(struct plugins *plugins, const struct plugin_hook *hook,
		       void *payload, void *cb_arg)
{
}
