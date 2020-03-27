#include <ccan/array_size/array_size.h>
#include <plugins/libplugin.h>

static void init(struct plugin *p, const char *buf UNUSED,
		 const jsmntok_t *config UNUSED)
{
}

static const struct plugin_command commands[] = {
};


int main(int argc, char *argv[])
{
	setup_locale();
	plugin_main(argv, init, PLUGIN_RESTARTABLE, commands, ARRAY_SIZE(commands),
	            NULL, 0, NULL, 0, NULL);
}
