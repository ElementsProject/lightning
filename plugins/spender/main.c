#include "config.h"
#include <plugins/spender/fundchannel.h>
#include <plugins/spender/multifundchannel.h>
#include <plugins/spender/multiwithdraw.h>
#include <plugins/spender/openchannel.h>

/*~ The spender plugin contains various commands that handle
 * spending from the onchain wallet.  */

static
const char *spender_init(struct plugin *p, const char *b, const jsmntok_t *t)
{
	openchannel_init(p, b, t);
	/* whatever_init(p, b, t); */
	return NULL;
}

int main(int argc, char **argv)
{
	struct plugin_command *commands;
	struct plugin_notification *notifs;

	setup_locale();

	commands = tal_arr(NULL, struct plugin_command, 0);

	tal_expand(&commands, multiwithdraw_commands, num_multiwithdraw_commands);
	tal_expand(&commands, fundchannel_commands, num_fundchannel_commands);
	tal_expand(&commands, multifundchannel_commands, num_multifundchannel_commands);
	/* tal_expand(&commands, whatever_commands, num_whatever_commands); */

	notifs = tal_arr(NULL, struct plugin_notification, 0);
	tal_expand(&notifs, openchannel_notifs, num_openchannel_notifs);

	plugin_main(argv, &spender_init, PLUGIN_STATIC, true,
		    NULL,
		    take(commands), tal_count(commands),
		    take(notifs), tal_count(notifs),
		    NULL, 0,
		    NULL, 0, /* Notification topics */
		    NULL);

	return 0;
}
