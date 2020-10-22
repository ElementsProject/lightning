#ifndef LIGHTNING_PLUGINS_SPENDER_OPENCHANNEL_H
#define LIGHTNING_PLUGINS_SPENDER_OPENCHANNEL_H
#include "config.h"
#include <ccan/tal/tal.h>

struct wally_psbt;

extern const struct plugin_notification openchannel_notifs[];
extern const size_t num_openchannel_notifs;

/* register_mfc - Register to listen for incoming
 * 		  peer signature notifications */
void register_mfc(struct multifundchannel_command *mfc);

struct command_result *
openchannel_init_dest(struct multifundchannel_destination *dest);

void openchannel_init(struct plugin *p, const char *b,
		      const jsmntok_t *t);

struct command_result *
perform_openchannel_update(struct multifundchannel_command *mfc);

struct command_result *
check_sigs_ready(struct multifundchannel_command *mfc);

struct command_result *
perform_openchannel_signed(struct multifundchannel_command *mfc);

#endif /* LIGHTNING_PLUGINS_SPENDER_OPENCHANNEL_H */
