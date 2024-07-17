#ifndef LIGHTNING_PLUGINS_OFFERS_INV_HOOK_H
#define LIGHTNING_PLUGINS_OFFERS_INV_HOOK_H
#include "config.h"
#include <plugins/libplugin.h>

/* We got an onionmessage with an invoice!  reply_path could be NULL. */
struct command_result *handle_invoice(struct command *cmd,
				      const u8 *invbin,
				      struct blinded_path *reply_path STEALS,
				      const struct secret *secret);

#endif /* LIGHTNING_PLUGINS_OFFERS_INV_HOOK_H */
