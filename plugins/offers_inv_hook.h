#ifndef LIGHTNING_PLUGINS_OFFERS_INV_HOOK_H
#define LIGHTNING_PLUGINS_OFFERS_INV_HOOK_H
#include "config.h"
#include <plugins/libplugin.h>

/* We got an onionmessage with an invoice!  replytok could be NULL. */
struct command_result *handle_invoice(struct command *cmd,
				      const char *buf,
				      const jsmntok_t *invtok,
				      const jsmntok_t *replytok);
#endif /* LIGHTNING_PLUGINS_OFFERS_INV_HOOK_H */
