#ifndef LIGHTNING_PLUGINS_OFFERS_INVREQ_HOOK_H
#define LIGHTNING_PLUGINS_OFFERS_INVREQ_HOOK_H
#include "config.h"
#include <plugins/libplugin.h>

extern u32 cltv_final;

/* We got an onionmessage with an invreq! */
struct command_result *handle_invoice_request(struct command *cmd,
					      const char *buf,
					      const jsmntok_t *invreqtok,
					      const jsmntok_t *replytok);
#endif /* LIGHTNING_PLUGINS_OFFERS_INVREQ_HOOK_H */
