#ifndef LIGHTNING_PLUGINS_OFFERS_OFFER_H
#define LIGHTNING_PLUGINS_OFFERS_OFFER_H
#include "config.h"
#include <plugins/libplugin.h>

struct command_result *json_offer(struct command *cmd,
				  const char *buffer,
				  const jsmntok_t *params);

struct command_result *json_invoicerequest(struct command *cmd,
					   const char *buffer,
					   const jsmntok_t *params);
#endif /* LIGHTNING_PLUGINS_OFFERS_OFFER_H */
