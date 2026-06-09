#ifndef LIGHTNING_PLUGINS_XPAY_LISTPAYS_H
#define LIGHTNING_PLUGINS_XPAY_LISTPAYS_H
#include "config.h"
#include <common/json_parse_simple.h>

struct command;

/* listpays was in the original pay plugin: with those functions deprecated,
 * we moved it into xpay for want of a better home */
struct command_result *json_listpays(struct command *cmd,
				     const char *buf,
				     const jsmntok_t *params);
#endif /* LIGHTNING_PLUGINS_XPAY_LISTPAYS_H */
