#ifndef LIGHTNING_PLUGINS_RENEPAY_SUCCESS_H
#define LIGHTNING_PLUGINS_RENEPAY_SUCCESS_H

#include "config.h"
#include <common/json_command.h>

struct command_result *notification_sendpay_success(struct command *cmd,
						    const char *buf,
						    const jsmntok_t *params);

#endif /* LIGHTNING_PLUGINS_RENEPAY_SUCCESS_H */
