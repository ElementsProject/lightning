#ifndef LIGHTNING_PLUGINS_RENEPAY_SENDPAY_H
#define LIGHTNING_PLUGINS_RENEPAY_SENDPAY_H

#include "config.h"

struct command_result *json_renesendpay(struct command *cmd,
					const char *buf,
					const jsmntok_t *params);

#endif /* LIGHTNING_PLUGINS_RENEPAY_SENDPAY_H */
