#ifndef LIGHTNING_PLUGINS_RENEPAY_SUCCESS_H
#define LIGHTNING_PLUGINS_RENEPAY_SUCCESS_H

/* success:
 * This handles the success of a route. We send the information learned to
 * the uncertainty network, we flag the payment as PAYMENT_SUCCESS and we move
 * to the finish section. */

#include "config.h"
#include <common/json_command.h>

struct command_result *notification_sendpay_success(struct command *cmd,
						    const char *buf,
						    const jsmntok_t *params);

#endif /* LIGHTNING_PLUGINS_RENEPAY_SUCCESS_H */
