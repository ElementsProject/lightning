#ifndef LIGHTNING_PLUGINS_RENEPAY_FAILURE_H
#define LIGHTNING_PLUGINS_RENEPAY_FAILURE_H

/* failure:
 * This handles the failure of a route. We send the information learned to
 * the uncertainty network and we decide whether to try again the payment or
 * finish the payment with the flag PAYMENT_FAIL. */

#include "config.h"
#include <common/json_command.h>

struct command_result *notification_sendpay_failure(struct command *cmd,
						    const char *buf,
						    const jsmntok_t *params);

#endif /* LIGHTNING_PLUGINS_RENEPAY_FAILURE_H */
