#ifndef LIGHTNING_PLUGINS_RENEPAY_FINISH_H
#define LIGHTNING_PLUGINS_RENEPAY_FINISH_H

/* finish:
 * This handles the end of a payment either as a PAYMENT_SUCCESS
 * or a PAYMENT_FAIL. */

#include "config.h"
#include <plugins/renepay/payment.h>

struct command_result *payment_finish(struct payment *p);

#endif /* LIGHTNING_PLUGINS_RENEPAY_FINISH_H */
