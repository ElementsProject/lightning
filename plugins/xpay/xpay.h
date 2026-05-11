#ifndef LIGHTNING_PLUGINS_XPAY_XPAY_H
#define LIGHTNING_PLUGINS_XPAY_XPAY_H
#include "config.h"
#include <stdbool.h>

struct plugin;
struct sha256;

/* Are we still attempting this payment?  If so, we won't list is as failed. */
bool attempt_ongoing(struct plugin *plugin, const struct sha256 *payment_hash);

#endif /* LIGHTNING_PLUGINS_XPAY_XPAY_H */
