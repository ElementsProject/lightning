#ifndef LIGHTNING_PLUGINS_RENEPAY_ROUTEFAIL_H
#define LIGHTNING_PLUGINS_RENEPAY_ROUTEFAIL_H

/* This module provides the state machine for handling route failures. */

#include "config.h"
#include <plugins/renepay/route.h>

struct command_result *routefail_start(struct command *cmd,
				       struct payment *payment,
				       struct route *route);

#endif /* LIGHTNING_PLUGINS_RENEPAY_ROUTEFAIL_H */
