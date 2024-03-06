#ifndef LIGHTNING_PLUGINS_RENEPAY_UNETWORK_H
#define LIGHTNING_PLUGINS_RENEPAY_UNETWORK_H
#include "config.h"
#include <ccan/tal/tal.h>
#include <common/gossmap.h>
#include <plugins/renepay/chan_extra.h>
#include <plugins/renepay/route.h>

struct unetwork {
	// TODO
};

void unetwork_route_success(struct unetwork *unetwork,
			    const struct route *route);
void unetwork_remove_htlcs(struct unetwork *unetwork,
			   const struct route *route);

struct unetwork *unetwork_new(const tal_t *ctx);

#endif /* LIGHTNING_PLUGINS_RENEPAY_UNETWORK_H */
