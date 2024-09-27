#ifndef LIGHTNING_PLUGINS_RENEPAY_ROUTETRACKER_H
#define LIGHTNING_PLUGINS_RENEPAY_ROUTETRACKER_H

/* This module provides entry points for the management of a route thread. */

#include "config.h"
#include <plugins/renepay/route.h>

struct routetracker{
	/* Routes that we compute and are kept here before sending them. */
	struct route **computed_routes;

	/* Routes that we sendpay and are still waiting for rpc returning
	 * success. */
	struct route_map *sent_routes;

	/* Routes that have concluded (either SENDPAY_FAILED or
	 * SENDPAY_COMPLETE). */
	struct route **finalized_routes;
};

/* Data used to make RPC calls after a sendpay notification was received. */
struct route_notification {
	struct command *cmd;
	struct payment *payment;
	struct route *route;
};

struct command_result *route_unreserve(struct route_notification *r);

struct routetracker *new_routetracker(const tal_t *ctx, struct payment *payment);
void routetracker_cleanup(struct routetracker *routetracker);

bool routetracker_have_results(struct routetracker *routetracker);

/* The payment has a list of route that have "returned". Calling this function
 * payment will look through that list and process those routes' results:
 *	- update the commited amounts,
 *	- update the uncertainty network,
 *	- and free the allocated memory. */
void tal_collect_results(const tal_t *ctx, struct routetracker *routetracker,
			 struct preimage **payment_preimage,
			 enum jsonrpc_errcode *final_error,
			 const char **final_msg);

void route_pending_register(struct routetracker *routetracker,
			    struct route *route);

struct command_result *notification_sendpay_failure(struct command *cmd,
						    const char *buf,
						    const jsmntok_t *params);

struct command_result *notification_sendpay_success(struct command *cmd,
						    const char *buf,
						    const jsmntok_t *params);

#endif /* LIGHTNING_PLUGINS_RENEPAY_ROUTETRACKER_H */
