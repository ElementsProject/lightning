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

struct routetracker *new_routetracker(const tal_t *ctx, struct payment *payment);
void routetracker_cleanup(struct routetracker *routetracker);

bool routetracker_have_results(struct routetracker *routetracker);

/* The payment has a list of route that have "returned". Calling this function
 * payment will look through that list and process those routes' results:
 *	- update the commited amounts,
 *	- update the uncertainty network,
 *	- and free the allocated memory. */
void payment_collect_results(struct payment *payment,
			     struct preimage **payment_preimage,
			     enum jsonrpc_errcode *final_error,
			     const char **final_msg);

/* Sends a sendpay request for this route. */
struct command_result *route_sendpay_request(struct command *cmd,
					     struct route *route TAKES,
					     struct payment *payment);

struct command_result *notification_sendpay_failure(struct command *cmd,
						    const char *buf,
						    const jsmntok_t *params);

struct command_result *notification_sendpay_success(struct command *cmd,
						    const char *buf,
						    const jsmntok_t *params);

/* Notify the tracker that this route has failed. */
void route_failure_register(struct routetracker *routetracker,
			    struct route *route);

// FIXME: double-check that we actually get one notification for each sendpay,
// ie. that after some time we don't have yet pending sendpays for old failed or
// successful payments that we havent processed because we haven't received the
// notification

#endif /* LIGHTNING_PLUGINS_RENEPAY_ROUTETRACKER_H */
