#ifndef LIGHTNING_PLUGINS_LIBPLUGIN_PAY_H
#define LIGHTNING_PLUGINS_LIBPLUGIN_PAY_H
#include "config.h"

#include <plugins/libplugin.h>

enum route_hop_style {
	ROUTE_HOP_LEGACY = 1,
	ROUTE_HOP_TLV = 2,
};

struct route_hop {
	struct short_channel_id channel_id;
	int direction;
	struct node_id nodeid;
	struct amount_msat amount;
	u32 delay;
	struct pubkey *blinding;
	enum route_hop_style style;
};

/* A parsed version of the possible outcomes that a sendpay / payment may
 * result in. */
struct payment_result {
};

/* Relevant information about a local channel so we can  exclude them early. */
struct channel_status {
};

/* Each payment goes through a number of steps that are always processed in
 * the same order, and some modifiers are called with the payment, and the
 * modifier's data before and after certain steps, allowing customization. The
 * following enum represents the normal workflow of processing a payment, and
 * is used by `payment_continue` to re-enter the state machine from a
 * modifier. The values are powers of two in order to make aggregating of
 * subtree states in the root easy.
 */
enum payment_step {
	PAYMENT_STEP_INITIALIZED = 1,

	/* We just called getroute and got a resulting route, allow modifiers
	 * to amend the route. */
	PAYMENT_STEP_GOT_ROUTE = 2,

	/* We just computed the onion payload, allow modifiers to amend,
	 * before constructing the onion packet. */
	PAYMENT_STEP_ONION_PAYLOAD = 4,

	/* The following states mean that the current payment failed, but a
	 * child payment is still running, and we can't say yet whether the
	 * overall payment will fail or succeed. */
	PAYMENT_STEP_SPLIT = 8,
	PAYMENT_STEP_RETRY = 16,

	/* The payment state-machine has terminated, these are the final
	 * states that a payment can be in. */
	PAYMENT_STEP_FAILED = 32,
	PAYMENT_STEP_SUCCESS = 64,
};

struct payment {
	/* The command that triggered this payment. */
	struct command *cmd;

	const char *json_buffer;
	const jsmntok_t *json_toks;

	/* The current phase we are in. */
	enum payment_step step;

	/* Real destination we want to route to */
	struct node_id *destination;

	/* Payment hash extracted from the invoice if any. */
	struct sha256 *payment_hash;

	u32 partid;

	/* Destination we should ask `getroute` for. This might differ from
	 * the above destination if we use rendez-vous routing of blinded
	 * paths to amend the route later in a mixin. */
	struct node_id  *getroute_destination;

	/* Target amount to be delivered at the destination */
	struct amount_msat amount;

	/* tal_arr of route_hops we decoded from the `getroute` call. Exposed
	 * here so it can be amended by mixins. */
	struct route_hop *route;

	struct channel_status *peer_channels;

	/* The blockheight at which the payment attempt was
	 * started.  */
	u32 start_block;

	struct timeabs start_time, end_time;
	struct timeabs deadline;

	struct amount_msat extra_budget;

	struct short_channel_id *exclusions;

	/* Tree structure of payments and subpayments. */
	struct payment *parent, **children;

	/* Null-terminated array of modifiers to apply to the payment. NULL
	 * terminated mainly so we can build a stack of modifiers at
	 * compile-time instead of allocating a list for each payment
	 * specifically. */
	struct payment_modifier **modifiers;
	void **modifier_data;
	int current_modifier;
};

struct payment_modifier {
	const char *name;
	void *(*data_init)(struct payment *p);
	void (*post_step_cb)(void *data, struct payment *p);
};

#define REGISTER_PAYMENT_MODIFIER(name, data_type, data_init_cb, step_cb)      \
	struct payment_modifier name##_pay_mod = {                             \
	    stringify(name),                                                   \
	    typesafe_cb_cast(void *(*)(struct payment *),                      \
			     data_type (*)(struct payment *), data_init_cb),   \
	    typesafe_cb_cast(void (*)(void *, struct payment *),               \
			     void (*)(data_type, struct payment *), step_cb),  \
	};

/* List of globally available payment modifiers. */
extern struct payment_modifier dummy_pay_mod;

struct payment *payment_new(tal_t *ctx, struct command *cmd,
			    struct payment *parent,
			    struct payment_modifier **mods);

void payment_start(struct payment *p);
void payment_continue(struct payment *p);

#endif /* LIGHTNING_PLUGINS_LIBPLUGIN_PAY_H */
