#ifndef LIGHTNING_PLUGINS_LIBPLUGIN_PAY_H
#define LIGHTNING_PLUGINS_LIBPLUGIN_PAY_H
#include "config.h"

#include <common/bolt11.h>
#include <common/route.h>
#include <plugins/libplugin.h>
#include <wire/onion_wire.h>

struct legacy_payload {
	struct short_channel_id scid;
	struct amount_msat forward_amt;
	u32 outgoing_cltv;
};

/* struct holding the information necessary to call createonion */
struct createonion_hop {
	struct node_id pubkey;

	enum route_hop_style style;
	struct tlv_tlv_payload *tlv_payload;
	struct legacy_payload *legacy_payload;
};

struct createonion_request {
	struct createonion_hop *hops;
	u8 *assocdata;
	struct secret *session_key;
};

/* States returned by listsendpays, waitsendpay, etc. */
enum payment_result_state {
	PAYMENT_PENDING,
	PAYMENT_COMPLETE,
	PAYMENT_FAILED,
};

/* A parsed version of the possible outcomes that a sendpay / payment may
 * result in. It excludes the redundant fields such as payment_hash and partid
 * which are already present in the `struct payment` itself. */
struct payment_result {
	/* DB internal id */
	u64 id;
	u32 partid;
	enum payment_result_state state;
	struct amount_msat amount_sent;
	struct preimage *payment_preimage;
	u32 code;
	const char* failcodename;
	enum onion_wire failcode;
	const u8 *raw_message;
	const char *message;
	u32 *erring_index;
	struct node_id *erring_node;
	struct short_channel_id *erring_channel;
	int *erring_direction;
};

/* Information about channels we inferred from a) looking at our channels, and
 * b) from failures encountered during attempts to perform a payment. These
 * are attached to the root payment, since that information is
 * global. Attempts update the estimated channel capacities when starting, and
 * get remove on failure. Success keeps the capacities, since the capacities
 * changed due to the successful HTLCs. */
struct channel_hint {
	struct short_channel_id_dir scid;

	/* Upper bound on remove channels inferred from payment failures. */
	struct amount_msat estimated_capacity;

	/* Is the channel enabled? */
	bool enabled;

	/* True if we are one endpoint of this channel */
	bool local;

	/* How many more htlcs can we send over this channel? Only set if this
	 * is a local channel, because those are the channels we have exact
	 * numbers on, and they are the bottleneck onto the network. */
	u16 htlc_budget;
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

	/* Something went wrong with the route returned by the
	previous step, so retry, but do not rerun the INITIALIZED
	modifiers. */
	PAYMENT_STEP_RETRY_GETROUTE = 3,

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

/* Just a container to collect a subtree result so we can summarize all
 * sub-payments and return a reasonable result to the caller of `pay` */
struct payment_tree_result {
	/* OR of all the leafs in the subtree. */
	enum payment_step leafstates;

	/* OR of all the inner nodes and leaf nodes. */
	enum payment_step treestates;

	struct amount_msat sent;

	/* Preimage if any of the attempts succeeded. */
	struct preimage *preimage;

	u32 attempts;

	/* Pointer to the failure that caused the payment to fail. We just
	 * take the one with the highest failcode, since that happen to match
	 * the severity of the error. */
	struct payment_result *failure;
};

struct getroute_request {
	struct node_id *destination;
	struct amount_msat amount;
	u32 cltv;
	u32 max_hops;

	/* Riskfactor milionths */
	u64 riskfactorppm;
};

struct payment_constraints {
	/* Maximum remaining fees we're willing to pay to complete this
	 * (sub-)payment. This is modified by a route being applied of by
	 * modifiers that use some of the budget. */
	struct amount_msat fee_budget;

	/* Maximum end-to-end CLTV delta we're willing to wait for this
	 * (sub-)payment to complete. */
	u32 cltv_budget;
};

struct payment {
	/* The command that triggered this payment. Only set for the root
	 * payment. */
	struct command *cmd;
	struct plugin *plugin;
	struct list_node list;
	struct node_id *local_id;

	const char *json_buffer;
	const jsmntok_t *json_toks;

	/* The current phase we are in. */
	enum payment_step step;

	/* Real destination we want to route to */
	struct node_id *destination;
	/* Do we know for sure that this supports OPT_VAR_ONION? */
	bool destination_has_tlv;

	/* Payment hash extracted from the invoice if any. */
	struct sha256 *payment_hash;

	/* Payment secret, from the invoice if any. */
	struct secret *payment_secret;

	u32 partid;
	u32 next_partid;

	/* Destination we should ask `getroute` for. This might differ from
	 * the above destination if we use rendez-vous routing of blinded
	 * paths amend the route later in a mixin. */
	struct getroute_request *getroute;

	struct createonion_request *createonion_request;
	struct createonion_response *createonion_response;

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

	/* Constraints the state machine and modifiers needs to maintain. */
	struct payment_constraints constraints;

	/* Copy of the above constraints inherited to sub-payments
	 * automatically. This is mainly so we don't have to unapply changes
	 * to the constraints when retrying or splitting. The copy is made in
	 * `payment_start` so they can be adjusted until then. */
	struct payment_constraints *start_constraints;

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

	/* Information from the invoice. */
	u32 min_final_cltv_expiry;
	struct route_info **routes;
	const u8 *features;

	/* tal_arr of channel_hints we incrementally learn while performing
	 * payment attempts. */
	struct channel_hint *channel_hints;
	struct node_id *excluded_nodes;

	/* Optional temporarily excluded channels/nodes (i.e. this routehint) */
	struct node_id *temp_exclusion;

	struct payment_result *result;

	/* Did something happen that will cause all future attempts to fail?
	 * This usually means that the final node reported that it can't be
	 * reached, or in MPP payments there are no more paths we can
	 * attempt. Modifiers need to leave failures alone once this is set to
	 * true. Set only on the root payment. */
	bool abort;

	/* Serialized bolt11/12 string, kept attachd to the root so we can filter
	 * by the invoice. */
	const char *invstring;

	/* If this is paying a local offer, this is the one (sendpay ensures we
	 * don't pay twice for single-use offers) */
	struct sha256 *local_offer_id;

	/* Textual explanation of why this payment was attempted. */
	const char *why;

	const char *label;

	/* Human readable explanation of why this payment failed. */
	const char *failreason;

	/* If a failed getroute call can be retried for this payment. Allows
	 * us for example to signal to any retry modifier that we can retry
	 * despite getroute not returning a usable route. This can be the case
	 * if we switch any of the parameters such as destination or
	 * amount. */
	bool failroute_retry;

	/* A unique id for the root of this payment.  */
	u64 id;

	/* A short description of the route of this payment.  */
	char *routetxt;

	/* The maximum number of parallel outgoing HTLCs we will allow.
	 * If unset, the maximum is based on the number of outgoing HTLCs.
	 * This only applies for the root payment, and is ignored on non-root
	 * payments.
	 * Clients of the paymod system MUST NOT modify it, and individual
	 * paymods MUST interact with it only via the payment_max_htlcs
	 * and payment_lower_max_htlcs functions.
	 */
	u32 max_htlcs;

	/* A human readable error message that is used as a top-level
	 * explanation if a payment is aborted. */
	char *aborterror;
};

struct payment_modifier {
	const char *name;
	void *(*data_init)(struct payment *p);
	void (*post_step_cb)(void *data, struct payment *p);
};

void *payment_mod_get_data(const struct payment *payment,
			   const struct payment_modifier *mod);

#define REGISTER_PAYMENT_MODIFIER(name, data_type, data_init_cb, step_cb)      \
	struct payment_modifier name##_pay_mod = {                             \
	    stringify(name),                                                   \
	    typesafe_cb_cast(void *(*)(struct payment *),                      \
			     data_type (*)(struct payment *), data_init_cb),   \
	    typesafe_cb_cast(void (*)(void *, struct payment *),               \
			     void (*)(data_type, struct payment *), step_cb),  \
	};

/* The UNUSED marker is used to shut some compilers up. */
#define REGISTER_PAYMENT_MODIFIER_HEADER(name, data_type)                      \
	extern struct payment_modifier name##_pay_mod;                         \
	UNUSED static inline data_type *payment_mod_##name##_get_data(         \
	    const struct payment *p)                                           \
	{                                                                      \
		return payment_mod_get_data(p, &name##_pay_mod);               \
	}


struct retry_mod_data {
	int retries;
};

struct routehints_data {
	/* What we did about routehints (if anything) */
	const char *routehint_modifications;

	/* Array of routehints to try. */
	struct route_info **routehints;

	/* Current routehint, if any. */
	struct route_info *current_routehint;

	/* Position of the current routehint in the routehints
	 * array. Inherited on retry (and possibly incremented),
	 * reset to 0 on split. */
	int offset;
	/* Base of the current routehint.
	 * This is randomized to start routehints at a random point
	 * on each split, to reduce the chances of multiple splits
	 * going to the same routehint.
	 * The sum of base + offset is used as the index into the
	 * routehints array (wraps around).
	 * offset is used to determine if we have run out of
	 * routehints, base is used for randomization.
	 */
	int base;

	/* We modify the CLTV in the getroute call, so we need to remember
	 * what the final cltv delta was so we re-apply it correctly. */
	u32 final_cltv;

	/* Is the destination reachable without any routehints? */
	bool destination_reachable;
};

struct exemptfee_data {
	/* Amounts below this amount will get their fee limit raised to
	 * exemptfee, i.e., we're willing to pay twice exemptfee to get this
	 * payment through. */
	struct amount_msat amount;
};

struct shadow_route_data {
#if DEVELOPER
	bool use_shadow;
#endif
	struct payment_constraints constraints;
	struct node_id destination;
	struct route_hop *route;

	/* multi-part payments require the sum of parts to be the exact
	 * amount, so we allow the payment flow to opt out of fuzzing the
	 * amount. */
	bool fuzz_amount;
};

struct direct_pay_data {
	/* If we have a direct channel remember it, so we can check each
	 * attempt against the channel hints. */
	struct short_channel_id_dir *chan;
};

struct presplit_mod_data {
	bool disable;
};

struct adaptive_split_mod_data {
	bool disable;
	u32 htlc_budget;
};

/* List of globally available payment modifiers. */
REGISTER_PAYMENT_MODIFIER_HEADER(retry, struct retry_mod_data);
REGISTER_PAYMENT_MODIFIER_HEADER(routehints, struct routehints_data);
REGISTER_PAYMENT_MODIFIER_HEADER(exemptfee, struct exemptfee_data);
REGISTER_PAYMENT_MODIFIER_HEADER(shadowroute, struct shadow_route_data);
REGISTER_PAYMENT_MODIFIER_HEADER(directpay, struct direct_pay_data);
extern struct payment_modifier waitblockheight_pay_mod;
REGISTER_PAYMENT_MODIFIER_HEADER(presplit, struct presplit_mod_data);
REGISTER_PAYMENT_MODIFIER_HEADER(adaptive_splitter, struct adaptive_split_mod_data);

/* For the root payment we can seed the channel_hints with the result from
 * `listpeers`, hence avoid channels that we know have insufficient capacity
 * or are disabled. We do this only for the root payment, to minimize the
 * overhead. */
REGISTER_PAYMENT_MODIFIER_HEADER(local_channel_hints, void);
/* The payee might be less well-connected than ourselves.
 * This paymod limits the number of HTLCs based on the number of channels
 * we detect the payee to have, in order to not exhaust the number of HTLCs
 * each of those channels can bear.  */
REGISTER_PAYMENT_MODIFIER_HEADER(payee_incoming_limit, void);

struct payment *payment_new(tal_t *ctx, struct command *cmd,
			    struct payment *parent,
			    struct payment_modifier **mods);

void payment_start(struct payment *p);
void payment_continue(struct payment *p);

/**
 * Set the payment to the current step.
 *
 * This must be used by modifiers if they want to skip to a specific step. It
 * ensures that the internal state is reset correctly and that all modifier
 * callbacks are called once `payment_continue` is called again.
 */
void payment_set_step(struct payment *p, enum payment_step newstep);


/* Fails a partial payment and continues with the core flow. */
void payment_fail(struct payment *p, const char *fmt, ...) PRINTF_FMT(2,3);

/* Fails a payment process by setting the root payment to
 * aborted. This will cause all subpayments to terminate as soon as
 * they can, and sets the root failreason so we have a sensible error
 * message. The failreason is overwritten if it is already set, since
 * we probably know better what happened in the modifier.. */
void payment_abort(struct payment *p, const char *fmt, ...) PRINTF_FMT(2,3);

struct payment *payment_root(struct payment *p);
struct payment_tree_result payment_collect_result(struct payment *p);

/* For special effects, like inspecting your own routes. */
struct gossmap *get_gossmap(struct plugin *plugin);

#endif /* LIGHTNING_PLUGINS_LIBPLUGIN_PAY_H */
