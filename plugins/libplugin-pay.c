#include <plugins/libplugin-pay.h>
#include <stdio.h>

struct payment *payment_new(tal_t *ctx, struct command *cmd,
			    struct payment *parent,
			    struct payment_modifier **mods)
{
	struct payment *p = tal(ctx, struct payment);
	p->children = tal_arr(p, struct payment *, 0);
	p->parent = parent;
	p->modifiers = mods;
	p->cmd = cmd;
	p->start_time = time_now();
	p->partid = partid++;

	/* Copy over the relevant pieces of information. */
	if (parent != NULL) {
		tal_arr_expand(&parent->children, p);
		p->destination = p->getroute_destination = parent->destination;
		p->amount = parent->amount;
		p->payment_hash = parent->payment_hash;
	}

	/* Initialize all modifier data so we can point to the fields when
	 * wiring into the param() call in a JSON-RPC handler. The callback
	 * can also just `memcpy` the parent if this outside access is not
	 * required. */
	p->modifier_data = tal_arr(p, void *, 0);
	for (size_t i=0; mods[i] != NULL; i++) {
		if (mods[i]->data_init != NULL)
			tal_arr_expand(&p->modifier_data,
				       mods[i]->data_init(p));
		else
			tal_arr_expand(&p->modifier_data, NULL);
	}

	return p;
}

void payment_start(struct payment *p)
{
	p->step = PAYMENT_STEP_INITIALIZED;
	p->current_modifier = -1;
	payment_continue(p);
}

static void payment_getroute(struct payment *p)
{
	p->step = PAYMENT_STEP_GOT_ROUTE;
	return payment_continue(p);
}

static void payment_compute_onion_payloads(struct payment *p)
{
	p->step = PAYMENT_STEP_ONION_PAYLOAD;
	/* Now allow all the modifiers to mess with the payloads, before we
	 * serialize via a call to createonion in the next step. */
	payment_continue(p);
}

static void payment_sendonion(struct payment *p)
{
	p->step = PAYMENT_STEP_FAILED;
	return payment_continue(p);
}

/* Mutual recursion. */
static void payment_finished(struct payment *p);

/* Function to bubble up completions to the root, which actually holds on to
 * the command that initiated the flow. */
static struct command_result *payment_child_finished(struct payment *parent,
						     struct payment *child)
{
	/* TODO implement logic to wait for all parts instead of bubbling up
	 * directly. */

	/* Should we continue bubbling up? */
	if (parent->parent == NULL) {
		assert(parent->cmd != NULL);
		return payment_finished(parent);
	} else {
		return payment_child_finished(parent->parent, parent);
	}
}

/* This function is called whenever a payment ends up in a final state, or all
 * leafs in the subtree rooted in the payment are all in a final state. It is
 * called only once, and it is guaranteed to be called in post-order
 * traversal, i.e., all children are finished before the parent is called. */
static void payment_finished(struct payment *p)
{
	/* TODO If this is a success bubble it back up through the part
	 * tree. If it is a failure, decide here whether to split, retry or
	 * split (maybe in a modifier instead?). */
	if (p->parent == NULL)
		return command_fail(p->cmd, JSONRPC2_INVALID_REQUEST, "Not functional yet");
	else
		return payment_child_finished(p->parent, p);
}

void payment_continue(struct payment *p)
{
	struct payment_modifier *mod;
	void *moddata;
	/* If we are in the middle of calling the modifiers, continue calling
	 * them, otherwise we can continue with the payment state-machine. */
	p->current_modifier++;
	mod = p->modifiers[p->current_modifier];

	if (mod != NULL) {
		/* There is another modifier, so call it. */
		moddata = p->modifier_data[p->current_modifier];
		return mod->post_step_cb(moddata, p);
	} else {
		/* There are no more modifiers, so reset the call chain and
		 * proceed to the next state. */
		p->current_modifier = -1;
		switch (p->step) {
		case PAYMENT_STEP_INITIALIZED:
			payment_getroute(p);
			return;

		case PAYMENT_STEP_GOT_ROUTE:
			payment_compute_onion_payloads(p);
			return;

		case PAYMENT_STEP_ONION_PAYLOAD:
			payment_sendonion(p);
			return;

		case PAYMENT_STEP_SUCCESS:
		case PAYMENT_STEP_FAILED:
			payment_finished(p);
			return;

		case PAYMENT_STEP_RETRY:
		case PAYMENT_STEP_SPLIT:
			/* Do nothing, we'll get pinged by a child succeeding
			 * or failing. */
			return;
		}
	}
	/* We should never get here, it'd mean one of the state machine called
	 * `payment_continue` after the final state. */
	abort();
}

static inline struct dummy_data *
dummy_data_init(struct payment *p)
{
	return tal(p, struct dummy_data);
}

static inline void dummy_step_cb(struct dummy_data *dd,
				 struct payment *p)
{
	fprintf(stderr, "dummy_step_cb called for payment %p at step %d\n", p, p->step);
	payment_continue(p);
}

REGISTER_PAYMENT_MODIFIER(dummy, struct dummy_data *, dummy_data_init,
			  dummy_step_cb);
