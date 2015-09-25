/* Test for state machine. */
#include <stdbool.h>
#include <ccan/array_size/array_size.h>
#include <ccan/tal/tal.h>
#include <ccan/tal/str/str.h>
#include <ccan/err/err.h>
#include <ccan/structeq/structeq.h>
#include <ccan/htable/htable_type.h>
#include <ccan/hash/hash.h>

static bool record_input_mapping(int b);
#define MAPPING_INPUTS(b) \
	do { if (record_input_mapping(b)) return false; } while(0)

#include "state.h"
#include "gen_state_names.h"

static enum state_input *mapping_inputs;

/* To recontruct errors. */
struct trail {
	struct trail *next;
	const char *problem;
	const char *name;
	enum state_input input;
	enum state before, after;
	const char *pkt_sent;
};

struct state_data {
	enum state state;
	size_t num_outputs;
	enum state_input outputs[6];
	enum state_input current_command;
	enum state_input deferred_pkt;
	enum state deferred_state;
	bool pkt_inputs;
	bool cmd_inputs;

	const char *error;
	
	/* What bitcoin/timeout notifications are we subscribed to? */
	uint64_t event_notifies;
	/* ID. */
	const char *name;
	/* The other peer's sdata. */
	struct state_data *peer;
};

struct situation {
	struct state_data a, b;
};

static const struct situation *situation_keyof(const struct situation *situation)
{
	return situation;
}

static uint32_t hash_add(uint64_t val, uint32_t base)
{
	return hash_any(&val, sizeof(val), base);
}

static size_t sdata_hash(const struct state_data *sdata)
{
	size_t h;

	h = hash(sdata->outputs, sdata->num_outputs, sdata->state);
	h = hash_add(sdata->current_command, h);
	h = hash_add(sdata->deferred_pkt, h);
	h = hash_add(sdata->deferred_state, h);
	h = hash_add(sdata->pkt_inputs, h);
	h = hash_add(sdata->event_notifies, h);

	return h;
}

static bool sdata_eq(const struct state_data *a, const struct state_data *b)
{
	assert(streq(a->name, b->name));
	return a->state == b->state
		&& a->num_outputs == b->num_outputs
		&& memcmp(a->outputs, b->outputs,
			  a->num_outputs * sizeof(*a->outputs)) == 0
		&& a->current_command == b->current_command
		&& a->deferred_pkt == b->deferred_pkt
		&& a->deferred_state == b->deferred_state
		&& a->pkt_inputs == b->pkt_inputs
		&& a->cmd_inputs == b->cmd_inputs
		&& a->event_notifies == b->event_notifies;
}

static size_t situation_hash(const struct situation *situation)
{
	return hash_add(sdata_hash(&situation->a), sdata_hash(&situation->b));
}

static bool situation_eq(const struct situation *a, const struct situation *b)
{
	return sdata_eq(&a->a, &b->a) && sdata_eq(&a->b, &b->b);
}

HTABLE_DEFINE_TYPE(struct situation,
		   situation_keyof, situation_hash, situation_eq,
		   sithash);

struct hist {
	/* All the different state combinations. */
	struct sithash sithash;

	/* The different inputs. */
	enum state_input **inputs_per_state;

	/* The different outputs. */
	enum state_input *outputs;
};
	
static const char *state_name(enum state s)
{
	size_t i;

	for (i = 0; enum_state_names[i].name; i++)
		if (enum_state_names[i].v == s)
			return enum_state_names[i].name;
	return "unknown";
}

static const char *input_name(enum state_input in)
{
	size_t i;

	for (i = 0; enum_state_input_names[i].name; i++)
		if (enum_state_input_names[i].v == in)
			return enum_state_input_names[i].name;
	return "unknown";
}

static enum state_input input_by_name(const char *name)
{
	size_t i;

	for (i = 0; enum_state_input_names[i].name; i++)
		if (streq(name, enum_state_input_names[i].name))
			return enum_state_input_names[i].v;
	if (strstarts(name, "ERROR_PKT:"))
		return PKT_ERROR;
	abort();
}

static Pkt *new_pkt(const tal_t *ctx, enum state_input i)
{
	return (Pkt *)input_name(i);
}
	
Pkt *pkt_open(const tal_t *ctx, const struct state_data *sdata)
{
	return new_pkt(ctx, PKT_OPEN);
}

Pkt *pkt_anchor(const tal_t *ctx, const struct state_data *sdata)
{
	return new_pkt(ctx, PKT_OPEN_ANCHOR);
}

Pkt *pkt_open_commit_sig(const tal_t *ctx, const struct state_data *sdata)
{
	return new_pkt(ctx, PKT_OPEN_COMMIT_SIG);
}

Pkt *pkt_open_complete(const tal_t *ctx, const struct state_data *sdata)
{
	return new_pkt(ctx, PKT_OPEN_COMPLETE);
}

Pkt *pkt_update(const tal_t *ctx, const struct state_data *sdata, void *data)
{
	return new_pkt(ctx, PKT_UPDATE);
}
		
Pkt *pkt_htlc_update(const tal_t *ctx, const struct state_data *sdata, void *data)
{
	return new_pkt(ctx, PKT_UPDATE_ADD_HTLC);
}

Pkt *pkt_htlc_complete(const tal_t *ctx, const struct state_data *sdata, void *data)
{
	return new_pkt(ctx, PKT_UPDATE_COMPLETE_HTLC);
}

Pkt *pkt_htlc_timedout(const tal_t *ctx, const struct state_data *sdata, void *data)
{
	return new_pkt(ctx, PKT_UPDATE_TIMEDOUT_HTLC);
}

Pkt *pkt_htlc_routefail(const tal_t *ctx, const struct state_data *sdata, void *data)
{
	return new_pkt(ctx, PKT_UPDATE_ROUTEFAIL_HTLC);
}

Pkt *pkt_update_accept(const tal_t *ctx, const struct state_data *sdata)
{
	return new_pkt(ctx, PKT_UPDATE_ACCEPT);
}

Pkt *pkt_update_signature(const tal_t *ctx, const struct state_data *sdata)
{
	return new_pkt(ctx, PKT_UPDATE_SIGNATURE);
}

Pkt *pkt_update_complete(const tal_t *ctx, const struct state_data *sdata)
{
	return new_pkt(ctx, PKT_UPDATE_COMPLETE);
}

Pkt *pkt_err(const tal_t *ctx, const char *msg)
{
	return (Pkt *)tal_fmt(ctx, "ERROR_PKT:%s", msg);
}

Pkt *pkt_close(const tal_t *ctx, const struct state_data *sdata)
{
	return new_pkt(ctx, PKT_CLOSE);
}

Pkt *pkt_close_complete(const tal_t *ctx, const struct state_data *sdata)
{
	return new_pkt(ctx, PKT_CLOSE_COMPLETE);
}

Pkt *pkt_close_ack(const tal_t *ctx, const struct state_data *sdata)
{
	return new_pkt(ctx, PKT_CLOSE_ACK);
}

Pkt *unexpected_pkt(const tal_t *ctx, enum state_input input)
{
	return pkt_err(ctx, "Unexpected pkt");
}

Pkt *accept_pkt_open(struct state_effect *effect, const struct state_data *sdata, const Pkt *pkt)
{
	return NULL;
}

Pkt *accept_pkt_anchor(struct state_effect *effect, const struct state_data *sdata, const Pkt *pkt)
{
	return NULL;
}

Pkt *accept_pkt_open_commit_sig(struct state_effect *effect, const struct state_data *sdata, const Pkt *pkt)
{
	return NULL;
}
	
Pkt *accept_pkt_update(struct state_effect *effect, const struct state_data *sdata, const Pkt *pkt)
{
	return NULL;
}

Pkt *accept_pkt_htlc_update(struct state_effect *effect,
			    const struct state_data *sdata, const Pkt *pkt,
			    Pkt **decline)
{
	/* FIXME: Test setting *decline. */
	*decline = NULL;
	return NULL;
}

Pkt *accept_pkt_htlc_routefail(struct state_effect *effect, const struct state_data *sdata, const Pkt *pkt)
{
	return NULL;
}

Pkt *accept_pkt_htlc_timedout(struct state_effect *effect, const struct state_data *sdata, const Pkt *pkt)
{
	return NULL;
}

Pkt *accept_pkt_htlc_complete(struct state_effect *effect, const struct state_data *sdata, const Pkt *pkt)
{
	return NULL;
}

Pkt *accept_pkt_update_accept(struct state_effect *effect, const struct state_data *sdata, const Pkt *pkt)
{
	return NULL;
}

Pkt *accept_pkt_update_complete(struct state_effect *effect, const struct state_data *sdata, const Pkt *pkt)
{
	return NULL;
}

Pkt *accept_pkt_update_signature(struct state_effect *effect, const struct state_data *sdata, const Pkt *pkt)
{
	return NULL;
}

Pkt *accept_pkt_close(struct state_effect *effect, const struct state_data *sdata, const Pkt *pkt)
{
	return NULL;
}

Pkt *accept_pkt_close_complete(struct state_effect *effect, const struct state_data *sdata, const Pkt *pkt)
{
	return NULL;
}

Pkt *accept_pkt_close_ack(struct state_effect *effect, const struct state_data *sdata, const Pkt *pkt)
{
	return NULL;
}

static struct bitcoin_tx *bitcoin_tx(const char *str)
{
	return (struct bitcoin_tx *)str;
}

static bool bitcoin_tx_is(const struct bitcoin_tx *btx, const char *str)
{
	return streq((const char *)btx, str);
}

struct bitcoin_tx *bitcoin_anchor(const tal_t *ctx,
				  const struct state_data *sdata)
{
	return bitcoin_tx("anchor");
}

static void add_event(uint64_t *events, enum state_input input)
{
	/* This is how they say "no event please" */
	if (input == INPUT_NONE)
		return;
			
	assert(input < 64);
	assert(!(*events & (1ULL << input)));
	*events |= (1ULL << input);
}

struct watch {
	uint64_t events;
};

struct watch *bitcoin_watch_anchor(const tal_t *ctx,
				   const struct state_data *sdata,
				   enum state_input depthok,
				   enum state_input timeout,
				   enum state_input unspent,
				   enum state_input theyspent,
				   enum state_input otherspent)
{
	struct watch *watch = talz(ctx, struct watch);

	add_event(&watch->events, depthok);
	add_event(&watch->events, timeout);
	add_event(&watch->events, unspent);
	add_event(&watch->events, theyspent);
	add_event(&watch->events, otherspent);

	/* We assume these values in activate_event. */
	assert(timeout == BITCOIN_ANCHOR_TIMEOUT
	       || timeout == INPUT_NONE);
	assert(depthok == BITCOIN_ANCHOR_DEPTHOK);
	return watch;
}

struct watch *bitcoin_unwatch_anchor_depth(const tal_t *ctx,
					   const struct state_data *sdata,
					   enum state_input depthok,
					   enum state_input timeout)
{
	struct watch *watch = talz(ctx, struct watch);

	add_event(&watch->events, depthok);
	add_event(&watch->events, timeout);
	return watch;
}

/* Wait for our commit to be spendable. */
struct watch *bitcoin_watch_delayed(const struct state_effect *effect,
				    enum state_input canspend)
{
	struct watch *watch = talz(effect, struct watch);

	assert(bitcoin_tx_is(effect->broadcast, "our commit"));
	add_event(&watch->events, canspend);
	return watch;
}

/* Wait for commit to be very deeply buried (so we no longer need to
 * even watch) */
struct watch *bitcoin_watch(const struct state_effect *effect,
			    enum state_input done)
{
	struct watch *watch = talz(effect, struct watch);

	if (done == BITCOIN_STEAL_DONE)
		assert(bitcoin_tx_is(effect->broadcast, "steal"));
	else if (done == BITCOIN_SPEND_THEIRS_DONE)
		assert(bitcoin_tx_is(effect->broadcast, "spend their commit"));
	else if (done == BITCOIN_SPEND_OURS_DONE)
		assert(bitcoin_tx_is(effect->broadcast, "spend our commit"));
	else
		errx(1, "Unknown watch effect %s", input_name(done));
	add_event(&watch->events, done);
	return watch;
}

/* Other side should drop close tx; watch for it. */
struct watch *bitcoin_watch_close(const tal_t *ctx,
				  const struct state_data *sdata,
				  enum state_input done)
{
	struct watch *watch = talz(ctx, struct watch);
	add_event(&watch->events, done);
	return watch;
}
	
struct bitcoin_tx *bitcoin_close(const tal_t *ctx,
				 const struct state_data *sdata)
{
	return bitcoin_tx("close");
}

struct bitcoin_tx *bitcoin_spend_ours(const tal_t *ctx,
				      const struct state_data *sdata)
{
	return bitcoin_tx("spend our commit");
}

struct bitcoin_tx *bitcoin_spend_theirs(const tal_t *ctx,
					const struct state_data *sdata)
{
	return bitcoin_tx("spend their commit");
}

struct bitcoin_tx *bitcoin_steal(const tal_t *ctx,
				 const struct state_data *sdata,
					struct bitcoin_event *btc)
{
	/* FIXME: Test this failing! */
	return bitcoin_tx("steal");
}

struct bitcoin_tx *bitcoin_commit(const tal_t *ctx,
				  const struct state_data *sdata)
{
	return bitcoin_tx("our commit");
}

#include "state.c"
#include <ccan/tal/tal.h>
#include <stdio.h>

static void sdata_init(struct state_data *sdata,
		       struct state_data *other,
		       enum state_input initstate,
		       const char *name)
{
	sdata->state = initstate;
	sdata->num_outputs = 1;
	sdata->error = NULL;
	memset(sdata->outputs, 0, sizeof(sdata->outputs));
	sdata->deferred_pkt = INPUT_NONE;
	sdata->deferred_state = STATE_MAX;
	sdata->outputs[0] = INPUT_NONE;
	sdata->current_command = INPUT_NONE;
	sdata->event_notifies = 0;
	sdata->pkt_inputs = true;
	sdata->cmd_inputs = true;
	sdata->name = name;
	sdata->peer = other;
}

static void copy_peers(struct state_data *dst, struct state_data *peer,
		       const struct state_data *src)
{
	*dst = *src;
	*peer = *src->peer;
	dst->peer = peer;
	peer->peer = dst;
}

/* Recursion! */
static struct trail *run_peer(const struct state_data *sdata,
			      struct hist *hist);

/* Returns false if we've been here before. */
static bool sithash_update(struct sithash *sithash,
			   const struct state_data *sdata)
{
	struct situation sit;

	if (streq(sdata->name, "A")) {
		sit.a = *sdata;
		sit.b = *sdata->peer;
	} else {
		sit.b = *sdata;
		sit.a = *sdata->peer;
	}

	if (sithash_get(sithash, &sit))
		return false;

	sithash_add(sithash, tal_dup(NULL, struct situation, &sit));
	return true;
}

static struct trail *add_trail(enum state_input input,
			       const struct state_data *before,
			       enum state after,
			       const struct state_effect *effects,
			       struct trail *next)
{
	struct trail *t = tal(NULL, struct trail);

	t->name = before->name;
	t->problem = next ? next->problem : NULL;
	t->next = tal_steal(t, next);
	t->input = input;
	t->before = before->state;
	t->after = after;
	t->pkt_sent = (const char *)effects->send;
	return t;
}

static struct trail *new_trail(enum state_input input,
			       const struct state_data *before,
			       enum state after,
			       const struct state_effect *effects,
			       const char *problem)
{
	struct trail *t = add_trail(input, before, after, effects, NULL);
	t->problem = problem;
	return t;
}

static bool is_current_command(const struct state_data *sdata,
			       enum state_input cmd)
{
	if (cmd == CMD_SEND_UPDATE_ANY) {
		return is_current_command(sdata, CMD_SEND_UPDATE)
			|| is_current_command(sdata, CMD_SEND_HTLC_UPDATE)
			|| is_current_command(sdata, CMD_SEND_HTLC_COMPLETE)
			|| is_current_command(sdata, CMD_SEND_HTLC_TIMEDOUT)
			|| is_current_command(sdata, CMD_SEND_HTLC_ROUTEFAIL);
	}
	return sdata->current_command == cmd;
}

static const char *apply_effects(struct state_data *sdata,
				 const struct state_effect *effect)
{
	if (effect->send) {
		const char *pkt = (const char *)effect->send;

		/* Check for errors. */
		if (strstarts(pkt, "ERROR_PKT:")) {
			/* Some are expected. */
			if (!streq(pkt, "ERROR_PKT:Commit tx noticed")
			    && !streq(pkt, "ERROR_PKT:Otherspend noticed")
			    && !streq(pkt, "ERROR_PKT:Anchor timed out")
			    && !streq(pkt, "ERROR_PKT:Close timed out")) {
				return pkt;
			}
		}
		assert(sdata->num_outputs < ARRAY_SIZE(sdata->outputs));
		sdata->outputs[sdata->num_outputs++] = input_by_name(pkt);
	}
	if (effect->watch) {
		/* We can have multiple steals in flight, so make an exception
		 * for BITCOIN_STEAL_DONE */
		if (sdata->event_notifies & (1ULL << BITCOIN_STEAL_DONE)
		    & effect->watch->events)
			effect->watch->events &= ~(1ULL << BITCOIN_STEAL_DONE);

		if (sdata->event_notifies & effect->watch->events)
			return "event set twice";
		sdata->event_notifies |= effect->watch->events;
		/* Events are not independent. */
		if (effect->watch->events & BITCOIN_ANCHOR_DEPTHOK)
			sdata->event_notifies &= ~(1ULL<<BITCOIN_ANCHOR_TIMEOUT);
		if (effect->watch->events & BITCOIN_ANCHOR_TIMEOUT)
			sdata->event_notifies &= ~(1ULL<<BITCOIN_ANCHOR_DEPTHOK);
	}
	if (effect->unwatch) {
		if ((sdata->event_notifies & effect->unwatch->events)
		    != effect->unwatch->events)
			return "unset event unwatched";
		sdata->event_notifies &= ~effect->unwatch->events;
	}
	if (effect->defer != INPUT_NONE) {
		/* If it was current command, it is no longer. */
		if (is_current_command(sdata, effect->defer))
			sdata->current_command = INPUT_NONE;
		else if (input_is_pkt(effect->defer)) {
			/* Unlike commands, which we always resubmit,
			 * we have to remember deferred packets. */
			/* We assume only one deferrment! */
			assert(sdata->deferred_pkt == INPUT_NONE
			       || sdata->deferred_pkt == effect->defer);
			sdata->deferred_pkt = effect->defer;
			sdata->deferred_state = sdata->state;
		}
	}
	if (effect->complete != INPUT_NONE) {
		if (!is_current_command(sdata, effect->complete))
			return tal_fmt(NULL, "Completed %s not %s",
				       input_name(effect->complete),
				       input_name(sdata->current_command));
		sdata->current_command = INPUT_NONE;
	}
	if (effect->stop_packets) {
		if (!sdata->pkt_inputs)
			return "stop_packets twice";
		sdata->pkt_inputs = false;

		/* Can no longer receive packet timeouts, either. */
		sdata->event_notifies &= ~(1ULL<<INPUT_CLOSE_COMPLETE_TIMEOUT);
	}
	if (effect->stop_commands) {
		if (!sdata->cmd_inputs)
			return "stop_commands twice";
		if (sdata->current_command != INPUT_NONE)
			return tal_fmt(NULL, "stop_commands with pending command %s",
				       input_name(sdata->current_command));
		sdata->cmd_inputs = false;
	}
	if (effect->close_timeout != INPUT_NONE) {
		add_event(&sdata->event_notifies, effect->close_timeout);
		/* We assume this. */
		assert(effect->close_timeout == INPUT_CLOSE_COMPLETE_TIMEOUT);
	}
	if (effect->in_error) {
		/* We should stop talking to them after error received. */
		if (sdata->pkt_inputs)
			return "packets still open after error pkt";
	}
	return NULL;
}
	
static void eliminate_input(enum state_input **inputs, enum state_input in)
{
	size_t i, n = tal_count(*inputs);

	for (i = 0; i < n; i++) {
		if ((*inputs)[i] != in)
			continue;

		if (i != n-1)
			(*inputs)[i] = (*inputs)[n-1];
		tal_resize(inputs, n - 1);
		break;
	}
}

static bool find_output(const enum state_input *outputs, enum state_input out)
{
	size_t n, i;

	n = tal_count(outputs);
	for (i = 0; i < n; i++)
		if (outputs[i] == out)
			return true;
	return false;
}

static void record_output(enum state_input **outputs, enum state_input out)
{
	size_t n;

	if (find_output(*outputs, out))
		return;

	n = tal_count(*outputs);
	tal_resize(outputs, n+1);
	(*outputs)[n] = out;
}
				
static struct trail *try_input(const struct state_data *sdata,
			       enum state_input i,
			       struct hist *hist)
{
	struct state_data copy, peer;
	union input idata;
	struct trail *t;
	struct state_effect *effect = tal(NULL, struct state_effect);
	enum state newstate;
	const char *problem;

	state_effect_init(effect);

	eliminate_input(&hist->inputs_per_state[sdata->state], i);
	idata.pkt = (Pkt *)tal(effect, char);
	newstate = state(sdata->state, sdata, i, &idata, effect);

	if (newstate == STATE_ERR_INTERNAL)
		return new_trail(i, sdata, newstate, effect, "Internal error");

	copy_peers(&copy, &peer, sdata);
	copy.state = newstate;
	problem = apply_effects(&copy, effect);
	if (problem)
		return new_trail(i, sdata, newstate, effect, problem);

	/* Record any output. */
	if (effect->send) {
		record_output(&hist->outputs,
			      input_by_name((const char *)effect->send));
	}
	
	/* Have we been in this overall situation before? */
	if (!sithash_update(&hist->sithash, &copy)) {
		tal_free(effect);
		return NULL;
	}

	/* Don't continue if we reached a different error state. */
	if (state_is_error(newstate)) {
		tal_free(effect);
		return NULL;
	}

	/* Finished? */
	if (newstate == STATE_CLOSED) {
		if (copy.pkt_inputs)
			return new_trail(i, sdata, newstate, effect,
					 "CLOSED but taking packets?");

		if (copy.cmd_inputs)
			return new_trail(i, sdata, newstate, effect,
					 "CLOSED but taking commands?");

		if (copy.current_command != INPUT_NONE)
			return new_trail(i, sdata, newstate, effect,
					 input_name(copy.current_command));
		tal_free(effect);
		return NULL;
	}

	/* Try inputs from here down. */
	t = run_peer(&copy, hist);
	if (!t)
		t = run_peer(&peer, hist);
	if (!t) {
		tal_free(effect);
		return NULL;
	}
	return add_trail(i, sdata, newstate, effect, t);
}

static void sanity_check(const struct state_data *sdata)
{
	if (sdata->state == STATE_NORMAL_LOWPRIO
	    || sdata->state == STATE_NORMAL_HIGHPRIO) {
		/* Home state: expect commands to be finished. */
		if (sdata->current_command != INPUT_NONE)
			errx(1, "Unexpected command %u in state %u",
			     sdata->current_command, sdata->state);
	}
}

static void activate_event(struct state_data *sdata, enum state_input i)
{
	/* Events are not independent. */
	switch (i) {
	case BITCOIN_ANCHOR_DEPTHOK:
		/* Can't sent TIMEOUT */
		sdata->event_notifies &= ~(1ULL<<BITCOIN_ANCHOR_TIMEOUT);
		break;
	case BITCOIN_ANCHOR_TIMEOUT:
		/* Can't sent DEPTHOK */
		sdata->event_notifies &= ~(1ULL<<BITCOIN_ANCHOR_DEPTHOK);
		break;
	default:
		;
	}
}

static struct trail *run_peer(const struct state_data *sdata,
			      struct hist *hist)
{
	struct state_data copy, peer;
	size_t i;
	uint64_t old_notifies;
	struct trail *t;

	sanity_check(sdata);

	/* We want to frob some things... */
	copy_peers(&copy, &peer, sdata);
	
	/* Try the event notifiers */
	old_notifies = copy.event_notifies;
	for (i = 0; i < 64; i++) {
		if (!(copy.event_notifies & (1ULL << i)))
			continue;

		/* Don't re-fire (except OTHERSPEND can reoccur) */
		if (i != BITCOIN_ANCHOR_OTHERSPEND)
			copy.event_notifies &= ~(1ULL << i);
		activate_event(&copy, i);
		t = try_input(&copy, i, hist);
		if (t)
			return t;
		copy.event_notifies = old_notifies;
	}

	/* Try sending commands (unless in init state, or closed). */
	if (sdata->state != STATE_INIT_WITHANCHOR
	    && sdata->state != STATE_INIT_NOANCHOR
	    && sdata->cmd_inputs) {
		/* We don't allow nested commands. */
		if (sdata->current_command == INPUT_NONE) {
			size_t i;
			static const enum state_input cmds[]
				= { CMD_SEND_UPDATE,
				    CMD_SEND_HTLC_UPDATE,
				    CMD_SEND_HTLC_COMPLETE,
				    CMD_SEND_HTLC_TIMEDOUT,
				    CMD_SEND_HTLC_ROUTEFAIL,
				    CMD_CLOSE };

			for (i = 0; i < sizeof(cmds) / sizeof(cmds[i]); i++) {
				copy.current_command = cmds[i];
				t = try_input(&copy, cmds[i], hist);
				if (t)
					return t;
			}
			copy.current_command = INPUT_NONE;
		}
	}

	/* Allowed to send inputs? */
	if (copy.pkt_inputs) {
		enum state_input i;
		
		if (copy.deferred_pkt != INPUT_NONE) {
			/* Can only resubmit once state changed. */
			if (copy.state != copy.deferred_state) {
				i = copy.deferred_pkt;
				copy.deferred_pkt = INPUT_NONE;
				return try_input(&copy, i, hist);
			}
			/* Can't send anything until that's done. */
			return NULL;
		}
				
		if (peer.num_outputs) {
			i = peer.outputs[0];

			/* Do the first, recursion does the rest. */
			memmove(peer.outputs, peer.outputs + 1,
				sizeof(peer.outputs) - sizeof(peer.outputs[0]));
			peer.num_outputs--;
			return try_input(&copy, i, hist);
		}
	}
	return NULL;
}

static bool record_input_mapping(int b)
{
	size_t n;

	if (!mapping_inputs)
		return false;

	/* Accumulating tested inputs? */
	n = tal_count(mapping_inputs);
	tal_resize(&mapping_inputs, n+1);
	mapping_inputs[n] = b;
	return true;
}
	
static enum state_input **map_inputs(void)
{
	enum state_input **inps = tal_arr(NULL, enum state_input *, STATE_MAX);
	unsigned int i;
	struct state_effect *effect = tal(inps, struct state_effect);

	for (i = 0; i < STATE_MAX; i++) {
		/* This is a global */
		mapping_inputs = tal_arr(inps, enum state_input, 0);

		state_effect_init(effect);
		/* This adds to mapping_inputs every input_is() call */
		if (!state_is_error(i))
			state(i, NULL, INPUT_NONE, NULL, effect);
		inps[i] = mapping_inputs;
	}

	/* Reset global */
	mapping_inputs = NULL;
	tal_free(effect);
	return inps;
}

static bool visited_state(const struct sithash *sithash,
			  enum state state, bool b)
{
	struct situation *h;
	struct sithash_iter i;

	for (h = sithash_first(sithash, &i); h; h = sithash_next(sithash, &i)) {
		if (b) {
			if (h->b.state == state)
				return true;
		} else {
			if (h->a.state == state)
				return true;
		}
	}
	return false;
}

int main(void)
{
	struct state_data a, b;
	unsigned int i;
	struct hist hist;
	struct trail *t;

	/* Map the inputs tested in each state. */
	hist.inputs_per_state = map_inputs();
	sithash_init(&hist.sithash);
	hist.outputs = tal_arr(NULL, enum state_input, 0);

	/* Initialize universe. */
	sdata_init(&a, &b, STATE_INIT_WITHANCHOR, "A");
	sdata_init(&b, &a, STATE_INIT_NOANCHOR, "B");
	if (!sithash_update(&hist.sithash, &a))
		abort();

	/* Now, try each input in each state. */
	t = run_peer(&a, &hist);
	if (t) {
		fprintf(stderr, "Error: %s\n", t->problem);
		while (t) {
			fprintf(stderr, "%s: %s %s -> %s\n",
				t->name,
				input_name(t->input),
				state_name(t->before), state_name(t->after));
			if (t->pkt_sent)
				fprintf(stderr, "  => %s\n", t->pkt_sent);
			t = t->next;
		}
		exit(1);
	}

	for (i = 0; i < STATE_MAX; i++) {
		bool a_expect = true, b_expect = true;
		/* A supplied anchor, so doesn't enter NOANCHOR states. */
		if (i == STATE_INIT_NOANCHOR
		    || i == STATE_OPEN_WAIT_FOR_OPEN_NOANCHOR
		    || i == STATE_OPEN_WAIT_FOR_ANCHOR
		    || i == STATE_OPEN_WAITING_THEIRANCHOR
		    || i == STATE_OPEN_WAIT_FOR_COMPLETE_THEIRANCHOR
		    || i == STATE_ERR_ANCHOR_TIMEOUT)
			a_expect = false;
		if (i == STATE_INIT_WITHANCHOR
		    || i == STATE_OPEN_WAIT_FOR_OPEN_WITHANCHOR
		    || i == STATE_OPEN_WAIT_FOR_COMMIT_SIG
		    || i == STATE_OPEN_WAIT_FOR_COMPLETE_OURANCHOR
		    || i == STATE_OPEN_WAITING_OURANCHOR)
			b_expect = false;
		if (i == STATE_ERR_INTERNAL)
			a_expect = b_expect = false;
		if (visited_state(&hist.sithash, i, 0) != a_expect)
			warnx("Peer A %s state %s",
			      a_expect ? "didn't visit" : "visited",
			      state_name(i));
		if (visited_state(&hist.sithash, i, 1) != b_expect)
			warnx("Peer B %s state %s",
			     b_expect ? "didn't visit" : "visited",
			      state_name(i));
		if (!state_is_error(i) && tal_count(hist.inputs_per_state[i]))
			warnx("Never sent %s input %s", state_name(i),
			      input_name(*hist.inputs_per_state[i]));
	}

	for (i = 0; i < INPUT_MAX; i++) {
		/* Not all input values are valid. */
		if (streq(input_name(i), "unknown"))
			continue;
		/* We only expect packets to be output. */
		if (!input_is_pkt(i))
			continue;
		if (!find_output(hist.outputs, i))
			warnx("Never sent output %s", input_name(i));
	}
	return 0;
}	
