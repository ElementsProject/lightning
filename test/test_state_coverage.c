/* Test for state machine. */
#include <stdbool.h>
#include <ccan/array_size/array_size.h>
#include <ccan/tal/tal.h>
#include <ccan/tal/str/str.h>
#include <ccan/err/err.h>
#include <ccan/structeq/structeq.h>
#include <ccan/htable/htable_type.h>
#include <ccan/hash/hash.h>
#include <ccan/opt/opt.h>
#include <ccan/asort/asort.h>
#include <ccan/list/list.h>
#include "version.h"

static bool record_input_mapping(int b);
#define MAPPING_INPUTS(b) \
	do { if (record_input_mapping(b)) return false; } while(0)

#include "state.h"
#include "gen_state_names.h"

static bool quick = false;
static bool dot_simplify = false;
static bool dot_enable = false;
static bool dot_include_abnormal = false;
static bool dot_include_errors = false;
static bool include_nops = false;
static enum state_input *mapping_inputs;

enum failure {
	FAIL_NONE,
	FAIL_DECLINE_HTLC,
};

struct htlc {
	bool to_them;
	unsigned int id;
};

struct htlc_progress {
	struct htlc htlc; /* id == -1 if none in progress. */
	bool adding; /* otherwise, removing. */
};

struct htlc_spend_watch {
	unsigned int id;
	enum state_input done;
};

/* Beyond this we consider cases equal for traverse loop detection. */
#define CAP_HTLCS 1

/* How many HTLCs to negotiate. */
#define MAX_HTLCS 2

/* But we can have many different malleated commit txs. */
#define HTLC_ARRSIZE 20

/*
 * Worst case:
 * Low priority: PKT_UPDATE_ADD_HTLC
 * Receive update, which we decline: PKT_UPDATE_DECLINE_HTLC
 * Send new update: PKT_UPDATE_ADD_HTLC
 * Start close: PKT_CLOSE
 * Some error: PKT_ERROR
 */
#define MAX_OUTQ 5

/* No padding, for fast compare and hashing. */
struct core_state {
	/* What bitcoin/timeout notifications are we subscribed to? */
	uint64_t event_notifies;

	enum state state;
	enum state deferred_state;
	enum state_input current_command;
	enum state_input deferred_pkt;

	enum state_input outputs[MAX_OUTQ];

	uint8_t num_outputs;
	bool pkt_inputs;
	bool cmd_inputs;
	/* Here down need to be generated from other fields */
	bool has_current_htlc;

	uint8_t capped_htlcs_to_them;
	uint8_t capped_htlcs_to_us;
	uint8_t capped_htlc_spends_to_them;
	uint8_t capped_htlc_spends_to_us;

	uint8_t capped_live_htlcs_to_them;
	uint8_t capped_live_htlcs_to_us;
	bool closing_cmd;
	bool valid;
};

struct state_data {
	struct core_state core;
	/* To store HTLC numbers. */
	unsigned int pkt_data[MAX_OUTQ];

	/* id == -1 if none currently. */
	struct htlc_progress current_htlc;
	
	unsigned int num_htlcs_to_them, num_htlcs_to_us;
	struct htlc htlcs_to_them[MAX_HTLCS], htlcs_to_us[MAX_HTLCS];

	unsigned int num_live_htlcs_to_them, num_live_htlcs_to_us;
	struct htlc live_htlcs_to_them[HTLC_ARRSIZE], live_htlcs_to_us[HTLC_ARRSIZE];

	unsigned int num_htlc_spends_to_them, num_htlc_spends_to_us;
	struct htlc htlc_spends_to_us[HTLC_ARRSIZE],
		htlc_spends_to_them[HTLC_ARRSIZE];

	unsigned int num_rvals_known;
	unsigned int rvals_known[HTLC_ARRSIZE];

	/* Where we came from. */
	const struct trail *trail;

	/* Current input and idata (for fail()) */
	enum state_input current_input;
	const union input *current_idata;
	
	const char *error;
	
	/* ID. */
	const char *name;
	/* The other peer's sdata. */
	struct state_data *peer;
};

/* To recontruct errors. */
struct trail {
	const struct trail *prev;
	const char *name;
	enum state_input input;
	const struct state_data *before, *after;
	int htlc_id;
	unsigned int num_peer_outputs;
	unsigned int depth;
	const char *pkt_sent;
};

struct situation {
	union {
		struct core_state s;
		uint32_t u32[sizeof(struct core_state)/sizeof(uint32_t)];
	} a, b;
};

static const struct situation *situation_keyof(const struct situation *situation)
{
	return situation;
}

/* After 2, we stop looping. */
static unsigned int cap(unsigned int val)
{
	return val > CAP_HTLCS ? CAP_HTLCS : val;
}

static size_t situation_hash(const struct situation *situation)
{
	BUILD_ASSERT(sizeof(situation->a.u32) == sizeof(situation->a.s));
	return hash(situation->a.u32, ARRAY_SIZE(situation->a.u32), 0);
}

static bool situation_eq(const struct situation *a, const struct situation *b)
{
	/* No padding */
	BUILD_ASSERT(sizeof(a->a.s)
		     == (sizeof(a->a.s.event_notifies)
			 + sizeof(a->a.s.state)
			 + sizeof(a->a.s.deferred_state)
			 + sizeof(a->a.s.current_command)
			 + sizeof(a->a.s.deferred_pkt)
			 + sizeof(a->a.s.outputs)
			 + sizeof(a->a.s.num_outputs)
			 + sizeof(a->a.s.pkt_inputs)
			 + sizeof(a->a.s.cmd_inputs)
			 + sizeof(a->a.s.has_current_htlc)
			 + sizeof(a->a.s.capped_htlcs_to_us)
			 + sizeof(a->a.s.capped_htlcs_to_them)
			 + sizeof(a->a.s.capped_htlc_spends_to_us)
			 + sizeof(a->a.s.capped_htlc_spends_to_them)
			 + sizeof(a->a.s.capped_live_htlcs_to_us)
			 + sizeof(a->a.s.capped_live_htlcs_to_them)
			 + sizeof(a->a.s.closing_cmd)
			 + sizeof(a->a.s.valid)));
	return structeq(&a->a.s, &b->a.s) && structeq(&a->b.s, &b->b.s);
}

struct dot_edge {
	const char *oldstate, *newstate;
	enum state_input i;
	const char *pkt;
};

static const struct dot_edge *dot_edge_keyof(const struct dot_edge *dot_edge)
{
	return dot_edge;
}

static size_t dot_edge_hash(const struct dot_edge *d)
{
	uint32_t pkthash;

	if (d->pkt)
		pkthash = hash(d->pkt, strlen(d->pkt), d->i);
	else
		pkthash = d->i;
	return hash_pointer(d->oldstate, hash_pointer(d->newstate, pkthash));
}

static bool dot_edge_eq(const struct dot_edge *a, const struct dot_edge *b)
{
	return a->oldstate == b->oldstate
		&& a->newstate == b->newstate
		&& a->i == b->i
		&& ((a->pkt == NULL && b->pkt == NULL)
		    || streq(a->pkt, b->pkt));
}

HTABLE_DEFINE_TYPE(struct dot_edge,
		   dot_edge_keyof, dot_edge_hash, dot_edge_eq,
		   edge_hash);

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

	/* Edges for the dot graph, if any. */
	struct edge_hash edges;

	/* For dumping states. */
	struct state_dump {
		enum state_input input;
		enum state next;
		enum state_input pkt;
	} **state_dump;
};

struct failpoint {
	/* Hash key (with which_fail) */
	struct situation sit;
	/* The universe state at the time. */
	struct state_data sdata, peer;
	enum state_input input;
	union input idata;
	/* Previous history. */
	const struct trail *prev_trail;
	/* Which failure */
	enum failure which_fail;
	/* Have we tried failing yet? */
	bool failed;
};

static const struct failpoint *
failpoint_keyof(const struct failpoint *f)
{
	return f;
}

static size_t failpoint_hash(const struct failpoint *f)
{
	return situation_hash(&f->sit) + f->which_fail;
}

static bool failpoint_eq(const struct failpoint *a,
			 const struct failpoint *b)
{
	return a->which_fail == b->which_fail
		&& situation_eq(&a->sit, &b->sit);
}

HTABLE_DEFINE_TYPE(struct failpoint,
		   failpoint_keyof, failpoint_hash, failpoint_eq,
		   failhash);

static struct failhash failhash;

static void update_core(struct core_state *core, const struct state_data *sdata)
{
	size_t i;

	for (i = core->num_outputs; i < ARRAY_SIZE(core->outputs); i++)
		assert(core->outputs[i] == 0);
		
	core->has_current_htlc = sdata->current_htlc.htlc.id != -1;
	core->capped_htlcs_to_us = cap(sdata->num_htlcs_to_us);
	core->capped_htlcs_to_them = cap(sdata->num_htlcs_to_them);
	core->capped_live_htlcs_to_us = cap(sdata->num_live_htlcs_to_us);
	core->capped_live_htlcs_to_them = cap(sdata->num_live_htlcs_to_them);
	core->capped_htlc_spends_to_us = cap(sdata->num_htlc_spends_to_us);
	core->capped_htlc_spends_to_them = cap(sdata->num_htlc_spends_to_them);
	core->valid = true;
}

static void situation_init(struct situation *sit,
			   const struct state_data *sdata)
{
	if (streq(sdata->name, "A")) {
		sit->a.s = sdata->core;
		update_core(&sit->a.s, sdata);
		/* If we're still talking to peer, their state matters. */
		if (sdata->core.pkt_inputs || sdata->peer->core.pkt_inputs) {
			sit->b.s = sdata->peer->core;
			update_core(&sit->b.s, sdata->peer);
		} else
			memset(&sit->b.s, 0, sizeof(sit->b.s));
	} else {
		sit->b.s = sdata->core;
		update_core(&sit->b.s, sdata);
		/* If we're still talking to peer, their state matters. */
		if (sdata->core.pkt_inputs || sdata->peer->core.pkt_inputs) {
			sit->a.s = sdata->peer->core;
			update_core(&sit->a.s, sdata->peer);
		} else
			memset(&sit->a.s, 0, sizeof(sit->a.s));
	}
}


/* Returns false if we've been here before. */
static bool sithash_update(struct sithash *sithash,
			   const struct state_data *sdata)
{
	struct situation sit;

	situation_init(&sit, sdata);

	if (sithash_get(sithash, &sit))
		return false;

	sithash_add(sithash, tal_dup(NULL, struct situation, &sit));
	return true;
}

static void copy_peers(struct state_data *dst, struct state_data *peer,
		       const struct state_data *src)
{
	*dst = *src;
	*peer = *src->peer;
	dst->peer = peer;
	peer->peer = dst;
}

static const struct trail *clone_trail(const tal_t *ctx,
				       const struct trail *trail)
{
	struct trail *t;

	if (!trail)
		return NULL;
	
	t = tal_dup(ctx, struct trail, trail);
	t->before = tal_dup(t, struct state_data, trail->before);
	t->after = trail->after ? tal_dup(t, struct state_data, trail->after)
		: NULL;
	t->pkt_sent = trail->pkt_sent ? tal_strdup(t, trail->pkt_sent) : NULL;
	t->prev = clone_trail(ctx, trail->prev);
	return t;
}

static const union input dup_idata(const tal_t *ctx,
				    enum state_input input,
				    const union input *idata)
{
	union input i;

	if (input_is_pkt(input))
		i.pkt = (Pkt *)tal_strdup(ctx, (const char *)idata->pkt);
	else if (input == CMD_SEND_HTLC_UPDATE
		 || input == CMD_SEND_HTLC_FULFILL
		 || input == CMD_SEND_HTLC_ROUTEFAIL
		 || input == CMD_SEND_HTLC_TIMEDOUT) {
		i.htlc_prog = tal_dup(ctx, struct htlc_progress,
				      idata->htlc_prog);
	} else {
		if (idata->htlc)
			i.htlc = tal_dup(ctx, struct htlc, idata->htlc);
		else
			i.htlc = NULL;
	}
	return i;
}

static bool fail(const struct state_data *sdata, enum failure which_fail)
{
	struct failpoint *f = tal(NULL, struct failpoint), *old;

	copy_peers(&f->sdata, &f->peer, sdata);
	situation_init(&f->sit, &f->sdata);
	f->sdata.trail = clone_trail(f, sdata->trail);
	f->which_fail = which_fail;
	f->input = sdata->current_input;
	f->idata = dup_idata(f, f->input, sdata->current_idata);
	f->failed = false;

	/* If we've been here before... */
	old = failhash_get(&failhash, f);
	if (old) {
		tal_free(f);
		/* If we haven't tried failing, try that now. */
		if (!old->failed) {
			old->failed = true;
			return true;
		}
		return false;
	}

	/* First time here, don't fail. */
	failhash_add(&failhash, f);
	return false;
}

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

	for (i = 0; enum_state_input_names[i].name; i++) {
		if (!strstarts(name, enum_state_input_names[i].name))
			continue;
		if (name[strlen(enum_state_input_names[i].name)] == '\0'
		    || name[strlen(enum_state_input_names[i].name)] == ':')
			return enum_state_input_names[i].v;
	}
	abort();
}

/* We don't bother with lifetime issues */
static Pkt *set_errpkt(const tal_t *ctx, const Pkt *pkt)
{
	return (Pkt *)pkt;
}

static Pkt *new_pkt(const tal_t *ctx, enum state_input i)
{
	return (Pkt *)input_name(i);
}

static unsigned int htlc_id_from_pkt(const Pkt *pkt)
{
	const char *s = strstr((const char *)pkt, ": HTLC #");
	return s ? atoi(s + strlen(": HTLC #")) : -1U;
}

static Pkt *htlc_pkt(const tal_t *ctx, const char *prefix, unsigned int id)
{
	return (Pkt *)tal_fmt(ctx, "%s: HTLC #%u", prefix, id);
}

static unsigned int htlc_id_from_tx(const struct bitcoin_tx *tx)
{
	const char *s = strstr((const char *)tx, "HTLC #");
	return atoi(s + strlen("HTLC #"));
}

static struct bitcoin_tx *htlc_tx(const tal_t *ctx,
				  const char *prefix, unsigned int id)
{
	return (struct bitcoin_tx *)tal_fmt(ctx, "%s HTLC #%u", prefix, id);
}

static struct htlc *find_any_htlc(const struct htlc *htlcs, size_t num,
					unsigned id)
{
	unsigned int i;

	for (i = 0; i < num; i++)
		if (htlcs[i].id == id)
			return (struct htlc *)htlcs + i;
	return NULL;
}

static struct htlc *find_htlc(const struct state_data *sdata, unsigned id)
{
	const struct htlc *h;

	h = find_any_htlc(sdata->htlcs_to_us, sdata->num_htlcs_to_us, id);
	if (!h)
		h = find_any_htlc(sdata->htlcs_to_them,
				  sdata->num_htlcs_to_them, id);
	return (struct htlc *)h;
}

static struct htlc *find_live_htlc(const struct state_data *sdata,
				   unsigned id)
{
	const struct htlc *h;

	h = find_any_htlc(sdata->live_htlcs_to_us, sdata->num_live_htlcs_to_us,
			  id);
	if (!h)
		h = find_any_htlc(sdata->live_htlcs_to_them,
				  sdata->num_live_htlcs_to_them, id);
	return (struct htlc *)h;
}

static struct htlc *find_htlc_spend(const struct state_data *sdata,
					  unsigned id)
{
	const struct htlc *h;

	h = find_any_htlc(sdata->htlc_spends_to_us,
			  sdata->num_htlc_spends_to_us,
			  id);
	if (!h)
		h = find_any_htlc(sdata->htlc_spends_to_them,
				  sdata->num_htlc_spends_to_them, id);
	return (struct htlc *)h;
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

Pkt *pkt_htlc_update(const tal_t *ctx, const struct state_data *sdata,
		     const struct htlc_progress *htlc_prog)
{
	return htlc_pkt(ctx, "PKT_UPDATE_ADD_HTLC", htlc_prog->htlc.id);
}

Pkt *pkt_htlc_fulfill(const tal_t *ctx, const struct state_data *sdata,
		      const struct htlc_progress *htlc_prog)
{
	return htlc_pkt(ctx, "PKT_UPDATE_FULFILL_HTLC", htlc_prog->htlc.id);
}

Pkt *pkt_htlc_timedout(const tal_t *ctx, const struct state_data *sdata,
		       const struct htlc_progress *htlc_prog)
{
	return htlc_pkt(ctx, "PKT_UPDATE_TIMEDOUT_HTLC", htlc_prog->htlc.id);
}

Pkt *pkt_htlc_routefail(const tal_t *ctx, const struct state_data *sdata,
			const struct htlc_progress *htlc_prog)
{
	return htlc_pkt(ctx, "PKT_UPDATE_ROUTEFAIL_HTLC", htlc_prog->htlc.id);
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
	return (Pkt *)tal_fmt(ctx, "PKT_ERROR: %s", msg);
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
	
Pkt *accept_pkt_htlc_update(struct state_effect *effect,
			    const struct state_data *sdata, const Pkt *pkt,
			    Pkt **decline,
			    struct htlc_progress **htlcprog)
{
	if (fail(sdata, FAIL_DECLINE_HTLC))
		*decline = new_pkt(effect, PKT_UPDATE_DECLINE_HTLC);
	else {
		*decline = NULL;
		*htlcprog = tal(effect, struct htlc_progress);
		/* If they propose it, it's to us. */
		(*htlcprog)->htlc.to_them = false;
		(*htlcprog)->htlc.id = htlc_id_from_pkt(pkt);
		(*htlcprog)->adding = true;
	}
	return NULL;
}

Pkt *accept_pkt_htlc_routefail(struct state_effect *effect,
			       const struct state_data *sdata, const Pkt *pkt,
			       struct htlc_progress **htlcprog)
{
	unsigned int id = htlc_id_from_pkt(pkt);
	const struct htlc *h = find_htlc(sdata, id);

	/* The shouldn't fail unless it's to them */
	assert(h->to_them);
	
	*htlcprog = tal(effect, struct htlc_progress);
	(*htlcprog)->htlc = *h;
	(*htlcprog)->adding = false;
	return NULL;
}

Pkt *accept_pkt_htlc_timedout(struct state_effect *effect,
			      const struct state_data *sdata, const Pkt *pkt,
			      struct htlc_progress **htlcprog)
{
	unsigned int id = htlc_id_from_pkt(pkt);
	const struct htlc *h = find_htlc(sdata, id);

	/* The shouldn't timeout unless it's to us */
	assert(!h->to_them);
	
	*htlcprog = tal(effect, struct htlc_progress);
	(*htlcprog)->htlc = *h;
	(*htlcprog)->adding = false;
	return NULL;
}

Pkt *accept_pkt_htlc_fulfill(struct state_effect *effect,
			      const struct state_data *sdata, const Pkt *pkt,
			      struct htlc_progress **htlcprog)
{
	unsigned int id = htlc_id_from_pkt(pkt);
	const struct htlc *h = find_htlc(sdata, id);

	/* The shouldn't complete unless it's to them */
	assert(h->to_them);

	*htlcprog = tal(effect, struct htlc_progress);
	(*htlcprog)->htlc = *h;
	(*htlcprog)->adding = false;
	return NULL;
}

Pkt *accept_pkt_update_accept(struct state_effect *effect, const struct state_data *sdata, const Pkt *pkt, struct signature **sig)
{
	*sig = (struct signature *)tal_strdup(effect, "from PKT_UPDATE_ACCEPT");
	return NULL;
}

Pkt *accept_pkt_update_complete(struct state_effect *effect, const struct state_data *sdata, const Pkt *pkt)
{
	return NULL;
}

Pkt *accept_pkt_update_signature(struct state_effect *effect,
				 const struct state_data *sdata, const Pkt *pkt,
				 struct signature **sig)
{
	*sig = (struct signature *)tal_strdup(effect, "from PKT_UPDATE_SIGNATURE");
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

Pkt *accept_pkt_simultaneous_close(struct state_effect *effect, const struct state_data *sdata, const Pkt *pkt)
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

static bool have_event(uint64_t events, enum state_input input)
{
	return events & (1ULL << input);
}

static bool add_event_(uint64_t *events, enum state_input input)
{
	/* This is how they say "no event please" */
	if (input == INPUT_NONE)
		return true;
			
	assert(input < 64);
	if (have_event(*events, input))
		return false;
	*events |= (1ULL << input);
	return true;
}

static bool remove_event_(uint64_t *events, enum state_input input)
{
	/* This is how they say "no event please" */
	if (input == INPUT_NONE)
		return true;
			
	assert(input < 64);
	if (!have_event(*events, input))
		return false;
	*events &= ~(1ULL << input);
	return true;
}

static void remove_event(uint64_t *events, enum state_input input)
{
#ifdef NDEBUG
#error "Don't run tests with NDEBUG"
#endif
	assert(remove_event_(events, input));
}

static void add_event(uint64_t *events, enum state_input input)
{
#ifdef NDEBUG
#error "Don't run tests with NDEBUG"
#endif
	assert(add_event_(events, input));
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
				    const struct bitcoin_tx *tx,
				    enum state_input canspend)
{
	struct watch *watch = talz(effect, struct watch);

	assert(bitcoin_tx_is(tx, "our commit"));
	add_event(&watch->events, canspend);
	return watch;
}

/* Wait for commit to be very deeply buried (so we no longer need to
 * even watch) */
struct watch *bitcoin_watch(const struct state_effect *effect,
			    const struct bitcoin_tx *tx,
			    enum state_input done)
{
	struct watch *watch = talz(effect, struct watch);

	if (done == BITCOIN_STEAL_DONE)
		assert(bitcoin_tx_is(tx, "steal"));
	else if (done == BITCOIN_SPEND_THEIRS_DONE)
		assert(bitcoin_tx_is(tx, "spend their commit"));
	else if (done == BITCOIN_SPEND_OURS_DONE)
		assert(bitcoin_tx_is(tx, "spend our commit"));
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
					const struct state_data *sdata,
					const struct bitcoin_event *btc)
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

/* Create a HTLC refund collection */
struct bitcoin_tx *bitcoin_htlc_timeout(const tal_t *ctx,
					const struct state_data *sdata,
					const struct htlc *htlc)
{
	return htlc_tx(ctx, "htlc timeout", htlc->id);
}

/* Create a HTLC collection */
struct bitcoin_tx *bitcoin_htlc_spend(const tal_t *ctx,
				      const struct state_data *sdata,
				      const struct htlc *htlc)
{
	return htlc_tx(ctx, "htlc fulfill", htlc->id);
}

bool committed_to_htlcs(const struct state_data *sdata)
{
	return sdata->num_htlcs_to_them != 0 || sdata->num_htlcs_to_us != 0;
}

struct htlc_watch
{
	enum state_input tous_timeout;
	enum state_input tothem_spent;
	enum state_input tothem_timeout;
	unsigned int num_htlcs_to_us, num_htlcs_to_them;
	struct htlc htlcs_to_us[MAX_HTLCS], htlcs_to_them[MAX_HTLCS];
};

struct htlc_unwatch
{
	unsigned int id;
	enum state_input all_done;
};

struct htlc_watch *htlc_outputs_our_commit(const tal_t *ctx,
					   const struct state_data *sdata,
					   const struct bitcoin_tx *tx,
					   enum state_input tous_timeout,
					   enum state_input tothem_spent,
					   enum state_input tothem_timeout)
{
	struct htlc_watch *w = tal(ctx, struct htlc_watch);

	/* We assume these. */
	assert(tous_timeout == BITCOIN_HTLC_TOUS_TIMEOUT);
	assert(tothem_spent == BITCOIN_HTLC_TOTHEM_SPENT);
	assert(tothem_timeout == BITCOIN_HTLC_TOTHEM_TIMEOUT);

	w->tous_timeout = tous_timeout;
	w->tothem_spent = tothem_spent;
	w->tothem_timeout = tothem_timeout;

	w->num_htlcs_to_us = sdata->num_htlcs_to_us;
	w->num_htlcs_to_them = sdata->num_htlcs_to_them;
	BUILD_ASSERT(sizeof(sdata->htlcs_to_us) == sizeof(w->htlcs_to_us));
	BUILD_ASSERT(sizeof(sdata->htlcs_to_them) == sizeof(w->htlcs_to_them));
	memcpy(w->htlcs_to_us, sdata->htlcs_to_us, sizeof(sdata->htlcs_to_us));
	memcpy(w->htlcs_to_them, sdata->htlcs_to_them,
	       sizeof(sdata->htlcs_to_them));

	if (!w->num_htlcs_to_us && !w->num_htlcs_to_them)
		return tal_free(w);

	return w;
}

struct htlc_watch *htlc_outputs_their_commit(const tal_t *ctx,
					     const struct state_data *sdata,
					     const struct bitcoin_event *tx,
					     enum state_input tous_timeout,
					     enum state_input tothem_spent,
					     enum state_input tothem_timeout)
{
	struct htlc_watch *w = tal(ctx, struct htlc_watch);
	unsigned int i;

	/* We assume these. */
	assert(tous_timeout == BITCOIN_HTLC_TOUS_TIMEOUT);
	assert(tothem_spent == BITCOIN_HTLC_TOTHEM_SPENT);
	assert(tothem_timeout == BITCOIN_HTLC_TOTHEM_TIMEOUT);

	w->tous_timeout = tous_timeout;
	w->tothem_spent = tothem_spent;
	w->tothem_timeout = tothem_timeout;

	/* It's what our peer thinks is current... */
	w->num_htlcs_to_us = sdata->peer->num_htlcs_to_them;
	w->num_htlcs_to_them = sdata->peer->num_htlcs_to_us;
	BUILD_ASSERT(sizeof(sdata->peer->htlcs_to_them) == sizeof(w->htlcs_to_us));
	BUILD_ASSERT(sizeof(sdata->peer->htlcs_to_us) == sizeof(w->htlcs_to_them));
	memcpy(w->htlcs_to_us, sdata->peer->htlcs_to_them, sizeof(w->htlcs_to_us));
	memcpy(w->htlcs_to_them, sdata->peer->htlcs_to_us,
	       sizeof(w->htlcs_to_them));

	if (!w->num_htlcs_to_us && !w->num_htlcs_to_them)
		return tal_free(w);

	/* Reverse perspective, mark rvalue unknown */
	for (i = 0; i < w->num_htlcs_to_us; i++) {
		assert(w->htlcs_to_us[i].to_them);
		w->htlcs_to_us[i].to_them = false;
	}
	for (i = 0; i < w->num_htlcs_to_them; i++) {
		assert(!w->htlcs_to_them[i].to_them);
		w->htlcs_to_them[i].to_them = true;
	}
	return w;
}

struct htlc_unwatch *htlc_unwatch(const tal_t *ctx,
				  const struct htlc *htlc,
				  enum state_input all_done)
{
	struct htlc_unwatch *w = tal(ctx, struct htlc_unwatch);

	w->id = htlc->id;
	assert(w->id != -1U);
	w->all_done = all_done;
	return w;
}

struct htlc_unwatch *htlc_unwatch_all(const tal_t *ctx,
				      const struct state_data *sdata)
{
	struct htlc_unwatch *w = tal(ctx, struct htlc_unwatch);

	w->id = -1U;
	return w;
}

struct htlc_spend_watch *htlc_spend_watch(const tal_t *ctx,
					  const struct bitcoin_tx *tx,
					  const struct command *cmd,
					  enum state_input done)
{
	struct htlc_spend_watch *w = tal(ctx, struct htlc_spend_watch);
	w->id = htlc_id_from_tx(tx);
	w->done = done;
	return w;
}

struct htlc_spend_watch *htlc_spend_unwatch(const tal_t *ctx,
					    const struct htlc *htlc,
					    enum state_input all_done)
{
	struct htlc_spend_watch *w = tal(ctx, struct htlc_spend_watch);

	w->id = htlc->id;
	w->done = all_done;
	return w;
}

struct htlc_rval {
	unsigned int id;
};
	
struct htlc_rval *r_value_from_cmd(const tal_t *ctx,
				   const struct state_data *sdata,
				   const struct htlc *htlc)
{
	struct htlc_rval *r = tal(ctx, struct htlc_rval);
	r->id = htlc->id;
	return r;
}

struct htlc_rval *bitcoin_r_value(const tal_t *ctx, const struct htlc *htlc)
{
	struct htlc_rval *r = tal(ctx, struct htlc_rval);
	r->id = htlc->id;
	return r;
}

struct htlc_rval *r_value_from_pkt(const tal_t *ctx, const Pkt *pkt)
{
	struct htlc_rval *r = tal(ctx, struct htlc_rval);
	r->id = htlc_id_from_pkt(pkt);
	return r;
}

#include "state.c"
#include <ccan/tal/tal.h>
#include <stdio.h>

static void sdata_init(struct state_data *sdata,
		       struct state_data *other,
		       enum state_input initstate,
		       const char *name)
{
	sdata->core.state = initstate;
	sdata->core.num_outputs = 1;
	sdata->current_htlc.htlc.id = -1;
	sdata->num_htlcs_to_us = 0;
	sdata->num_htlcs_to_them = 0;
	sdata->num_live_htlcs_to_us = 0;
	sdata->num_live_htlcs_to_them = 0;
	sdata->num_htlc_spends_to_us = 0;
	sdata->num_htlc_spends_to_them = 0;
	sdata->num_rvals_known = 0;
	sdata->error = NULL;
	memset(sdata->core.outputs, 0, sizeof(sdata->core.outputs));
	sdata->core.deferred_pkt = INPUT_NONE;
	sdata->core.deferred_state = STATE_MAX;
	sdata->core.outputs[0] = INPUT_NONE;
	sdata->pkt_data[0] = -1;
	sdata->core.current_command = INPUT_NONE;
	sdata->core.event_notifies = 0;
	sdata->core.pkt_inputs = true;
	sdata->core.cmd_inputs = true;
	sdata->core.closing_cmd = false;
	sdata->name = name;
	sdata->peer = other;
	sdata->trail = NULL;
}

/* Recursion! */
static void run_peer(const struct state_data *sdata,
		     bool normalpath, bool errorpath,
		     const struct trail *prev_trail,
		     struct hist *hist);

static void init_trail(struct trail *t,
		       enum state_input input,
		       const union input *idata,
		       const struct state_data *before,
		       const struct trail *prev)
{
	t->name = before->name;
	t->prev = prev;
	t->depth = prev ? prev->depth + 1 : 0;
	t->input = input;
	t->before = before;
	t->after = NULL;
	t->num_peer_outputs = -1;
	t->pkt_sent = NULL;
	if (input == CMD_SEND_HTLC_FULFILL
	    || input == INPUT_RVALUE
	    || input == BITCOIN_HTLC_TOTHEM_TIMEOUT
	    || input == BITCOIN_HTLC_TOTHEM_SPENT
	    || input == BITCOIN_HTLC_TOUS_TIMEOUT
	    || input == BITCOIN_HTLC_FULFILL_SPEND_DONE
	    || input == BITCOIN_HTLC_RETURN_SPEND_DONE) 
		t->htlc_id = idata->htlc->id;
	else if (input == PKT_UPDATE_ADD_HTLC)
		t->htlc_id = htlc_id_from_pkt(idata->pkt);
	else
		t->htlc_id = -1;
}

static void update_trail(struct trail *t,
			 const struct state_data *after,
			 const struct state_effect *effects)
{
	t->after = after;
	t->num_peer_outputs = after->peer->core.num_outputs;
	t->pkt_sent = (const char *)effects->send;
}

static void report_trail_rev(const struct trail *t)
{
	size_t i;

	if (t->prev)
		report_trail_rev(t->prev);

	fprintf(stderr, "%s: %s(%i) %s -> %s",
		t->name,
		input_name(t->input), t->htlc_id,
		state_name(t->before->core.state),
		t->after ? state_name(t->after->core.state) : "<unknown>");
	if (t->after) {
		for (i = 0; i < t->after->core.num_outputs; i++)
			fprintf(stderr, " >%s",
				input_name(t->after->core.outputs[i]));
	}
	fprintf(stderr, " +%u in\n",
		t->num_peer_outputs);
	if (!t->after)
		goto pkt_sent;

	if (t->after->core.state >= STATE_CLOSED) {
		if (t->after->num_live_htlcs_to_us
		    || t->after->num_live_htlcs_to_them) {
			fprintf(stderr, "  Live HTLCs:");
			for (i = 0; i < t->after->num_live_htlcs_to_us; i++)
				fprintf(stderr, " <%u",
					t->after->live_htlcs_to_us[i].id);
			for (i = 0; i < t->after->num_live_htlcs_to_them; i++)
				fprintf(stderr, " >%u",
					t->after->live_htlcs_to_them[i].id);
			fprintf(stderr, "\n");
		}
		if (t->after->num_htlc_spends_to_us
		    || t->after->num_htlc_spends_to_them) {
			fprintf(stderr, "  HTLC spends:");
			for (i = 0; i < t->after->num_htlc_spends_to_us; i++)
				fprintf(stderr, " <%u",
					t->after->htlc_spends_to_us[i].id);
			for (i = 0; i < t->after->num_htlc_spends_to_them; i++)
				fprintf(stderr, " <%u",
					t->after->htlc_spends_to_them[i].id);
			fprintf(stderr, "\n");
		}
	} else {
		if (t->after->num_htlcs_to_us
		    || t->after->num_htlcs_to_them) {
			fprintf(stderr, "  HTLCs:");
			for (i = 0; i < t->after->num_htlcs_to_us; i++)
				fprintf(stderr, " <%u",
					t->after->htlcs_to_us[i].id);
			for (i = 0; i < t->after->num_htlcs_to_them; i++)
				fprintf(stderr, " >%u",
					t->after->htlcs_to_them[i].id);
			fprintf(stderr, "\n");
		}
	}
pkt_sent:
	if (t->pkt_sent)
		fprintf(stderr, "  => %s\n", t->pkt_sent);
}

static void report_trail(const struct trail *t, const char *problem)
{
	fprintf(stderr, "Error: %s\n", problem);
	report_trail_rev(t);
	exit(1);
}

static bool is_current_command(const struct state_data *sdata,
			       enum state_input cmd)
{
	if (cmd == CMD_SEND_UPDATE_ANY) {
		return is_current_command(sdata, CMD_SEND_HTLC_UPDATE)
			|| is_current_command(sdata, CMD_SEND_HTLC_FULFILL)
			|| is_current_command(sdata, CMD_SEND_HTLC_TIMEDOUT)
			|| is_current_command(sdata, CMD_SEND_HTLC_ROUTEFAIL);
	}
	return sdata->core.current_command == cmd;
}

static void add_htlc(struct htlc *to_us, unsigned int *num_to_us,
		     struct htlc *to_them, unsigned int *num_to_them,
		     size_t arrsize,
		     const struct htlc *h)
{
	struct htlc *arr;
	unsigned int *n;

	if (h->to_them) {
		arr = to_them;
		n = num_to_them;
	} else {
		arr = to_us;
		n = num_to_us;
	}
	assert(*n < arrsize);
	arr[(*n)++] = *h;
}

static void remove_htlc(struct htlc *to_us, unsigned int *num_to_us,
			struct htlc *to_them, unsigned int *num_to_them,
			size_t arrsize,
			const struct htlc *h)
{
	size_t off;
	struct htlc *arr;
	unsigned int *n;

	if (h->to_them) {
		arr = to_them;
		n = num_to_them;
	} else {
		arr = to_us;
		n = num_to_us;
	}
	assert(*n <= arrsize);
	assert(h >= arr && h < arr + *n);

	off = h - arr;
	memmove(arr + off, arr + off + 1, (char *)(arr + *n) - (char *)(h + 1));
	(*n)--;
}

static bool outstanding_htlc_watches(const struct state_data *sdata)
{
	return sdata->num_live_htlcs_to_us
		|| sdata->num_live_htlcs_to_them
		|| sdata->num_htlc_spends_to_us
		|| sdata->num_htlc_spends_to_them;
}

static bool rval_known(const struct state_data *sdata, unsigned int id)
{
	unsigned int i;

	for (i = 0; i < sdata->num_rvals_known; i++)
		if (sdata->rvals_known[i] == id)
			return true;
	return false;
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
			    && !streq(pkt, "ERROR_PKT:Close timed out")
			    && !streq(pkt, "ERROR_PKT:Close forced due to HTLCs")) {
				return pkt;
			}
		}
		if (sdata->core.num_outputs >= ARRAY_SIZE(sdata->core.outputs))
			return "Too many outputs";
		sdata->core.outputs[sdata->core.num_outputs]
			= input_by_name(pkt);
		sdata->pkt_data[sdata->core.num_outputs++]
			= htlc_id_from_pkt(effect->send);
	}
	if (effect->watch) {
		/* We can have multiple steals or spendtheirs in flight,
		   so make exceptions for BITCOIN_STEAL_DONE/BITCOIN_SPEND_THEIRS_DONE */
		if (sdata->core.event_notifies & (1ULL << BITCOIN_STEAL_DONE)
		    & effect->watch->events)
			remove_event(&effect->watch->events, BITCOIN_STEAL_DONE);

		if (sdata->core.event_notifies
		    & (1ULL << BITCOIN_SPEND_THEIRS_DONE)
		    & effect->watch->events)
			remove_event(&effect->watch->events,
				     BITCOIN_SPEND_THEIRS_DONE);

		if (sdata->core.event_notifies & effect->watch->events)
			return "event set twice";
		sdata->core.event_notifies |= effect->watch->events;
	}
	if (effect->unwatch) {
		if ((sdata->core.event_notifies & effect->unwatch->events)
		    != effect->unwatch->events)
			return "unset event unwatched";
		sdata->core.event_notifies &= ~effect->unwatch->events;
	}
	if (effect->defer != INPUT_NONE) {
		/* If it was current command, it is no longer. */
		if (is_current_command(sdata, effect->defer))
			sdata->core.current_command = INPUT_NONE;
		else if (input_is_pkt(effect->defer)) {
			/* Unlike commands, which we always resubmit,
			 * we have to remember deferred packets. */
			/* We assume only one deferrment! */
			assert(sdata->core.deferred_pkt == INPUT_NONE
			       || sdata->core.deferred_pkt == effect->defer);
			sdata->core.deferred_pkt = effect->defer;
			sdata->core.deferred_state = sdata->core.state;
		}
	}
	if (effect->complete != INPUT_NONE) {
		if (!is_current_command(sdata, effect->complete)) {
			return tal_fmt(NULL, "Completed %s not %s",
				       input_name(effect->complete),
				       input_name(sdata->core.current_command));
		}
		sdata->core.current_command = INPUT_NONE;
	}
	if (effect->close_status != CMD_STATUS_ONGOING) {
		if (!sdata->core.closing_cmd)
			return tal_fmt(NULL, "%s but not closing",
				       effect->close_status == CMD_STATUS_SUCCESS ? "Success"
				       : "Failure");
		sdata->core.closing_cmd = false;
	}
	if (effect->stop_packets) {
		if (!sdata->core.pkt_inputs)
			return "stop_packets twice";
		sdata->core.pkt_inputs = false;

		/* Can no longer receive packet timeouts, either. */
		remove_event_(&sdata->core.event_notifies,
			      INPUT_CLOSE_COMPLETE_TIMEOUT);
	}
	if (effect->stop_commands) {
		if (!sdata->core.cmd_inputs)
			return "stop_commands twice";
		if (sdata->core.current_command != INPUT_NONE)
			return tal_fmt(NULL, "stop_commands with pending command %s",
				       input_name(sdata->core.current_command));
		if (sdata->core.closing_cmd)
			return "stop_commands with pending CMD_CLOSE";
		sdata->core.cmd_inputs = false;
	}
	if (effect->close_timeout != INPUT_NONE) {
		add_event(&sdata->core.event_notifies, effect->close_timeout);
		/* We assume this. */
		assert(effect->close_timeout == INPUT_CLOSE_COMPLETE_TIMEOUT);
	}
	if (effect->in_error) {
		/* We should stop talking to them after error received. */
		if (sdata->core.pkt_inputs)
			return "packets still open after error pkt";
	}
	/* We can abandon and add a new one, if we're LOWPRIO */
	if (effect->htlc_abandon) {
		if (sdata->current_htlc.htlc.id == -1)
			return "HTLC not in progress, can't abandon";
		if (effect->htlc_fulfill)
			return "Complete and abandon?";
		sdata->current_htlc.htlc.id = -1;
	}
	if (effect->htlc_in_progress) {
		if (sdata->current_htlc.htlc.id != -1)
			return "HTLC already in progress";
		if (effect->htlc_fulfill)
			return "Complete in one step?";
		sdata->current_htlc = *effect->htlc_in_progress;
	}
	if (effect->htlc_fulfill) {
		if (sdata->current_htlc.htlc.id == -1)
			return "HTLC not in progress, can't complete";

		if (sdata->current_htlc.adding) {
			add_htlc(sdata->htlcs_to_us, &sdata->num_htlcs_to_us,
				 sdata->htlcs_to_them,
				 &sdata->num_htlcs_to_them,
				 ARRAY_SIZE(sdata->htlcs_to_us),
				 &sdata->current_htlc.htlc);
		} else {
			const struct htlc *h;
			h = find_htlc(sdata, sdata->current_htlc.htlc.id);
			if (!h)
				return "Removing nonexistent HTLC?";
			if (h->to_them != sdata->current_htlc.htlc.to_them)
				return "Removing disagreed about to_them";
			remove_htlc(sdata->htlcs_to_us, &sdata->num_htlcs_to_us,
				    sdata->htlcs_to_them,
				    &sdata->num_htlcs_to_them,
				    ARRAY_SIZE(sdata->htlcs_to_us),
				    h);
		}
		sdata->current_htlc.htlc.id = -1;
	}

	if (effect->r_value) {
		/* We set r_value when they spend an HTLC, so we can set this
		 * multiple times (multiple commit txs) */
		if (!rval_known(sdata, effect->r_value->id)) {
			if (sdata->num_rvals_known
			    == ARRAY_SIZE(sdata->rvals_known))
				return "Too many rvals";

			sdata->rvals_known[sdata->num_rvals_known++]
				= effect->r_value->id;
		}
	}

	if (effect->watch_htlcs) {
		assert(sdata->num_live_htlcs_to_us
		       + effect->watch_htlcs->num_htlcs_to_us
		       <= ARRAY_SIZE(sdata->live_htlcs_to_us));
		assert(sdata->num_live_htlcs_to_them
		       + effect->watch_htlcs->num_htlcs_to_them
		       <= ARRAY_SIZE(sdata->live_htlcs_to_them));
		memcpy(sdata->live_htlcs_to_us + sdata->num_live_htlcs_to_us,
		       effect->watch_htlcs->htlcs_to_us,
		       effect->watch_htlcs->num_htlcs_to_us
		       * sizeof(effect->watch_htlcs->htlcs_to_us[0]));
		memcpy(sdata->live_htlcs_to_them + sdata->num_live_htlcs_to_them,
		       effect->watch_htlcs->htlcs_to_them,
		       effect->watch_htlcs->num_htlcs_to_them
		       * sizeof(effect->watch_htlcs->htlcs_to_them[0]));
		sdata->num_live_htlcs_to_us
			+= effect->watch_htlcs->num_htlcs_to_us;
		sdata->num_live_htlcs_to_them
			+= effect->watch_htlcs->num_htlcs_to_them;
		/* Can happen if we were finished, then new commit tx */
		remove_event_(&sdata->core.event_notifies, INPUT_NO_MORE_HTLCS);
	}
	if (effect->watch_htlc_spend) {
		const struct htlc *h;

		h = find_live_htlc(sdata, effect->watch_htlc_spend->id);
		add_htlc(sdata->htlc_spends_to_us, &sdata->num_htlc_spends_to_us,
			 sdata->htlc_spends_to_them,
			 &sdata->num_htlc_spends_to_them,
			 ARRAY_SIZE(sdata->htlc_spends_to_us),
			 h);

		/* We assume this */
		if (h->to_them)
			assert(effect->watch_htlc_spend->done
			       == BITCOIN_HTLC_RETURN_SPEND_DONE);
		else
			assert(effect->watch_htlc_spend->done
			       == BITCOIN_HTLC_FULFILL_SPEND_DONE);
	}
	if (effect->unwatch_htlc_spend) {
		const struct htlc *h;

		h = find_htlc_spend(sdata, effect->unwatch_htlc_spend->id);
		remove_htlc(sdata->htlc_spends_to_us,
			    &sdata->num_htlc_spends_to_us,
			    sdata->htlc_spends_to_them,
			    &sdata->num_htlc_spends_to_them,
			    ARRAY_SIZE(sdata->htlc_spends_to_us),
			    h);
		if (!outstanding_htlc_watches(sdata)) {
			assert(effect->unwatch_htlc_spend->done
			       == INPUT_NO_MORE_HTLCS);
			add_event(&sdata->core.event_notifies,
				  effect->unwatch_htlc_spend->done);
		}
	}
	if (effect->unwatch_htlc) {
		/* Unwatch all? */
		if (effect->unwatch_htlc->id == -1) {
			/* This can happen if we get in front of
			 * INPUT_NO_MORE_HTLCS */
			if (!outstanding_htlc_watches(sdata)
			    && !have_event(sdata->core.event_notifies,
					   INPUT_NO_MORE_HTLCS))
				return "unwatching all with no htlcs?";
			sdata->num_htlc_spends_to_us = 0;
			sdata->num_htlc_spends_to_them = 0;
			sdata->num_live_htlcs_to_us = 0;
			sdata->num_live_htlcs_to_them = 0;
		} else {
			const struct htlc *h;

			h = find_live_htlc(sdata, effect->unwatch_htlc->id);

			/* That can fail, when we see them spend (and
			 * thus stop watching) after we've timed out,
			 * then our return tx wins and gets buried. */
			if (h) {
				remove_htlc(sdata->live_htlcs_to_us,
					    &sdata->num_live_htlcs_to_us,
					    sdata->live_htlcs_to_them,
					    &sdata->num_live_htlcs_to_them,
					    ARRAY_SIZE(sdata->live_htlcs_to_us),
					    h);

				/* If that was last, fire INPUT_NO_MORE_HTLCS */
				if (!outstanding_htlc_watches(sdata)) {
					assert(effect->unwatch_htlc->all_done
					       == INPUT_NO_MORE_HTLCS);
					add_event(&sdata->core.event_notifies,
						  effect->unwatch_htlc->all_done);
				}
			}
		}
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
				
static void record_state(struct state_dump **sd,
			 enum state_input input,
			 enum state newstate,
			 const char *pktstr)
{
	size_t i, n = tal_count(*sd);
	enum state_input pkt;

	if (!pktstr)
		pkt = INPUT_NONE;
	else
		pkt = input_by_name(pktstr);

	for (i = 0; i < n; i++) {
		if ((*sd)[i].input != input)
			continue;
		if ((*sd)[i].next != newstate)
			continue;
		if ((*sd)[i].pkt != pkt)
			continue;
		/* Duplicate. */
		return;
	}
	tal_resize(sd, n+1);
	(*sd)[n].input = input;
	(*sd)[n].next = newstate;
	(*sd)[n].pkt = pkt;
}
				
static bool error_path(enum state_input i, enum state src, enum state dst)
{
	return state_is_error(dst) || i == PKT_ERROR;
}

static bool normal_path(enum state_input i, enum state src, enum state dst)
{
	if (error_path(i, src, dst))
		return false;

	/* Weird inputs. */
	if (i == BITCOIN_ANCHOR_TIMEOUT
	    || i == BITCOIN_ANCHOR_UNSPENT
	    || i == BITCOIN_ANCHOR_THEIRSPEND
	    || i == BITCOIN_ANCHOR_OTHERSPEND
	    || i == BITCOIN_STEAL_DONE
	    || i == PKT_UPDATE_DECLINE_HTLC
	    || i == PKT_UPDATE_ROUTEFAIL_HTLC
	    || i == PKT_UPDATE_TIMEDOUT_HTLC
	    || i == INPUT_CLOSE_COMPLETE_TIMEOUT)
		return false;

	return true;
}

/* These clutter the graph, so only handle from normal state. */
static bool too_cluttered(enum state_input i, enum state src)
{
	if (i == CMD_CLOSE || i == PKT_CLOSE || i == PKT_UPDATE_ADD_HTLC || i == PKT_UPDATE_FULFILL_HTLC)
		return src != STATE_NORMAL_LOWPRIO
			&& src != STATE_NORMAL_HIGHPRIO;
	return false;
}

static void add_dot(struct edge_hash *hash,
		    const char *oldstate,
		    const char *newstate,
		    enum state_input i,
		    const Pkt *pkt)
{
	struct dot_edge *d = tal(NULL, struct dot_edge);
	d->oldstate = oldstate;
	d->newstate = newstate;
	d->i = i;
	if (pkt)
		d->pkt = tal_strdup(d, (const char *)pkt);
	else
		d->pkt = NULL;

	if (edge_hash_get(hash, d))
		tal_free(d);
	else
		edge_hash_add(hash, d);
}

static const char *simplify_state(enum state s)
{
	/* Turn all high prio into low prio, and merge some open states */
	switch (s) {
	case STATE_OPEN_WAITING_OURANCHOR:
	case STATE_OPEN_WAITING_THEIRANCHOR:
		return "STATE_OPEN_WAITING";

	case STATE_OPEN_WAIT_FOR_COMPLETE_OURANCHOR:
	case STATE_OPEN_WAIT_FOR_COMPLETE_THEIRANCHOR:
		return "STATE_OPEN_WAIT_FOR_COMPLETE";

	case STATE_NORMAL_LOWPRIO:
	case STATE_NORMAL_HIGHPRIO:
		return "STATE_NORMAL";

	case STATE_WAIT_FOR_HTLC_ACCEPT_LOWPRIO:
	case STATE_WAIT_FOR_HTLC_ACCEPT_HIGHPRIO:
		return "STATE_WAIT_FOR_HTLC_ACCEPT";

	case STATE_WAIT_FOR_UPDATE_COMPLETE_LOWPRIO:
	case STATE_WAIT_FOR_UPDATE_COMPLETE_HIGHPRIO:
		return "STATE_WAIT_FOR_UPDATE_COMPLETE";

	case STATE_WAIT_FOR_UPDATE_SIG_LOWPRIO:
	case STATE_WAIT_FOR_UPDATE_SIG_HIGHPRIO:
		return "STATE_WAIT_FOR_UPDATE_SIG";

	default:
		return state_name(s);
	}
}

static bool waiting_statepair(enum state a, enum state b)
{
	if (a > b)
		return waiting_statepair(b, a);

	/* We don't need inputs if we're waiting for anchors. */
	if (a == STATE_OPEN_WAITING_OURANCHOR)
		return true;
	if (b == STATE_OPEN_WAITING_THEIRANCHOR)
		return true;

	/* We don't need inputs at start of main loop. */
	if (a == STATE_NORMAL_LOWPRIO
	    && b == STATE_NORMAL_HIGHPRIO)
		return true;

	return false;
}

static bool has_packets(const struct state_data *sdata)
{
	return sdata->core.deferred_pkt != INPUT_NONE
		|| sdata->core.num_outputs != 0;
}

static void try_input(const struct state_data *sdata,
		      enum state_input i,
		      const union input *idata,
		      bool normalpath, bool errorpath,
		      const struct trail *prev_trail,
		      struct hist *hist)
{
	struct state_data copy, peer;
	struct trail t;
	struct state_effect *effect = tal(NULL, struct state_effect);
	enum state newstate;
	const char *problem;

	state_effect_init(effect);
	copy_peers(&copy, &peer, sdata);

	copy.current_input = i;
	copy.current_idata = idata;
	init_trail(&t, i, idata, sdata, prev_trail);
	copy.trail = &t;

	eliminate_input(&hist->inputs_per_state[copy.core.state], i);
	newstate = state(copy.core.state, &copy, i, idata, effect);

	normalpath &= normal_path(i, sdata->core.state, newstate);
	errorpath |= error_path(i, sdata->core.state, newstate);

	if (dot_enable
	    && (dot_include_abnormal || normalpath)
	    && (dot_include_errors || !errorpath)
	    && (dot_include_abnormal || !too_cluttered(i, sdata->core.state))) {
		const char *oldstr, *newstr;

		/* Simplify folds high and low prio, skip "STATE_" */
		if (dot_simplify) {
			oldstr = simplify_state(sdata->core.state) + 6;
			newstr = simplify_state(newstate) + 6;
		} else {
			oldstr = state_name(sdata->core.state) + 6;
			newstr = state_name(newstate) + 6;
		}
		if (newstr != oldstr || include_nops)
			add_dot(&hist->edges, oldstr, newstr, i, effect->send);
	}

	copy.core.state = newstate;

	problem = apply_effects(&copy, effect);
	update_trail(&t, &copy, effect);
	if (problem)
		report_trail(&t, problem);

	if (newstate == STATE_ERR_INTERNAL)
		report_trail(&t, "Internal error");
	if (strstarts(state_name(newstate), "STATE_UNUSED"))
		report_trail(&t, "Unused state");


	/* Record any output. */
	if (effect->send) {
		record_output(&hist->outputs,
			      input_by_name((const char *)effect->send));
	}

	if (hist->state_dump) {
		record_state(&hist->state_dump[sdata->core.state], i, newstate,
			     (const char *)effect->send);
	}
	
	/* Have we been in this overall situation before? */
	if (!sithash_update(&hist->sithash, &copy)) {
		/*
		 * We expect to loop if:
		 * 1) We deferred, OR
		 * 2) We get repeated BITCOIN_ANCHOR_OTHERSPEND/THEIRSPEND, OR
		 * 3) We pass through NORMAL state.
		 *
		 * And if we're being quick, always stop.
		 */
		if (effect->defer != INPUT_NONE
		    || newstate == STATE_NORMAL_LOWPRIO
		    || newstate == STATE_NORMAL_HIGHPRIO
		    || i == BITCOIN_ANCHOR_OTHERSPEND
		    || i == BITCOIN_ANCHOR_THEIRSPEND
		    || quick) {
			tal_free(effect);
			return;
		}
		if (t.depth > STATE_MAX * 10)
			report_trail(&t, "Loop");
	}

	/* Don't continue if we reached a different error state. */
	if (state_is_error(newstate)) {
		tal_free(effect);
		return;
	}

	/*
	 * If we're listening, someone should be talking (usually).
	 */
	if (copy.core.pkt_inputs && !has_packets(&copy) && !has_packets(&peer)
	    && !waiting_statepair(copy.core.state, peer.core.state)) {
		report_trail(&t, "Deadlock");
	}

	/* Finished? */
	if (newstate == STATE_CLOSED) {
		if (copy.core.pkt_inputs)
			report_trail(&t, "CLOSED but taking packets?");

		if (copy.core.cmd_inputs)
			report_trail(&t, "CLOSED but taking commands?");

		if (copy.core.current_command != INPUT_NONE)
			report_trail(&t, input_name(copy.core.current_command));

		if (copy.current_htlc.htlc.id != -1)
			report_trail(&t, "CLOSED with htlc in progress?");

		if (outstanding_htlc_watches(&copy))
			report_trail(&t, "CLOSED but watching HTLCs?");
		tal_free(effect);
		return;
	}

	/* Try inputs from here down. */
	run_peer(&copy, normalpath, errorpath, &t, hist);

	/* Don't bother running other peer we can't communicate. */
	if (copy.core.pkt_inputs || peer.core.pkt_inputs)
		run_peer(&peer, normalpath, errorpath, &t, hist);
	tal_free(effect);
}

static void sanity_check(const struct state_data *sdata)
{
	if (sdata->core.state == STATE_NORMAL_LOWPRIO
	    || sdata->core.state == STATE_NORMAL_HIGHPRIO) {
		/* Home state: expect commands to be finished. */
		if (sdata->core.current_command != INPUT_NONE)
			errx(1, "Unexpected command %u in state %u",
			     sdata->core.current_command, sdata->core.state);
	}
}

static void activate_event(struct state_data *sdata, enum state_input i)
{
	/* Events are not independent. */
	switch (i) {
	case BITCOIN_ANCHOR_DEPTHOK:
		/* Can't sent TIMEOUT (may not be set) */
		remove_event_(&sdata->core.event_notifies, BITCOIN_ANCHOR_TIMEOUT);
		break;
	case BITCOIN_ANCHOR_TIMEOUT:
		/* Can't sent DEPTHOK */
		remove_event(&sdata->core.event_notifies, BITCOIN_ANCHOR_DEPTHOK);
		break;
	/* And of the "done" cases means we won't give the others. */
	case BITCOIN_SPEND_THEIRS_DONE:
	case BITCOIN_SPEND_OURS_DONE:
	case BITCOIN_STEAL_DONE:
	case BITCOIN_CLOSE_DONE:
		remove_event_(&sdata->core.event_notifies,
			      BITCOIN_SPEND_OURS_DONE);
		remove_event_(&sdata->core.event_notifies,
			      BITCOIN_SPEND_THEIRS_DONE);
		remove_event_(&sdata->core.event_notifies, BITCOIN_STEAL_DONE);
		remove_event_(&sdata->core.event_notifies, BITCOIN_CLOSE_DONE);
		remove_event_(&sdata->core.event_notifies,
			      BITCOIN_ANCHOR_OURCOMMIT_DELAYPASSED);
		remove_event_(&sdata->core.event_notifies,
			      BITCOIN_ANCHOR_THEIRSPEND);
		remove_event_(&sdata->core.event_notifies,
			      BITCOIN_ANCHOR_OTHERSPEND);
		remove_event_(&sdata->core.event_notifies,
			      BITCOIN_ANCHOR_UNSPENT);
		break;
	default:
		;
	}
}

static bool can_refire(enum state_input i)
{
	/* They could have lots of old HTLCS */
	if (i == BITCOIN_ANCHOR_OTHERSPEND)
		return true;
 	/* Signature malleability means any number of these */
	if (i == BITCOIN_ANCHOR_THEIRSPEND)
		return true;

	/* They could have lots of htlcs. */
	if (i == BITCOIN_HTLC_TOTHEM_SPENT || i == BITCOIN_HTLC_TOTHEM_TIMEOUT
	    || i == BITCOIN_HTLC_TOUS_TIMEOUT)
		return true;

	/* We manually remove these if they're not watching any more spends */
	if (i == BITCOIN_HTLC_RETURN_SPEND_DONE
	    || i == BITCOIN_HTLC_FULFILL_SPEND_DONE)
		return true;

	return false;
}

static unsigned int next_htlc_id(void)
{
	static unsigned int num;

	return ++num;
}

static void run_peer(const struct state_data *sdata,
		     bool normalpath, bool errorpath,
		     const struct trail *prev_trail,
		     struct hist *hist)
{
	struct state_data copy, peer;
	size_t i;
	uint64_t old_notifies;
	union input *idata = talz(NULL, union input);

	sanity_check(sdata);

	/* We want to frob some things... */
	copy_peers(&copy, &peer, sdata);
	
	/* Try the event notifiers */
	old_notifies = copy.core.event_notifies;
	for (i = 0; i < 64; i++) {
		if (!have_event(copy.core.event_notifies, i))
			continue;

		/* Don't re-fire most events */
		if (!can_refire(i))
			remove_event(&copy.core.event_notifies, i);
		activate_event(&copy, i);
		try_input(&copy, i, idata, normalpath, errorpath,
			  prev_trail, hist);
		copy.core.event_notifies = old_notifies;
	}

	/* We can send a close command even if already sending a
	 * (different) command. */
	if (sdata->core.state != STATE_INIT_WITHANCHOR
	    && sdata->core.state != STATE_INIT_NOANCHOR
	    && sdata->core.cmd_inputs
	    && !sdata->core.closing_cmd) {
		copy.core.closing_cmd = true;
		try_input(&copy, CMD_CLOSE, idata,
			  normalpath, errorpath, prev_trail, hist);
		copy.core.closing_cmd = false;
	}

	/* Try sending commands (unless in init state, closed or
	 * already doing one). */
	if (sdata->core.state != STATE_INIT_WITHANCHOR
	    && sdata->core.state != STATE_INIT_NOANCHOR
	    && sdata->core.cmd_inputs
	    && sdata->core.current_command == INPUT_NONE
	    && !sdata->core.closing_cmd) {
		unsigned int i;

		/* Add a new HTLC if not at max. */
		if (copy.num_htlcs_to_them < MAX_HTLCS) {
			copy.core.current_command = CMD_SEND_HTLC_UPDATE;
			idata->htlc_prog = tal(idata, struct htlc_progress);
			idata->htlc_prog->adding = true;
			idata->htlc_prog->htlc.to_them = true;
			idata->htlc_prog->htlc.id = next_htlc_id();
				
			try_input(&copy, copy.core.current_command, idata,
				  normalpath, errorpath,
				  prev_trail, hist);
			idata->htlc_prog = tal_free(idata->htlc_prog);
		}

		/* We can complete or routefail an HTLC they offered */
		for (i = 0; i < sdata->num_htlcs_to_us; i++) {
			idata->htlc_prog = tal(idata, struct htlc_progress);
			idata->htlc_prog->htlc = sdata->htlcs_to_us[i];
			idata->htlc_prog->adding = false;

			/* Only send this once. */
			if (!rval_known(sdata, idata->htlc_prog->htlc.id)) {
				copy.core.current_command
					= CMD_SEND_HTLC_FULFILL;
				try_input(&copy, copy.core.current_command,
					  idata, normalpath, errorpath,
					  prev_trail, hist);
			}
			copy.core.current_command = CMD_SEND_HTLC_ROUTEFAIL;
			try_input(&copy, copy.core.current_command,
				  idata, normalpath, errorpath,
				  prev_trail, hist);
		}

		/* We can timeout an HTLC we offered. */
		for (i = 0; i < sdata->num_htlcs_to_them; i++) {
			idata->htlc_prog = tal(idata, struct htlc_progress);
			idata->htlc_prog->htlc = sdata->htlcs_to_them[i];
			idata->htlc_prog->adding = false;

			copy.core.current_command = CMD_SEND_HTLC_TIMEDOUT;
			try_input(&copy, copy.core.current_command,
				  idata, normalpath, errorpath,
				  prev_trail, hist);
		}

		/* Restore current_command */
		copy.core.current_command = INPUT_NONE;
	}

	/* If they're watching HTLCs, we can send events. */
	for (i = 0; i < sdata->num_live_htlcs_to_us; i++) {
		idata->htlc = (struct htlc *)&copy.live_htlcs_to_us[i];
		/* Only send this once. */
		if (!rval_known(sdata, idata->htlc->id)) {
			try_input(&copy, INPUT_RVALUE,
				  idata, normalpath, errorpath,
				  prev_trail, hist);
		}
		try_input(&copy, BITCOIN_HTLC_TOUS_TIMEOUT,
			  idata, normalpath, errorpath,
			  prev_trail, hist);
	}

	for (i = 0; i < sdata->num_live_htlcs_to_them; i++) {
		idata->htlc = (struct htlc *)&copy.live_htlcs_to_them[i];
		try_input(&copy, BITCOIN_HTLC_TOTHEM_SPENT,
			  idata, normalpath, errorpath,
			  prev_trail, hist);
		try_input(&copy, BITCOIN_HTLC_TOTHEM_TIMEOUT,
			  idata, normalpath, errorpath,
			  prev_trail, hist);
	}

	/* If they're watching HTLC spends, we can send events. */
	for (i = 0; i < sdata->num_htlc_spends_to_us; i++) {
		idata->htlc = (struct htlc *)&copy.htlc_spends_to_us[i];
		try_input(&copy, BITCOIN_HTLC_FULFILL_SPEND_DONE,
			  idata, normalpath, errorpath,
			  prev_trail, hist);
	}
	for (i = 0; i < sdata->num_htlc_spends_to_them; i++) {
		idata->htlc = (struct htlc *)&copy.htlc_spends_to_them[i];
		try_input(&copy, BITCOIN_HTLC_RETURN_SPEND_DONE,
			  idata, normalpath, errorpath,
			  prev_trail, hist);
	}

	/* Allowed to send inputs? */
	if (copy.core.pkt_inputs) {
		enum state_input i;
		
		if (copy.core.deferred_pkt != INPUT_NONE) {
			/* Can only resubmit once state changed. */
			if (copy.core.state != copy.core.deferred_state) {
				i = copy.core.deferred_pkt;
				copy.core.deferred_pkt = INPUT_NONE;
				try_input(&copy, i, idata,
					  normalpath, errorpath,
					  prev_trail, hist);
			}
			/* Can't send anything until that's done. */
			return;
		}

		if (peer.core.num_outputs) {
			i = peer.core.outputs[0];
			if (peer.pkt_data[0] == -1U)
				idata->pkt = (Pkt *)talz(idata, char);
			else
				idata->pkt = htlc_pkt(idata, input_name(i),
						      peer.pkt_data[0]);

			/* Do the first, recursion does the rest. */
			memmove(peer.core.outputs, peer.core.outputs + 1,
				sizeof(peer.core.outputs)
				- sizeof(peer.core.outputs[0]));
			memmove(peer.pkt_data, peer.pkt_data + 1,
				sizeof(peer.pkt_data)-sizeof(peer.pkt_data[0]));
			peer.core.num_outputs--;
			/* Reset so that hashing doesn't get confused. */
			peer.core.outputs[peer.core.num_outputs] = 0;
			try_input(&copy, i, idata, normalpath, errorpath,
				  prev_trail, hist);
		}
	}
	tal_free(idata);
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
	unsigned int num = 0;

	for (h = sithash_first(sithash, &i); h; h = sithash_next(sithash, &i)) {
		num++;
		if (b) {
			if (h->a.s.valid && h->b.s.state == state)
				return true;
		} else {
			if (h->a.s.valid && h->a.s.state == state)
				return true;
		}
	}
	return false;
}

static int state_dump_cmp(const struct state_dump *a,
			  const struct state_dump *b,
			  void *unused)
{
	if (a->input != b->input)
		return a->input - b->input;
	if (a->next != b->next)
		return a->next - b->next;
	return 0;
}

int main(int argc, char *argv[])
{
	struct state_data a, b;
	unsigned int i;
	struct hist hist;
	bool dump_states = false;
	bool more_failpoints;

	err_set_progname(argv[0]);

	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   ""
			   "Test lightning state machine",
			   "Print this message.");
	opt_register_noarg("--dot",
			   opt_set_bool, &dot_enable,
			   "Output dot format for normal paths");
	opt_register_noarg("--dot-all",
			   opt_set_bool, &dot_include_abnormal,
			   "Output dot format for all non-error paths");
	opt_register_noarg("--dot-include-errors",
			   opt_set_bool, &dot_include_errors,
			   "Output dot format for error paths");
	opt_register_noarg("--include-nops",
			   opt_set_bool, &include_nops,
			   "Output even for inputs which don't change state");
	opt_register_noarg("--dot-simplify",
			   opt_set_bool, &dot_simplify,
			   "Merge high and low priority states");
	opt_register_noarg("--dump-states",
			   opt_set_bool, &dump_states,
			   "Summarize all state transitions");
	opt_register_version();

 	opt_parse(&argc, argv, opt_log_stderr_exit);
	if (dot_include_abnormal)
		dot_enable = true;
	if (dot_simplify && !dot_enable)
		opt_usage_exit_fail("--dot-simplify needs --dot/--dot-all");
	if (dot_include_errors && !dot_enable)
		opt_usage_exit_fail("--dot-include-errors needs --dot/--dot-all");
	if (include_nops && !dot_enable && !dump_states)
		opt_usage_exit_fail("--include-nops needs --dot/--dot-all/--dump-states");

	/* Map the inputs tested in each state. */
	hist.inputs_per_state = map_inputs();
	sithash_init(&hist.sithash);
	hist.outputs = tal_arr(NULL, enum state_input, 0);
	edge_hash_init(&hist.edges);
	if (dump_states) {
		hist.state_dump = tal_arr(NULL, struct state_dump *, STATE_MAX);
		for (i = 0; i < STATE_MAX; i++)
			hist.state_dump[i] = tal_arr(hist.state_dump,
						     struct state_dump, 0);
	} else
		hist.state_dump = NULL;

#if 0
	quick = dot_enable || dump_states;
#else
	quick = true;
#endif
	
	/* Initialize universe. */
	sdata_init(&a, &b, STATE_INIT_WITHANCHOR, "A");
	sdata_init(&b, &a, STATE_INIT_NOANCHOR, "B");
	if (!sithash_update(&hist.sithash, &a))
		abort();
	failhash_init(&failhash);

	/* Now, try each input in each state. */
	run_peer(&a, true, false, NULL, &hist);

	/* Now probe all the failure points */
	do {
		struct failpoint *f;
		struct failhash_iter i;
		more_failpoints = false;

		for (f = failhash_first(&failhash, &i);
		     f;
		     f = failhash_next(&failhash, &i)) {
			if (!f->failed) {
				try_input(&f->sdata, f->input, &f->idata,
					  false, true,
					  f->sdata.trail,
					  &hist);
				more_failpoints = true;
			}
		}
	} while (!more_failpoints);
	
	for (i = 0; i < STATE_MAX; i++) {
		bool a_expect = true, b_expect = true;

		/* Ignore unused states. */
		if (strstarts(state_name(i), "STATE_UNUSED"))
			continue;

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

	if (dot_enable) {
		struct dot_edge *d;
		struct edge_hash_iter i;

		printf("digraph lightning {\n");
		for (d = edge_hash_first(&hist.edges, &i);
		     d;
		     d = edge_hash_next(&hist.edges, &i)) {
			printf("%s -> %s ", d->oldstate, d->newstate);
			if (!d->pkt)
				printf("[label=\"<%s\"];\n", input_name(d->i));
			else {
				printf("[label=\"<%s\\n>%s\"];\n",
				       input_name(d->i), d->pkt);
			}
		}
		printf("}\n");
	}

	if (dump_states) {
		for (i = 0; i < STATE_MAX; i++) {
			size_t j;
			size_t n = tal_count(hist.state_dump[i]);
			if (!n)
				continue;
			printf("%s:\n", state_name(i) + 6);
			asort(hist.state_dump[i], n, state_dump_cmp, NULL);
			for (j = 0; j < n; j++) {
				if (!include_nops
				    && hist.state_dump[i][j].next == i)
					continue;
				printf("\t%s -> %s",
				       input_name(hist.state_dump[i][j].input),
				       state_name(hist.state_dump[i][j].next)+6);
				if (hist.state_dump[i][j].pkt != INPUT_NONE)
					printf(" (%s)",
					       input_name(hist.state_dump[i][j].pkt));
				printf("\n");
			}
		}
	}
					       
	return 0;
}	
