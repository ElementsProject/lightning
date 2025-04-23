#include "config.h"
#include <assert.h>
#include <ccan/endian/endian.h>
#include <ccan/err/err.h>
#include <ccan/str/hex/hex.h>
#include <ccan/tal/str/str.h>
#include <ccan/tal/tal.h>
#include <ccan/time/time.h>
#include <common/json_stream.h>
#include <common/memleak.h>
#include <common/pseudorand.h>
#include <common/trace.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#if HAVE_USDT
  #include <sys/sdt.h>

/* The traceperent format is defined in W3C Trace Context RFC[1].
 * Its format is defined as
 *
 * ```
 * version-format   = trace-id "-" parent-id "-" trace-flags
 * trace-id         = 32HEXDIGLC  ; 16 bytes array identifier. All zeroes forbidden
 * parent-id        = 16HEXDIGLC  ; 8 bytes array identifier. All zeroes forbidden
 * trace-flags      = 2HEXDIGLC   ; 8 bit flags. Currently, only one bit is used.
 * ```
 *
 * [1] https://www.w3.org/TR/trace-context/
 */
#define TRACEPARENT_LEN (2 + 1 + 32 + 1 + 16 + 1 + 2)

#ifdef TRACE_DEBUG
#define TRACE_DBG(args...) fprintf(stderr, args)
#else
#define TRACE_DBG(args...)
#endif

const char *trace_service_name = "lightningd";
static bool disable_trace = false;
static FILE *trace_to_file = NULL;

#define SPAN_MAX_TAGS 2

struct span_tag {
	const char *name;
	const char *valuestr;
	int valuelen;
};

struct span {
	/* Our own id */
	u64 id;

	/* The trace_id for this span and all its children. */
	u64 trace_id_hi, trace_id_lo;

	u64 start_time;
	u64 end_time;

	/* The unique key used to find ourselves in the active
	 * spans. */
	size_t key;
	struct span *parent;
	struct span_tag tags[SPAN_MAX_TAGS];
	const char *name;

	bool suspended;
};

static struct span *active_spans = NULL;
static struct span *current;

static void init_span(struct span *s,
		      size_t key,
		      const char *name,
		      struct span *parent)
{
	struct timeabs now = time_now();

	s->key = key;
	s->id = pseudorand_u64();
	s->start_time = (now.ts.tv_sec * 1000000) + now.ts.tv_nsec / 1000;
	s->parent = parent;
	s->name = name;
	s->suspended = false;

	/* If this is a new root span we also need to associate a new
	 * trace_id with it. */
	if (!s->parent) {
		s->trace_id_hi = pseudorand_u64();
		s->trace_id_lo = pseudorand_u64();
	} else {
		s->trace_id_hi = current->trace_id_hi;
		s->trace_id_lo = current->trace_id_lo;
	}
}

/* FIXME: forward decls for minimal patch size */
static struct span *trace_span_slot(void);
static size_t trace_key(const void *key);
static void trace_span_clear(struct span *s);

/* If the `CLN_TRACEPARENT` envvar is set, we inject that as the
 * parent for the startup. This allows us to integrate the startup
 * tracing with whatever tooling we build around it. This only has an
 * effect if the envvar is set, otherwise the startup will create its
 * own parent. */
static void trace_inject_traceparent(void)
{
	const char *traceparent;
	be64 trace_hi, trace_lo, span;

	traceparent = getenv("CLN_TRACEPARENT");
	if (!traceparent)
		return;

	assert(strlen(traceparent) == TRACEPARENT_LEN);
	current = trace_span_slot();
	assert(current);

	init_span(current, trace_key(&active_spans), "", NULL);
	assert(current && !current->parent);

	if (!hex_decode(traceparent + 3, 16, &trace_hi, sizeof(trace_hi))
	    || !hex_decode(traceparent + 3 + 16, 16, &trace_lo, sizeof(trace_lo))
	    || !hex_decode(traceparent + 3 + 16 + 16 + 1, 16, &span, sizeof(span))) {
		/* We failed to parse the traceparent, abandon. */
		fprintf(stderr, "Failed!");
		trace_span_clear(current);
		current = NULL;
	} else {
		current->trace_id_hi = be64_to_cpu(trace_hi);
		current->trace_id_lo = be64_to_cpu(trace_lo);
		current->id = be64_to_cpu(span);
	}
}

#ifdef TRACE_DEBUG

/** Quickly print out the entries in the `active_spans`. */
static void trace_spans_print(void)
{
	for (size_t j = 0; j < tal_count(active_spans); j++) {
		struct span *s = &active_spans[j], *parent = s->parent;
		TRACE_DBG(" > %zu: %s (key=%zu, parent=%s, "
			  "parent_key=%zu)\n",
			  j, s->name, s->key, parent ? parent->name : "-",
			  parent ? parent->key : 0);
	}
}

/** Small helper to check for consistency in the linking. The idea is
 * that we should be able to reach the root (a span without a
 * `parent`) in less than the number of spans. */
static void trace_check_tree(void)
{
	/* `current` is either NULL or a valid entry. */

	/* Walk the tree structure from leaves to their roots. It
	 * should not take more than the number of spans. */
	struct span *c;
	for (size_t i = 0; i < tal_count(active_spans); i++) {
		c = &active_spans[i];
		for (int j = 0; j < tal_count(active_spans); j++)
			if (c->parent == NULL)
				break;
			else
				c = c->parent;
		if (c->parent != NULL) {
			TRACE_DBG("Cycle in the trace tree structure!\n");
			trace_spans_print();
			abort();
		}

		assert(c->parent == NULL);
	}
}
#else
static inline void trace_check_tree(void) {}
#endif

static void trace_init(void)
{
	const char *dev_trace_file;
	if (active_spans)
		return;

	active_spans = notleak(tal_arrz(NULL, struct span, 1));

	current = NULL;
	dev_trace_file = getenv("CLN_DEV_TRACE_FILE");
	if (dev_trace_file) {
		const char *fname = tal_fmt(tmpctx, "%s.%u",
					    dev_trace_file, (unsigned)getpid());
		trace_to_file = fopen(fname, "a+");
		if (!trace_to_file)
			err(1, "Opening CLN_DEV_TRACE_FILE %s", fname);
	}
	trace_inject_traceparent();
}

/**
 * Convert the pointer to a context object to a numeric key.
 */
static size_t trace_key(const void *key)
{
	return (size_t)key;
}

static struct span *trace_span_find(size_t key)
{
	for (size_t i = 0; i < tal_count(active_spans); i++)
		if (active_spans[i].key == key)
			return &active_spans[i];

	/* Return NULL to signal that there is no such span yet. Used
	 * to check for accidental collisions that'd reuse the span
	 * `key`. */
	return NULL;
}

/**
 * Find an empty slot for a new span.
 */
static struct span *trace_span_slot(void)
{
	/* Empty slots are defined as having `key=NULL`, so search for
	 * that, and we should get an empty slot. */
	struct span *s = trace_span_find(0);

	/* In the unlikely case this fails, double it */
	if (!s) {
		TRACE_DBG("%u: out of %zu spans, doubling!\n",
			  getpid(), tal_count(active_spans));
		tal_resizez(&active_spans, tal_count(active_spans) * 2);
		s = trace_span_find(0);
	}
	assert(s->parent == NULL);

	/* Be extra careful not to create cycles. If we return the
	 * position that is pointed at by current then we can only
	 * stub the trace by removing the parent link here. */
	if (s == current)
		current = NULL;

	return s;
}

#define MAX_BUF_SIZE 2048

static void trace_emit(struct span *s)
{
	char span_id[hex_str_size(sizeof(s->id))];
	char buffer[MAX_BUF_SIZE + 1];
	size_t len;

	snprintf(span_id, sizeof(span_id), "%016"PRIx64, s->id);
	len = snprintf(buffer, MAX_BUF_SIZE,
		       "[{\"id\":\"%s\",\"name\":\"%s\","
		       "\"timestamp\":%"PRIu64",\"duration\":%"PRIu64","
		       "\"localEndpoint\":{\"serviceName\":\"%s\"},",
		       span_id, s->name, s->start_time, s->end_time - s->start_time, trace_service_name);

	if (s->parent != NULL) {
		len += snprintf(buffer + len, MAX_BUF_SIZE - len,
				"\"parentId\":\"%016"PRIx64"\",",
				s->parent->id);
		if (len > MAX_BUF_SIZE)
			len = MAX_BUF_SIZE;
	}

	len += snprintf(buffer + len, MAX_BUF_SIZE - len,
			"\"tags\":{");
	if (len > MAX_BUF_SIZE)
		len = MAX_BUF_SIZE;
	for (size_t i = 0; i < SPAN_MAX_TAGS; i++) {
		if (!s->tags[i].name)
			continue;
		len += snprintf(buffer + len, MAX_BUF_SIZE - len,
				"%s\"%s\":\"%.*s\"", i == 0 ? "" : ", ",
				s->tags[i].name,
				s->tags[i].valuelen,
				s->tags[i].valuestr);
		if (len > MAX_BUF_SIZE)
			len = MAX_BUF_SIZE;
	}

	len += snprintf(buffer + len, MAX_BUF_SIZE - len,
			"},\"traceId\":\"%016"PRIx64"%016"PRIx64"\"}]",
			s->trace_id_hi, s->trace_id_lo);
	if (len > MAX_BUF_SIZE)
		len = MAX_BUF_SIZE;
	buffer[len] = '\0';
	/* FIXME: span_id here is in hex, could be u64? */
	DTRACE_PROBE2(lightningd, span_emit, span_id, buffer);
	if (trace_to_file) {
		fprintf(trace_to_file, "span_emit %s %s\n", span_id, buffer);
		fflush(trace_to_file);
	}
}

/**
 * Release the span back into the pool of available spans.
 */
static void trace_span_clear(struct span *s)
{
	memset(s, 0, sizeof(*s));
}

void trace_span_start_(const char *name, const void *key)
{
	size_t numkey = trace_key(key);

	if (disable_trace)
		return;
	trace_init();
	trace_check_tree();

	assert(trace_span_find(numkey) == NULL);
	struct span *s = trace_span_slot();
	if (!s)
		return;
	init_span(s, numkey, name, current);
	current = s;
	trace_check_tree();
	DTRACE_PROBE1(lightningd, span_start, s->id);
	if (trace_to_file) {
		fprintf(trace_to_file, "span_start %016"PRIx64"\n", s->id);
		fflush(trace_to_file);
	}
}

void trace_span_remote(u64 trace_id_hi, u64 trade_id_lo, u64 span_id)
{
	abort();
}

void trace_span_end(const void *key)
{
	if (disable_trace)
		return;

	size_t numkey = trace_key(key);
	struct span *s = trace_span_find(numkey);
	assert(s && "Span to end not found");
	assert(s == current && "Ending a span that isn't the current one");

	trace_check_tree();

	struct timeabs now = time_now();
	s->end_time = (now.ts.tv_sec * 1000000) + now.ts.tv_nsec / 1000;
	DTRACE_PROBE1(lightningd, span_end, s->id);
	if (trace_to_file) {
		fprintf(trace_to_file, "span_end %016"PRIx64"\n", s->id);
		fflush(trace_to_file);
	}
	trace_emit(s);

	/* Reset the context span we are in. */
	current = s->parent;

	/* Now reset the span */
	trace_span_clear(s);
	trace_check_tree();
}

void trace_span_tag(const void *key, const char *name, const char *value)
{
	if (disable_trace)
		return;

	assert(name);
	size_t numkey = trace_key(key);
	struct span *span = trace_span_find(numkey);
	assert(span);

	for (size_t i = 0; i < SPAN_MAX_TAGS; i++) {
		struct span_tag *t = &span->tags[i];
		if (!t->name) {
			t->name = name;
			t->valuestr = value;
			t->valuelen = strlen(value);
			if (t->valuestr[0] == '"'
			    && t->valuelen > 1
			    && t->valuestr[t->valuelen-1] == '"') {
				t->valuestr++;
				t->valuelen -= 2;
			}
			return;
		}
	}
	abort();
}

void trace_span_suspend_(const void *key, const char *lbl)
{
	if (disable_trace)
		return;

	size_t numkey = trace_key(key);
	struct span *span = trace_span_find(numkey);
	TRACE_DBG("Suspending span %s (%zu)\n", current->name, current->key);
	assert(current == span);
 	assert(!span->suspended);
	span->suspended = true;
	current = current->parent;
	DTRACE_PROBE1(lightningd, span_suspend, span->id);
	if (trace_to_file) {
		fprintf(trace_to_file, "span_suspend %016"PRIx64"\n", span->id);
		fflush(trace_to_file);
	}
}

static void destroy_trace_span(const void *key)
{
	size_t numkey = trace_key(key);
	struct span *span = trace_span_find(numkey);

	/* It's usually ended normally. */
	if (!span)
		return;

	/* Otherwise resume so we can terminate it */
	if (trace_to_file)
		fprintf(trace_to_file, "destroying span\n");
	trace_span_resume(key);
	trace_span_end(key);
}

void trace_span_suspend_may_free_(const void *key, const char *lbl)
{
	if (disable_trace)
		return;
	trace_span_suspend_(key, lbl);
	tal_add_destructor(key, destroy_trace_span);
}

void trace_span_resume_(const void *key, const char *lbl)
{
	if (disable_trace)
		return;

	size_t numkey = trace_key(key);
	current = trace_span_find(numkey);
 	assert(current->suspended);
	current->suspended = false;
	TRACE_DBG("Resuming span %s (%zu)\n", current->name, current->key);
	DTRACE_PROBE1(lightningd, span_resume, current->id);
	if (trace_to_file) {
		fprintf(trace_to_file, "span_resume %016"PRIx64"\n", current->id);
		fflush(trace_to_file);
	}
}

void trace_cleanup(void)
{
	active_spans = tal_free(active_spans);
}

#else /* HAVE_USDT */

void trace_span_start_(const char *name, const void *key) {}
void trace_span_end(const void *key) {}
void trace_span_suspend_(const void *key, const char *lbl) {}
void trace_span_suspend_may_free_(const void *key, const char *lbl) {}
void trace_span_resume_(const void *key, const char *lbl) {}
void trace_span_tag(const void *key, const char *name, const char *value) {}
void trace_cleanup(void) {}

#endif /* HAVE_USDT */
