#include "config.h"
#include <assert.h>
#include <ccan/htable/htable.h>
#include <ccan/str/hex/hex.h>
#include <ccan/tal/str/str.h>
#include <ccan/tal/tal.h>
#include <ccan/time/time.h>
#include <common/json_stream.h>
#include <common/memleak.h>
#include <common/trace.h>
#include <sodium/randombytes.h>
#include <stdio.h>

#if HAVE_USDT
#include <sys/sdt.h>

#define MAX_ACTIVE_SPANS 128

#define HEX_SPAN_ID_SIZE (2*SPAN_ID_SIZE+1)
#define HEX_TRACE_ID_SIZE (2 * TRACE_ID_SIZE + 1)

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

struct span_tag {
	char *name, *value;
};

struct span {
	/* Our own id */
	u8 id[SPAN_ID_SIZE];

	/* 0 if we have no parent. */
	u8 parent_id[SPAN_ID_SIZE];

	/* The trace_id for this span and all its children. */
	u8 trace_id[TRACE_ID_SIZE];

	u64 start_time;
	u64 end_time;

	/* The unique key used to find ourselves in the active
	 * spans. */
	size_t key;
	struct span *parent;
	struct span_tag *tags;
	char *name;

	/* Indicate whether this is a remote span, i.e., it was
	inherited by some other process, which is in charge of
	emitting the span. This just means that we don't emit this
	span ourselves, but we want to add child spans to the remote
	span. */
	bool remote;
};

static struct span *active_spans = NULL;
static struct span *current;

/* If the `CLN_TRACEPARENT` envvar is set, we inject that as the
 * parent for the startup. This allows us to integrate the startup
 * tracing with whatever tooling we build around it. This only has an
 * effect if the envvar is set, otherwise the startup will create its
 * own parent. */
static void trace_inject_traceparent(void)
{
	char *traceparent;
	traceparent = getenv("CLN_TRACEPARENT");
	if (!traceparent)
		return;

	assert(strlen(traceparent) == TRACEPARENT_LEN);
	trace_span_start("", active_spans);
	current->remote = true;
	assert(current && !current->parent);
	if (!hex_decode(traceparent + 3, 2*TRACE_ID_SIZE, current->trace_id,
			TRACE_ID_SIZE) ||
	    !hex_decode(traceparent + 36, 2*SPAN_ID_SIZE, current->id,
			SPAN_ID_SIZE)) {
		/* We failed to parse the traceparent, abandon. */
		fprintf(stderr, "Failed!");
		trace_span_end(active_spans);
	}
}

#ifdef TRACE_DEBUG

/** Quickly print out the entries in the `active_spans`. */
static void trace_spans_print(void)
{
	for (size_t j = 0; j < MAX_ACTIVE_SPANS; j++) {
		struct span *s = &active_spans[j], *parent = s->parent;
		TRACE_DBG(" > %zu: %s (key=%zu, parent=%s, "
			  "parent_key=%zu)\n",
			  j, s->name, s->key, parent ? parent->name : "-",
			  parent ? parent->key : 0);
	}
}

/** Small helper to check for consistency in the linking. The idea is
 * that we should be able to reach the root (a span without a
 * `parent`) in less than `MAX_ACTIVE_SPANS` steps. */
static void trace_check_tree(void)
{
	/* `current` is either NULL or a valid entry. */

	/* Walk the tree structure from leaves to their roots. It
	 * should not take more than `MAX_ACTIVE_SPANS`. */
	struct span *c;
	for (size_t i = 0; i < MAX_ACTIVE_SPANS; i++) {
		c = &active_spans[i];
		for (int j = 0; j < MAX_ACTIVE_SPANS; j++)
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
	if (active_spans)
		return;
	active_spans = calloc(MAX_ACTIVE_SPANS, sizeof(struct span));

	current = NULL;
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
	for (size_t i = 0; i < MAX_ACTIVE_SPANS; i++)
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

	/* Might end up here if we have more than MAX_ACTIVE_SPANS
	 * concurrent spans. */
	assert(s);
	assert(s->parent == NULL);

	/* Be extra careful not to create cycles. If we return the
	 * position that is pointed at by current then we can only
	 * stub the trace by removing the parent link here. */
	if (s == current)
		current = NULL;

	return s;
}

static void trace_emit(struct span *s)
{
	char span_id[HEX_SPAN_ID_SIZE];
	char trace_id[HEX_TRACE_ID_SIZE];
	char parent_span_id[HEX_SPAN_ID_SIZE];

	/* If this is a remote span it's not up to us to emit it. Make
	 * this a no-op. `trace_span_end` will take care of cleaning
	 * the in-memory span up. */
	if (s->remote)
		return;

	hex_encode(s->id, SPAN_ID_SIZE, span_id, HEX_SPAN_ID_SIZE);
	hex_encode(s->trace_id, TRACE_ID_SIZE, trace_id, HEX_TRACE_ID_SIZE);

	if (s->parent)
		hex_encode(s->parent_id, SPAN_ID_SIZE, parent_span_id, HEX_SPAN_ID_SIZE);

	char *res = tal_fmt(
	    NULL,
	    "[{\"id\": \"%s\", \"name\": \"%s\", "
	    "\"timestamp\": %" PRIu64 ", \"duration\": %" PRIu64 ",",
	    span_id, s->name, s->start_time, s->end_time - s->start_time);

	tal_append_fmt(&res, "\"localEndpoint\": { \"serviceName\": \"%s\"}, ",
		       trace_service_name);

	if (s->parent != NULL) {
		tal_append_fmt(&res, "\"parentId\": \"%s\",", parent_span_id);
	}

	tal_append_fmt(&res, "\"tags\": {");
	for (size_t i = 0; i < tal_count(s->tags); i++) {
		tal_append_fmt(&res, "%s\"%s\": \"%s\"", i == 0 ? "" : ", ",
			       s->tags[i].name, s->tags[i].value);
	}

	tal_append_fmt(&res, "}, \"traceId\": \"%s\"}]", trace_id);
	DTRACE_PROBE2(lightningd, span_emit, span_id, res);
	tal_free(res);
}

/**
 * Release the span back into the pool of available spans.
 */
static void trace_span_clear(struct span *s)
{
	s->key = 0;
	memset(s->id, 0, SPAN_ID_SIZE);
	memset(s->trace_id, 0, TRACE_ID_SIZE);
	;
	s->parent = NULL;
	s->name = tal_free(s->name);
	s->tags = tal_free(s->tags);
}

void trace_span_start(const char *name, const void *key)
{
	size_t numkey = trace_key(key);
	struct timeabs now = time_now();

	trace_init();
	trace_check_tree();

	assert(trace_span_find(numkey) == NULL);
	struct span *s = trace_span_slot();
	s->key = numkey;
	randombytes_buf(s->id, SPAN_ID_SIZE);
	s->start_time = (now.ts.tv_sec * 1000000) + now.ts.tv_nsec / 1000;
	s->parent = current;
	s->tags = notleak(tal_arr(NULL, struct span_tag, 0));
	s->name = notleak(tal_strdup(NULL, name));

	/* If this is a new root span we also need to associate a new
	 * trace_id with it. */
	if (!current) {
		randombytes_buf(s->trace_id, TRACE_ID_SIZE);
	} else {
		memcpy(s->parent_id, current->id, SPAN_ID_SIZE);
		memcpy(s->trace_id, current->trace_id, TRACE_ID_SIZE);
	}

	current = s;
	trace_check_tree();
	DTRACE_PROBE1(lightningd, span_start, s->id);
}

void trace_span_remote(u8 trace_id[TRACE_ID_SIZE], u8 span_id[SPAN_ID_SIZE])
{
	abort();
}

void trace_span_end(const void *key)
{
	size_t numkey = trace_key(key);
	struct span *s = trace_span_find(numkey);
	assert(s && "Span to end not found");
	assert(s == current && "Ending a span that isn't the current one");

	trace_check_tree();

	struct timeabs now = time_now();
	s->end_time = (now.ts.tv_sec * 1000000) + now.ts.tv_nsec / 1000;
	DTRACE_PROBE1(lightningd, span_end, s->id);
	trace_emit(s);

	/* Reset the context span we are in. */
	current = s->parent;

	/* Now reset the span */
	trace_span_clear(s);

	/* One last special case: if the parent is remote, it must be
	 * the root. And we should terminate that trace along with
	 * this one. */
	if (current && current->remote) {
		assert(current->parent == NULL);
		current = NULL;
	}
	trace_check_tree();
}

void trace_span_tag(const void *key, const char *name, const char *value)
{
	size_t numkey = trace_key(key);
	struct span *span = trace_span_find(numkey);
	assert(span);

	size_t s = tal_count(span->tags);
	tal_resize(&span->tags, s + 1);
	span->tags[s].name = tal_strdup(span->tags, name);
	if (strstarts(value, "\"")
		&& strlen(value) > 1
		&& strends(value, "\"")) {
		value = tal_strndup(tmpctx, value + 1,
			strlen(value) - 2);
	}
	span->tags[s].value = tal_strdup(span->tags, value);
}

void trace_span_suspend_(const void *key, const char *lbl)
{
	size_t numkey = trace_key(key);
	struct span *span = trace_span_find(numkey);
	TRACE_DBG("Suspending span %s (%zu)\n", current->name, current->key);
	assert(current == span);
	current = NULL;
	DTRACE_PROBE1(lightningd, span_suspend, span->id);
}

void trace_span_resume_(const void *key, const char *lbl)
{
	size_t numkey = trace_key(key);
	current = trace_span_find(numkey);
	TRACE_DBG("Resuming span %s (%zu)\n", current->name, current->key);
	DTRACE_PROBE1(lightningd, span_resume, current->id);
}

void trace_cleanup(void)
{
	free(active_spans);
	active_spans = NULL;
}

#else /* HAVE_USDT */

void trace_span_start(const char *name, const void *key) {}
void trace_span_end(const void *key) {}
void trace_span_suspend_(const void *key, const char *lbl) {}
void trace_span_resume_(const void *key, const char *lbl) {}
void trace_span_tag(const void *key, const char *name, const char *value) {}
void trace_cleanup(void) {}

#endif /* HAVE_USDT */
