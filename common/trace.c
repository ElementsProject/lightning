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

static void trace_free(void)
{
	current = NULL;
	free(active_spans);
	active_spans = NULL;
}

static void trace_init(void) {
	if (active_spans)
		return;
	active_spans = calloc(MAX_ACTIVE_SPANS, sizeof(struct span));

	current = NULL;
	trace_inject_traceparent();
	atexit(trace_free);
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

	return NULL;
}

/**
 * Find an empty slot for a new span.
 */
static struct span *trace_span_slot(void)
{
	struct span *s = trace_span_find(0);

	/* Might end up here if we have more than MAX_ACTIVE_SPANS
	 * concurrent spans. */
	assert(s);
	assert(s->parent == NULL);
	assert(s != current);
	return s;
}

static const struct span *trace_span_root(const struct span *s)
{
	if (s->parent)
		return trace_span_root(s->parent);
	return s;
}

static void trace_emit(struct span *s)
{
	const struct span *root = trace_span_root(s);
	char span_id[HEX_SPAN_ID_SIZE];
	char trace_id[HEX_TRACE_ID_SIZE];
	char parent_span_id[HEX_SPAN_ID_SIZE];

	/* If this is a remote span it's not up to us to emit it. Make
	 * this a no-op. `trace_span_end` will take care of cleaning
	 * the in-memory span up. */
	if (s->remote)
		return;

	hex_encode(s->id, SPAN_ID_SIZE, span_id, HEX_SPAN_ID_SIZE);
	hex_encode(root->trace_id, TRACE_ID_SIZE, trace_id, HEX_TRACE_ID_SIZE);

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
	memset(s->trace_id, 0, TRACE_ID_SIZE);;
	s->parent = NULL;
	s->name = tal_free(s->name);
	s->tags = tal_free(s->tags);
}

void trace_span_start(const char *name, const void *key)
{
	size_t numkey = trace_key(key);
	struct timeabs now = time_now();

	trace_init();

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
	}

	current = s;
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

	if (s != current) {
		fprintf(stderr, "Ending current span %s with a span %s, is this a mixup?\n", current->name, s->name);
		abort();
	}

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

void trace_span_suspend(const void *key)
{
	size_t numkey = trace_key(key);
	struct span *span = trace_span_find(numkey);
	current = NULL;
	DTRACE_PROBE1(lightningd, span_suspend, span->id);
}

void trace_span_resume(const void *key)
{
	size_t numkey = trace_key(key);
	current = trace_span_find(numkey);
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
void trace_span_suspend(const void *key) {}
void trace_span_resume(const void *key) {}
void trace_span_tag(const void *key, const char *name, const char *value) {}
void trace_cleanup(void) {}

#endif /* HAVE_USDT */
