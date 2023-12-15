#include "config.h"
#include <assert.h>
#include <ccan/htable/htable.h>
#include <ccan/short_types/short_types.h>
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
#define SPAN_ID_LEN 33

const char *trace_service_name = "lightningd";

struct span_tag {
	char *name, *value;
};

struct span {
	size_t key;
	u64 id;
	struct span *parent;
	u64 start_time;
	u64 end_time;
	struct span_tag *tags;
	char *name;
};

/* All traces we emit are prefixed with this constant. */
static u64 trace_prefix = 0;
static struct span *active_spans;
static struct span *current;
static size_t last_span_id;

static void trace_span_id_serialize(struct span *s, char *dest)
{
	hex_encode(&trace_prefix, 8, dest, 17);
	hex_encode(&s->id, 8, 16 + dest, 17);
}

static void trace_init(void) {
	randombytes_buf(&trace_prefix, sizeof(u64));
	active_spans = malloc(sizeof(struct span) * MAX_ACTIVE_SPANS);
	last_span_id = 1;
	current = NULL;
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

static void trace_emit(struct span *s)
{
	char id[SPAN_ID_LEN];
	trace_span_id_serialize(s, id);

	char *res = tal_fmt(
	    NULL,
	    "[{\"id\": \"%s\", \"name\": \"%s\", "
	    "\"timestamp\": %" PRIu64 ", \"duration\": %" PRIu64 ",",
	    id + 16, s->name, s->start_time, s->end_time - s->start_time);

	tal_append_fmt(&res, "\"localEndpoint\": { \"serviceName\": \"%s\"}, ",
		       trace_service_name);

	if (s->parent != NULL) {
		trace_span_id_serialize(s->parent, id);
		tal_append_fmt(&res, "\"parentId\": \"%s\",", id + 16);
	}

	tal_append_fmt(&res, "\"tags\": {");
	for (size_t i = 0; i < tal_count(s->tags); i++) {
		tal_append_fmt(&res, "%s\"%s\": \"%s\"", i == 0 ? "" : ", ",
			       s->tags[i].name, s->tags[i].value);
	}

	trace_span_id_serialize(s, id);
	tal_append_fmt(&res, "}, \"traceId\": \"%.*s\"}]", 16, id);
	DTRACE_PROBE2(lightningd, span_emit, id, res);
	tal_free(res);
}

/**
 * Release the span back into the pool of available spans.
 */
static void trace_span_clear(struct span *s)
{
	s->key = 0;
	s->id = 0;
	s->parent = NULL;
	s->name = tal_free(s->name);
	s->tags = tal_free(s->tags);
}

void trace_span_start(const char *name, const void *key)
{
	if (!trace_prefix)
		trace_init();

	size_t numkey = trace_key(key);
	struct timeabs now = time_now();

	assert(trace_span_find(numkey) == NULL);
	struct span *s = trace_span_slot();
	assert(current == NULL || current->id != 0);
	// assert(current != s);
	s->key = numkey;
	s->id = last_span_id++;
	s->start_time = (now.ts.tv_sec * 1000000) + now.ts.tv_nsec / 1000;
	s->parent = current;
	s->tags = notleak(tal_arr(NULL, struct span_tag, 0));
	s->name = notleak(tal_strdup(NULL, name));
	current = s;
	DTRACE_PROBE1(lightningd, span_start, s->id);
}

void trace_span_end(const void *key)
{
	size_t numkey = trace_key(key);
	struct span *s = trace_span_find(numkey);
	assert(s && "Span to end not found");
	assert(s == current && "Ending a span that isn't the current one");

	struct timeabs now = time_now();
	s->end_time = (now.ts.tv_sec * 1000000) + now.ts.tv_nsec / 1000;
	DTRACE_PROBE1(lightningd, span_end, s->id);
	trace_emit(s);

	/* Reset the context span we are in. */
	current = s->parent;

	/* Now reset the span */
	trace_span_clear(s);
}

void trace_span_tag(const void *key, const char *name, const char *value)
{
	size_t numkey = trace_key(key);
	struct span *span = trace_span_find(numkey);
	assert(span);

	size_t s = tal_count(span->tags);
	tal_resize(&span->tags, s + 1);
	span->tags[s].name = tal_strdup(span->tags, name);
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
