#include "config.h"
#include <assert.h>
#include <ccan/array_size/array_size.h>
#include <ccan/crypto/siphash24/siphash24.h>
#include <ccan/endian/endian.h>
#include <ccan/err/err.h>
#include <ccan/htable/htable_type.h>
#include <ccan/str/hex/hex.h>
#include <ccan/tal/str/str.h>
#include <common/json_stream.h>
#include <common/memleak.h>
#include <common/pseudorand.h>
#include <common/trace.h>
#include <inttypes.h>
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

static size_t span_keyof(const struct span *span)
{
	return span->key;
}

static size_t span_key_hash(size_t key)
{
	return siphash24(siphash_seed(), &key, sizeof(key));
}

static bool span_key_eq(const struct span *span, size_t key)
{
	return span->key == key;
}
HTABLE_DEFINE_NODUPS_TYPE(struct span, span_keyof, span_key_hash, span_key_eq,
			  span_htable);

static struct span fixed_spans[8];
static struct span_htable *spans = NULL;
static struct span *current;

static void init_span(struct span *s,
		      size_t key,
		      const char *name,
		      struct span *parent)
{
	struct timeabs now = time_now(); /* discouraged: but tracing wants non-dev time */

	s->key = key;
	s->id = pseudorand_u64();
	s->start_time = (now.ts.tv_sec * 1000000) + now.ts.tv_nsec / 1000;
	s->parent = parent;
	s->name = name;
	s->suspended = false;
	for (size_t i = 0; i < SPAN_MAX_TAGS; i++)
		s->tags[i].name = NULL;

	/* If this is a new root span we also need to associate a new
	 * trace_id with it. */
	if (!s->parent) {
		s->trace_id_hi = pseudorand_u64();
		s->trace_id_lo = pseudorand_u64();
	} else {
		s->trace_id_hi = current->trace_id_hi;
		s->trace_id_lo = current->trace_id_lo;
	}
	span_htable_add(spans, s);
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

	init_span(current, trace_key(&spans), "", NULL);
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

static void memleak_scan_spans(struct htable *memtable, struct span_htable *spantable)
{
	struct span_htable_iter i;
	const struct span *span;

	for (span = span_htable_first(spantable, &i);
	     span;
	     span = span_htable_next(spantable, &i)) {
		memleak_ptr(memtable, span);
		memleak_scan_region(memtable, span, sizeof(*span));
	}
}

static void trace_init(void)
{
	const char *dev_trace_file;

	if (spans)
		return;

	/* We can't use new_htable here because we put non-tal
	 * objects in our htable, and that breaks memleak_scan_htable! */
	spans = notleak(tal(NULL, struct span_htable));
	memleak_add_helper(spans, memleak_scan_spans);
	span_htable_init(spans);

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
	return span_htable_get(spans, key);
}

/**
 * Find an empty slot for a new span.
 */
static struct span *trace_span_slot(void)
{
	/* Look for a free fixed slot. */
	for (size_t i = 0; i < ARRAY_SIZE(fixed_spans); i++) {
		if (fixed_spans[i].key == 0)
			return &fixed_spans[i];
	}

	/* Those are used up, we have to allocate. */
	return tal(spans, struct span);
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
	if (!span_htable_del(spans, s))
		abort();

	/* If s is actually in fixed_spans, just zero it out. */
	if (s >= fixed_spans && s < fixed_spans + ARRAY_SIZE(fixed_spans)) {
		s->key = 0;
		return;
	}

	/* Dynamically allocated, so we need to free it */
	tal_free(s);
}

void trace_span_start_(const char *name, const void *key)
{
	size_t numkey = trace_key(key);

	if (disable_trace)
		return;
	trace_init();

	assert(trace_span_find(numkey) == NULL);
	struct span *s = trace_span_slot();
	if (!s)
		return;
	init_span(s, numkey, name, current);
	current = s;
	DTRACE_PROBE1(lightningd, span_start, s->id);
	if (trace_to_file) {
		fprintf(trace_to_file, "span_start %016"PRIx64" %s\n", s->id, name);
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

	struct timeabs now = time_now(); /* discouraged: but tracing wants non-dev time */
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
	spans = tal_free(spans);
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
