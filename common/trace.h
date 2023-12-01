#ifndef LIGHTNING_COMMON_TRACE_H
#define LIGHTNING_COMMON_TRACE_H
#include "config.h"
#include <ccan/short_types/short_types.h>

#define SPAN_ID_SIZE 8
#define TRACE_ID_SIZE 16

void trace_span_start(const char *name, const void *key);
void trace_span_end(const void *key);
void trace_span_suspend(const void *key);
void trace_span_resume(const void *key);
void trace_span_tag(const void *key, const char *name, const char *value);
void trace_cleanup(void);
void trace_span_remote(u8 trace_id[TRACE_ID_SIZE], u8 span_id[SPAN_ID_SIZE]);

#endif /* LIGHTNING_COMMON_TRACE_H */
