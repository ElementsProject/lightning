#ifndef LIGHTNING_COMMON_TRACE_H
#define LIGHTNING_COMMON_TRACE_H
#include "config.h"

void trace_span_start(const char *name, const void *key);
void trace_span_end(const void *key);
void trace_span_suspend(const void *key);
void trace_span_resume(const void *key);
void trace_span_tag(const void *key, const char *name, const char *value);
void trace_cleanup(void);

#endif /* LIGHTNING_COMMON_TRACE_H */
