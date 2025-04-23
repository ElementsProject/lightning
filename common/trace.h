#ifndef LIGHTNING_COMMON_TRACE_H
#define LIGHTNING_COMMON_TRACE_H
#include "config.h"
#include <ccan/short_types/short_types.h>

#undef TRACE_DEBUG

/* name must be a string constant */
#define trace_span_start(name, key) trace_span_start_(name "", (key))
void trace_span_start_(const char *name, const void *key);
void trace_span_end(const void *key);
void trace_span_tag(const void *key, const char *name, const char *value);
void trace_cleanup(void);
void trace_span_remote(u64 trace_id_hi, u64 trade_id_lo, u64 span_id);

#define TRACE_LBL __FILE__ ":" stringify(__LINE__)
void trace_span_suspend_(const void *key, const char *lbl);
void trace_span_suspend_may_free_(const void *key, const char *lbl);
void trace_span_resume_(const void *key, const char *lbl);
#define trace_span_suspend(key) trace_span_suspend_(key, TRACE_LBL)
#define trace_span_suspend_may_free(key) trace_span_suspend_may_free_(key, TRACE_LBL)
#define trace_span_resume(key) trace_span_resume_(key, TRACE_LBL)

#endif /* LIGHTNING_COMMON_TRACE_H */
