#ifndef LIGHTNING_LIGHTNINGD_LOG_H
#define LIGHTNING_LIGHTNINGD_LOG_H
#include "config.h"
#include <ccan/tal/tal.h>
#include <ccan/time/time.h>
#include <ccan/typesafe_cb/typesafe_cb.h>
#include <common/type_to_string.h>
#include <stdarg.h>

struct lightningd;
struct timerel;
struct lightningd;

enum log_level {
	/* Logging all IO. */
	LOG_IO,
	/* Gory details which are mainly good for debugging. */
	LOG_DBG,
	/* Information about what's going in. */
	LOG_INFORM,
	/* That's strange... */
	LOG_UNUSUAL,
	/* That's really bad, we're broken. */
	LOG_BROKEN
};

/* We can have a single log book, with multiple logs in it. */
struct log_book *new_log_book(const tal_t *ctx,
			      size_t max_mem,
			      enum log_level printlevel);

/* With different entry points */
struct log *new_log(const tal_t *ctx, struct log_book *record, const char *fmt, ...) PRINTF_FMT(3,4);

#define log_debug(log, ...) log_((log), LOG_DBG, __VA_ARGS__)
#define log_info(log, ...) log_((log), LOG_INFORM, __VA_ARGS__)
#define log_unusual(log, ...) log_((log), LOG_UNUSUAL, __VA_ARGS__)
#define log_broken(log, ...) log_((log), LOG_BROKEN, __VA_ARGS__)

void log_io(struct log *log, bool in, const void *data, size_t len);

void log_(struct log *log, enum log_level level, const char *fmt, ...)
	PRINTF_FMT(3,4);
void log_add(struct log *log, const char *fmt, ...) PRINTF_FMT(2,3);
void logv(struct log *log, enum log_level level, const char *fmt, va_list ap);
void logv_add(struct log *log, const char *fmt, va_list ap);

enum log_level get_log_level(struct log_book *lr);
void set_log_level(struct log_book *lr, enum log_level level);
void set_log_prefix(struct log *log, const char *prefix);
const char *log_prefix(const struct log *log);
#define set_log_outfn(lr, print, arg)					\
	set_log_outfn_((lr),						\
		       typesafe_cb_preargs(void, void *, (print), (arg),\
					   const char *,		\
					   enum log_level,		\
					   bool,			\
					   const struct timeabs *,	\
					   const char *), (arg))

void set_log_outfn_(struct log_book *lr,
		    void (*print)(const char *prefix,
				  enum log_level level,
				  bool continued,
				  const struct timeabs *time,
				  const char *str, void *arg),
		    void *arg);

size_t log_max_mem(const struct log_book *lr);
size_t log_used(const struct log_book *lr);
const struct timeabs *log_init_time(const struct log_book *lr);

#define log_each_line(lr, func, arg)					\
	log_each_line_((lr),						\
		       typesafe_cb_preargs(void, void *, (func), (arg),	\
					   unsigned int,		\
					   struct timerel,		\
					   enum log_level,		\
					   const char *,		\
					   const char *), (arg))

void log_each_line_(const struct log_book *lr,
		    void (*func)(unsigned int skipped,
				 struct timerel time,
				 enum log_level level,
				 const char *prefix,
				 const char *log,
				 void *arg),
		    void *arg);


void log_dump_to_file(int fd, const struct log_book *lr);
void opt_register_logging(struct lightningd *ld);
void crashlog_activate(const char *argv0, struct log *log);

char *arg_log_to_file(const char *arg, struct lightningd *ld);

/* Convenience parent for temporary allocations (eg. type_to_string)
 * during log calls; freed after every log_*() */
const tal_t *ltmp;

/* Before the crashlog is activated, just prints to stderr. */
void NORETURN PRINTF_FMT(1,2) fatal(const char *fmt, ...);

#endif /* LIGHTNING_LIGHTNINGD_LOG_H */
