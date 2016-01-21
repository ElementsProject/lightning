#ifndef LIGHTNING_DAEMON_LOG_H
#define LIGHTNING_DAEMON_LOG_H
#include "config.h"
#include <ccan/tal/tal.h>
#include <ccan/typesafe_cb/typesafe_cb.h>
#include <stdarg.h>

struct timerel;

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

/* We have a single record. */
struct log_record *new_log_record(const tal_t *ctx,
				  size_t max_mem,
				  enum log_level printlevel);

/* With different entry points */
struct log *PRINTF_FMT(3,4)
new_log(const tal_t *ctx, struct log_record *record, const char *fmt, ...);

#define log_debug(log, ...) log_((log), LOG_DBG, __VA_ARGS__)
#define log_info(log, ...) log_((log), LOG_INFORM, __VA_ARGS__)
#define log_unusual(log, ...) log_((log), LOG_UNUSUAL, __VA_ARGS__)
#define log_broken(log, ...) log_((log), LOG_BROKEN, __VA_ARGS__)

void log_io(struct log *log, bool in, const void *data, size_t len);

void log_(struct log *log, enum log_level level, const char *fmt, ...)
	PRINTF_FMT(3,4);
void log_add(struct log *log, const char *fmt, ...) PRINTF_FMT(2,3);
void log_add_hex(struct log *log, const void *data, size_t len);
void logv(struct log *log, enum log_level level, const char *fmt, va_list ap);

#define log_add_struct(log, structtype, ptr)				\
	log_add_struct_((log), stringify(structtype),			\
		((void)sizeof((ptr) == (structtype *)NULL), (ptr)))

#define log_add_enum(log, enumtype, val)				\
	log_add_enum_((log), stringify(enumtype), (val))

void log_add_struct_(struct log *log, const char *structname, const void *ptr);
void log_add_enum_(struct log *log, const char *enumname, unsigned int val);

void set_log_level(struct log_record *lr, enum log_level level);
void set_log_prefix(struct log *log, const char *prefix);
const char *log_prefix(const struct log *log);
#define set_log_outfn(lr, print, arg)					\
	set_log_outfn_((lr),						\
		       typesafe_cb_preargs(void, void *, (print), (arg),\
					   const char *,		\
					   enum log_level,		\
					   bool,			\
					   const char *), (arg))

void set_log_outfn_(struct log_record *lr,
		    void (*print)(const char *prefix,
				  enum log_level level,
				  bool continued,
				  const char *str, void *arg),
		    void *arg);

size_t log_max_mem(const struct log_record *lr);
size_t log_used(const struct log_record *lr);
const struct timeabs *log_init_time(const struct log_record *lr);

#define log_each_line(lr, func, arg)					\
	log_each_line_((lr),						\
		       typesafe_cb_preargs(void, void *, (func), (arg),	\
					   unsigned int,		\
					   struct timerel,		\
					   enum log_level,		\
					   const char *,		\
					   const char *), (arg))

void log_each_line_(const struct log_record *lr,
		    void (*func)(unsigned int skipped,
				 struct timerel time,
				 enum log_level level,
				 const char *prefix,
				 const char *log,
				 void *arg),
		    void *arg);


void log_dump_to_file(int fd, const struct log_record *lr);
void opt_register_logging(struct log *log);
void crashlog_activate(struct log *log);

/* Before the crashlog is activated, just prints to stderr. */
void NORETURN PRINTF_FMT(1,2) fatal(const char *fmt, ...);
#endif /* LIGHTNING_DAEMON_LOG_H */
