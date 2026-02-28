#ifndef LIGHTNING_LIGHTNINGD_LOG_H
#define LIGHTNING_LIGHTNINGD_LOG_H
#include "config.h"
#include <ccan/time/time.h>
#include <common/status.h>
#include <jsmn.h>

struct command;
struct json_stream;
struct lightningd;
struct node_id;
struct timerel;

/* We can have a single log book, with multiple loggers writing to it: it's freed
 * by the last struct logger itself. */
struct log_book *new_log_book(struct lightningd *ld, size_t max_mem);

/* With different entry points */
struct logger *new_logger(const tal_t *ctx, struct log_book *record,
			  const struct node_id *default_node_id,
			  const char *fmt, ...) PRINTF_FMT(4,5);

#define log_trace(logger, ...) log_((logger), LOG_TRACE, NULL, false, __VA_ARGS__)
#define log_debug(logger, ...) log_((logger), LOG_DBG, NULL, false, __VA_ARGS__)
#define log_info(logger, ...) log_((logger), LOG_INFORM, NULL, false, __VA_ARGS__)
#define log_unusual(logger, ...) log_((logger), LOG_UNUSUAL, NULL, true, __VA_ARGS__)
#define log_broken(logger, ...) log_((logger), LOG_BROKEN, NULL, true, __VA_ARGS__)

#define log_peer_trace(logger, nodeid, ...) log_((logger), LOG_TRACE, nodeid, false, __VA_ARGS__)
#define log_peer_debug(logger, nodeid, ...) log_((logger), LOG_DBG, nodeid, false, __VA_ARGS__)
#define log_peer_info(logger, nodeid, ...) log_((logger), LOG_INFORM, nodeid, false, __VA_ARGS__)
#define log_peer_unusual(logger, nodeid, ...) log_((logger), LOG_UNUSUAL, nodeid, true, __VA_ARGS__)
#define log_peer_broken(logger, nodeid, ...) log_((logger), LOG_BROKEN, nodeid, true, __VA_ARGS__)

void log_io(struct logger *logger, enum log_level dir,
	    const struct node_id *node_id,
	    const char *comment,
	    const void *data, size_t len);

void log_(struct logger *logger, enum log_level level,
	  const struct node_id *node_id,
	  bool call_notifier,
	  const char *fmt, ...)
	PRINTF_FMT(5,6);
void logv(struct logger *logger, enum log_level level, const struct node_id *node_id,
	  bool call_notifier, const char *fmt, va_list ap);

const char *log_prefix(const struct logger *logger);
/* Is there any chance we do io-level logging for this node_id in log? */
bool log_has_io_logging(const struct logger *log);
/* How about trace logging? */
bool log_has_trace_logging(const struct logger *log);

void opt_register_logging(struct lightningd *ld);

char *arg_log_to_file(const char *arg, struct lightningd *ld);

/* Once this is set, we dump fatal with a backtrace to this log */
extern struct logger *crashlog;
void NORETURN PRINTF_FMT(1,2) fatal(const char *fmt, ...);
void NORETURN fatal_vfmt(const char *fmt, va_list ap);

void log_backtrace_print(const char *fmt, ...);
void log_backtrace_exit(void);

/* Adds an array showing log entries */
void json_add_log(struct json_stream *result,
		  const struct log_book *log_book,
		  const struct node_id *node_id,
		  enum log_level minlevel);

struct command_result *param_loglevel(struct command *cmd,
				      const char *name,
				      const char *buffer,
				      const jsmntok_t *tok,
				      enum log_level **level);

/* Reference counted log_prefix.  Log entries keep a pointer, and they
 * can outlast the log entry point which created them. */
struct log_prefix {
	size_t refcnt;
	const char *prefix;
};

struct log_entry {
	struct timeabs time;
	enum log_level level;
	unsigned int skipped;
	struct node_id_cache *nc;
	struct log_prefix *prefix;
	char *log;
	/* Iff LOG_IO */
	const u8 *io;
};

/* For options.c's listconfig */
char *opt_log_level(const char *arg, struct log_book *log_book);
void json_add_opt_log_levels(struct json_stream *response, struct log_book *log_book);
void logging_options_parsed(struct log_book *log_book);
#endif /* LIGHTNING_LIGHTNINGD_LOG_H */
