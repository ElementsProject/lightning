#include "log.h"
#include <backtrace-supported.h>
#include <backtrace.h>
#include <ccan/array_size/array_size.h>
#include <ccan/list/list.h>
#include <ccan/opt/opt.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/str/hex/hex.h>
#include <ccan/tal/link/link.h>
#include <ccan/tal/str/str.h>
#include <common/memleak.h>
#include <common/pseudorand.h>
#include <common/utils.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/jsonrpc_errors.h>
#include <lightningd/lightningd.h>
#include <lightningd/options.h>
#include <lightningd/param.h>
#include <signal.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* Once we're up and running, this is set up. */
struct log *crashlog;

struct log_entry {
	struct list_node list;
	struct timeabs time;
	enum log_level level;
	unsigned int skipped;
	const char *prefix;
	char *log;
	/* Iff LOG_IO */
	const u8 *io;
};

struct log_book {
	size_t mem_used;
	size_t max_mem;
	void (*print)(const char *prefix,
		      enum log_level level,
		      bool continued,
		      const struct timeabs *time,
		      const char *str, const u8 *io, void *arg);
	void *print_arg;
	enum log_level print_level;
	struct timeabs init_time;

	struct list_head log;
};

struct log {
	struct log_book *lr;
	const char *prefix;
};

static void log_to_file(const char *prefix,
			enum log_level level,
			bool continued,
			const struct timeabs *time,
			const char *str,
			const u8 *io,
			FILE *logf)
{
	char iso8601_msec_fmt[sizeof("YYYY-mm-ddTHH:MM:SS.%03dZ")];
	strftime(iso8601_msec_fmt, sizeof(iso8601_msec_fmt), "%FT%T.%%03dZ", gmtime(&time->ts.tv_sec));
	char iso8601_s[sizeof("YYYY-mm-ddTHH:MM:SS.nnnZ")];
	snprintf(iso8601_s, sizeof(iso8601_s), iso8601_msec_fmt, (int) time->ts.tv_nsec / 1000000);

	if (level == LOG_IO_IN || level == LOG_IO_OUT) {
		const char *dir = level == LOG_IO_IN ? "[IN]" : "[OUT]";
		char *hex = tal_hex(NULL, io);
		fprintf(logf, "%s %s%s%s %s\n",
			iso8601_s, prefix, str, dir, hex);
		tal_free(hex);
	} else 	if (!continued) {
		fprintf(logf, "%s %s %s\n", iso8601_s, prefix, str);
	} else {
		fprintf(logf, "%s %s \t%s\n", iso8601_s, prefix, str);
	}
	fflush(logf);
}

static void log_to_stdout(const char *prefix,
			  enum log_level level,
			  bool continued,
			  const struct timeabs *time,
			  const char *str,
			  const u8 *io, void *unused UNUSED)
{
	log_to_file(prefix, level, continued, time, str, io, stdout);
}

static size_t mem_used(const struct log_entry *e)
{
	return sizeof(*e) + strlen(e->log) + 1 + tal_count(e->io);
}

static size_t prune_log(struct log_book *log)
{
	struct log_entry *i, *next, *tail;
	size_t skipped = 0, deleted = 0;

	/* Never delete the last one. */
	tail = list_tail(&log->log, struct log_entry, list);

	list_for_each_safe(&log->log, i, next, list) {
		/* 50% chance of deleting IO_IN, 25% IO_OUT, 12.5% DEBUG... */
		if (i == tail || !pseudorand(2 << i->level)) {
			i->skipped += skipped;
			skipped = 0;
			continue;
		}

		list_del_from(&log->log, &i->list);
		log->mem_used -= mem_used(i);
		tal_free(i);
		skipped++;
		deleted++;
	}

	assert(!skipped);
	return deleted;
}

struct log_book *new_log_book(size_t max_mem,
			      enum log_level printlevel)
{
	struct log_book *lr = tal_linkable(tal(NULL, struct log_book));

	/* Give a reasonable size for memory limit! */
	assert(max_mem > sizeof(struct log) * 2);
	lr->mem_used = 0;
	lr->max_mem = max_mem;
	lr->print = log_to_stdout;
	lr->print_level = printlevel;
	lr->init_time = time_now();
	list_head_init(&lr->log);

	return lr;
}

/* With different entry points */
struct log *PRINTF_FMT(3,4)
new_log(const tal_t *ctx, struct log_book *record, const char *fmt, ...)
{
	struct log *log = tal(ctx, struct log);
	va_list ap;

	log->lr = tal_link(log, record);
	va_start(ap, fmt);
	/* log->lr owns this, since its entries keep a pointer to it. */
	/* FIXME: Refcount this! */
	log->prefix = notleak(tal_vfmt(log->lr, fmt, ap));
	va_end(ap);

	return log;
}

struct log_book *get_log_book(const struct log *log)
{
	return log->lr;
}

enum log_level get_log_level(struct log_book *lr)
{
	return lr->print_level;
}

void set_log_level(struct log_book *lr, enum log_level level)
{
	lr->print_level = level;
}

void set_log_prefix(struct log *log, const char *prefix)
{
	/* log->lr owns this, since it keeps a pointer to it. */
	log->prefix = tal_strdup(log->lr, prefix);
}

void set_log_outfn_(struct log_book *lr,
		    void (*print)(const char *prefix,
				  enum log_level level,
				  bool continued,
				  const struct timeabs *time,
				  const char *str, const u8 *io, void *arg),
		    void *arg)
{
	lr->print = print;
	lr->print_arg = arg;
}

const char *log_prefix(const struct log *log)
{
	return log->prefix;
}

size_t log_max_mem(const struct log_book *lr)
{
	return lr->max_mem;
}

size_t log_used(const struct log_book *lr)
{
	return lr->mem_used;
}

const struct timeabs *log_init_time(const struct log_book *lr)
{
	return &lr->init_time;
}

static void add_entry(struct log *log, struct log_entry *l)
{
	log->lr->mem_used += mem_used(l);
	list_add_tail(&log->lr->log, &l->list);

	if (log->lr->mem_used > log->lr->max_mem) {
		size_t old_mem = log->lr->mem_used, deleted;
		deleted = prune_log(log->lr);
		log_debug(log, "Log pruned %zu entries (mem %zu -> %zu)",
			  deleted, old_mem, log->lr->mem_used);
	}
}

static struct log_entry *new_log_entry(struct log *log, enum log_level level)
{
	struct log_entry *l = tal(log->lr, struct log_entry);

	l->time = time_now();
	l->level = level;
	l->skipped = 0;
	l->prefix = log->prefix;
	l->io = NULL;

	return l;
}

static void maybe_print(const struct log *log, const struct log_entry *l,
			size_t offset)
{
	if (l->level >= log->lr->print_level)
		log->lr->print(log->prefix, l->level, offset != 0,
			       &l->time, l->log + offset,
			       l->io, log->lr->print_arg);
}

void logv(struct log *log, enum log_level level, const char *fmt, va_list ap)
{
	int save_errno = errno;
	struct log_entry *l = new_log_entry(log, level);

	l->log = tal_vfmt(l, fmt, ap);

	size_t log_len = strlen(l->log);

	/* Sanitize any non-printable characters, and replace with '?' */
	for (size_t i=0; i<log_len; i++)
		if (l->log[i] < ' ' || l->log[i] >= 0x7f)
			l->log[i] = '?';

	maybe_print(log, l, 0);

	add_entry(log, l);
	errno = save_errno;
}

void log_io(struct log *log, enum log_level dir,
	    const char *str TAKES,
	    const void *data TAKES, size_t len)
{
	int save_errno = errno;
	struct log_entry *l = new_log_entry(log, dir);

	assert(dir == LOG_IO_IN || dir == LOG_IO_OUT);

	l->log = tal_strdup(l, str);
	l->io = tal_dup_arr(l, u8, data, len, 0);

	maybe_print(log, l, 0);
	add_entry(log, l);
	errno = save_errno;
}

void logv_add(struct log *log, const char *fmt, va_list ap)
{
	struct log_entry *l = list_tail(&log->lr->log, struct log_entry, list);
	size_t oldlen = strlen(l->log);

	/* Remove from list, so it doesn't get pruned. */
	log->lr->mem_used -= mem_used(l);
	list_del_from(&log->lr->log, &l->list);

	tal_append_vfmt(&l->log, fmt, ap);

	/* Sanitize any non-printable characters, and replace with '?' */
	for (size_t i=oldlen; i<strlen(l->log); i++)
		if (l->log[i] < ' ' || l->log[i] >= 0x7f)
			l->log[i] = '?';

	add_entry(log, l);

	maybe_print(log, l, oldlen);
}

void log_(struct log *log, enum log_level level, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	logv(log, level, fmt, ap);
	va_end(ap);
}

void log_add(struct log *log, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	logv_add(log, fmt, ap);
	va_end(ap);
}

void log_each_line_(const struct log_book *lr,
		    void (*func)(unsigned int skipped,
				 struct timerel time,
				 enum log_level level,
				 const char *prefix,
				 const char *log,
				 const u8 *io,
				 void *arg),
		    void *arg)
{
	const struct log_entry *i;

	list_for_each(&lr->log, i, list) {
		func(i->skipped, time_between(i->time, lr->init_time),
		     i->level, i->prefix, i->log, i->io, arg);
	}
}

struct log_data {
	int fd;
	const char *prefix;
};

static void log_one_line(unsigned int skipped,
			 struct timerel diff,
			 enum log_level level,
			 const char *prefix,
			 const char *log,
			 const u8 *io,
			 struct log_data *data)
{
	char buf[101];

	if (skipped) {
		snprintf(buf, sizeof(buf), "%s... %u skipped...", data->prefix, skipped);
		write_all(data->fd, buf, strlen(buf));
		data->prefix = "\n";
	}

	snprintf(buf, sizeof(buf), "%s+%lu.%09u %s%s: ",
		data->prefix,
		(unsigned long)diff.ts.tv_sec,
		(unsigned)diff.ts.tv_nsec,
		prefix,
		level == LOG_IO_IN ? "IO_IN"
		: level == LOG_IO_OUT ? "IO_OUT"
		: level == LOG_DBG ? "DEBUG"
		: level == LOG_INFORM ? "INFO"
		: level == LOG_UNUSUAL ? "UNUSUAL"
		: level == LOG_BROKEN ? "BROKEN"
		: "**INVALID**");

	write_all(data->fd, buf, strlen(buf));
	write_all(data->fd, log, strlen(log));
	if (level == LOG_IO_IN || level == LOG_IO_OUT) {
		size_t off, used, len = tal_count(io);

		/* No allocations, may be in signal handler. */
		for (off = 0; off < len; off += used) {
			used = len - off;
			if (hex_str_size(used) > sizeof(buf))
				used = hex_data_size(sizeof(buf));
			hex_encode(io + off, used, buf, hex_str_size(used));
			write_all(data->fd, buf, strlen(buf));
		}
	}

	data->prefix = "\n";
}

static struct {
	const char *name;
	enum log_level level;
} log_levels[] = {
	{ "IO", LOG_IO_OUT },
	{ "DEBUG", LOG_DBG },
	{ "INFO", LOG_INFORM },
	{ "UNUSUAL", LOG_UNUSUAL },
	{ "BROKEN", LOG_BROKEN }
};

static char *arg_log_level(const char *arg, struct log *log)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(log_levels); i++) {
		if (strcasecmp(arg, log_levels[i].name) == 0) {
			set_log_level(log->lr, log_levels[i].level);
			return NULL;
		}
	}
	return tal_fmt(NULL, "unknown log level");
}

static void show_log_level(char buf[OPT_SHOW_LEN], const struct log *log)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(log_levels); i++) {
		if (log->lr->print_level == log_levels[i].level) {
			strncpy(buf, log_levels[i].name, OPT_SHOW_LEN-1);
			return;
		}
	}
	abort();
}

static char *arg_log_prefix(const char *arg, struct log *log)
{
	set_log_prefix(log, arg);
	return NULL;
}

static void show_log_prefix(char buf[OPT_SHOW_LEN], const struct log *log)
{
	strncpy(buf, log->prefix, OPT_SHOW_LEN);
}

char *arg_log_to_file(const char *arg, struct lightningd *ld)
{
	FILE *logf;

	if (ld->logfile) {
		fclose(ld->log->lr->print_arg);
		ld->logfile = tal_free(ld->logfile);
	}
	ld->logfile = tal_strdup(ld, arg);
	logf = fopen(arg, "a");
	if (!logf)
		return tal_fmt(NULL, "Failed to open: %s", strerror(errno));
	set_log_outfn(ld->log->lr, log_to_file, logf);
	return NULL;
}

void opt_register_logging(struct lightningd *ld)
{
	opt_register_arg("--log-level", arg_log_level, show_log_level, ld->log,
			 "log level (debug, info, unusual, broken)");
	opt_register_arg("--log-prefix", arg_log_prefix, show_log_prefix,
			 ld->log,
			 "log prefix");
	opt_register_arg("--log-file=<file>", arg_log_to_file, NULL, ld,
			 "log to file instead of stdout");
}

void log_backtrace_print(const char *fmt, ...)
{
	va_list ap;

	if (!crashlog)
		return;

	va_start(ap, fmt);
	logv(crashlog, LOG_BROKEN, fmt, ap);
	va_end(ap);
}

static void log_dump_to_file(int fd, const struct log_book *lr)
{
	const struct log_entry *i;
	char buf[100];
	int len;
	struct log_data data;
	time_t start;

	write_all(fd, "Start of new crash log\n",
		  strlen("Start of new crash log\n"));

	i = list_top(&lr->log, const struct log_entry, list);
	if (!i) {
		write_all(fd, "0 bytes:\n\n", strlen("0 bytes:\n\n"));
		return;
	}

	start = lr->init_time.ts.tv_sec;
	len = snprintf(buf, sizeof(buf), "%zu bytes, %s", lr->mem_used, ctime(&start));
	write_all(fd, buf, len);

	/* ctime includes \n... WTF? */
	data.prefix = "";
	data.fd = fd;
	log_each_line(lr, log_one_line, &data);
	write_all(fd, "\n\n", strlen("\n\n"));
}

/* FIXME: Dump peer logs! */
void log_backtrace_exit(void)
{
	if (!crashlog)
		return;

	/* If we're not already pointing at a log file, make one */
	if (crashlog->lr->print == log_to_stdout) {
		const char *logfile = NULL;
		int fd;

		/* We expect to be in config dir. */
		logfile = "crash.log";
		fd = open(logfile, O_WRONLY|O_CREAT|O_APPEND, 0600);
		if (fd < 0) {
			logfile = "/tmp/lightning-crash.log";
			fd = open(logfile, O_WRONLY|O_CREAT, 0600);
		}

		/* Dump entire log. */
		if (fd >= 0) {
			log_dump_to_file(fd, crashlog->lr);
			close(fd);
			fprintf(stderr, "Log dumped in %s\n", logfile);
		}
	}
}

void fatal(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);

	if (!crashlog)
		exit(1);

	va_start(ap, fmt);
	logv(crashlog, LOG_BROKEN, fmt, ap);
	va_end(ap);
	abort();
}

struct log_info {
	enum log_level level;
	struct json_result *response;
	unsigned int num_skipped;
};

static void add_skipped(struct log_info *info)
{
	if (info->num_skipped) {
		json_object_start(info->response, NULL);
		json_add_string(info->response, "type", "SKIPPED");
		json_add_num(info->response, "num_skipped", info->num_skipped);
		json_object_end(info->response);
		info->num_skipped = 0;
	}
}

static void json_add_time(struct json_result *result, const char *fieldname,
			  struct timespec ts)
{
	char timebuf[100];

	snprintf(timebuf, sizeof(timebuf), "%lu.%09u",
		(unsigned long)ts.tv_sec,
		(unsigned)ts.tv_nsec);
	json_add_string(result, fieldname, timebuf);
}

static void log_to_json(unsigned int skipped,
			struct timerel diff,
			enum log_level level,
			const char *prefix,
			const char *log,
			const u8 *io,
			struct log_info *info)
{
	info->num_skipped += skipped;

	if (level < info->level) {
		info->num_skipped++;
		return;
	}

	add_skipped(info);

	json_object_start(info->response, NULL);
	json_add_string(info->response, "type",
			level == LOG_BROKEN ? "BROKEN"
			: level == LOG_UNUSUAL ? "UNUSUAL"
			: level == LOG_INFORM ? "INFO"
			: level == LOG_DBG ? "DEBUG"
			: level == LOG_IO_IN ? "IO_IN"
			: level == LOG_IO_OUT ? "IO_OUT"
			: "UNKNOWN");
	json_add_time(info->response, "time", diff.ts);
	json_add_string(info->response, "source", prefix);
	json_add_string(info->response, "log", log);
	if (io)
		json_add_hex_talarr(info->response, "data", io);

	json_object_end(info->response);
}

void json_add_log(struct json_result *response,
		  const struct log_book *lr, enum log_level minlevel)
{
	struct log_info info;

	info.level = minlevel;
	info.response = response;
	info.num_skipped = 0;

	json_array_start(info.response, "log");
	log_each_line(lr, log_to_json, &info);
	add_skipped(&info);
	json_array_end(info.response);
}

bool json_tok_loglevel(const char *buffer, const jsmntok_t *tok,
		       enum log_level *level)
{
	if (json_tok_streq(buffer, tok, "io"))
		*level = LOG_IO_OUT;
	else if (json_tok_streq(buffer, tok, "debug"))
		*level = LOG_DBG;
	else if (json_tok_streq(buffer, tok, "info"))
		*level = LOG_INFORM;
	else if (json_tok_streq(buffer, tok, "unusual"))
		*level = LOG_UNUSUAL;
	else
		return false;
	return true;
}

static void json_getlog(struct command *cmd,
			const char *buffer, const jsmntok_t *params)
{
	struct json_result *response = new_json_result(cmd);
	enum log_level minlevel;
	struct log_book *lr = cmd->ld->log_book;

	if (!param(cmd, buffer, params,
		   p_opt_def("level", json_tok_loglevel, &minlevel, LOG_INFORM),
		   NULL))
		return;

	json_object_start(response, NULL);
	json_add_time(response, "created_at", log_init_time(lr)->ts);
	json_add_num(response, "bytes_used", (unsigned int)log_used(lr));
	json_add_num(response, "bytes_max", (unsigned int)log_max_mem(lr));
	json_add_log(response, lr, minlevel);
	json_object_end(response);
	command_success(cmd, response);
}

static const struct json_command getlog_command = {
	"getlog",
	json_getlog,
	"Show logs, with optional log {level} (info|unusual|debug|io)"
};
AUTODATA(json_command, &getlog_command);
