#include "log.h"
#include "pseudorand.h"
#include <ccan/array_size/array_size.h>
#include <ccan/list/list.h>
#include <ccan/opt/opt.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/str/hex/hex.h>
#include <ccan/tal/str/str.h>
#include <ccan/time/time.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

struct log_entry {
	struct list_node list;
	struct timeabs time;
	enum log_level level;
	unsigned int skipped;
	const char *prefix;
	char *log;
};

struct log_record {
	size_t mem_used;
	size_t max_mem;
	void (*print)(const char *prefix,
		      enum log_level level,
		      bool continued,
		      const char *str, void *arg);
	void *print_arg;
	enum log_level print_level;
	struct timeabs init_time;

	struct list_head log;
};

struct log {
	struct log_record *lr;
	const char *prefix;
};

static void log_default_print(const char *prefix,
			      enum log_level level,
			      bool continued,
			      const char *str, void *arg)
{
	if (!continued) {
		printf("%s %s\n", prefix, str);
	} else {
		printf("%s \t%s\n", prefix, str);
	}
}

static size_t log_bufsize(const struct log_entry *e)
{
	if (e->level == LOG_IO)
		return tal_count(e->log);
	else
		return strlen(e->log) + 1;
}

static size_t prune_log(struct log_record *log)
{
	struct log_entry *i, *next, *tail;
	size_t skipped = 0, deleted = 0;

	/* Never delete the last one. */
	tail = list_tail(&log->log, struct log_entry, list);

	list_for_each_safe(&log->log, i, next, list) {
		/* 50% chance of deleting debug, 25% inform, 12.5% unusual. */
		if (i == tail || !pseudorand(2 << i->level)) {
			i->skipped += skipped;
			skipped = 0;
			continue;
		}

		list_del_from(&log->log, &i->list);
		log->mem_used -= sizeof(*i) + log_bufsize(i);
		tal_free(i);
		skipped++;
		deleted++;
	}

	assert(!skipped);
	return deleted;
}

struct log_record *new_log_record(const tal_t *ctx,
				  size_t max_mem,
				  enum log_level printlevel)
{
	struct log_record *lr = tal(ctx, struct log_record);

	/* Give a reasonable size for memory limit! */
	assert(max_mem > sizeof(struct log) * 2);
	lr->mem_used = 0;
	lr->max_mem = max_mem;
	lr->print = log_default_print;
	lr->print_level = printlevel;
	lr->init_time = time_now();
	list_head_init(&lr->log);

	return lr;
}

/* With different entry points */
struct log *PRINTF_FMT(3,4)
new_log(const tal_t *ctx, struct log_record *record, const char *fmt, ...)
{
	struct log *log = tal(ctx, struct log);
	va_list ap;

	log->lr = record;
	va_start(ap, fmt);
	/* log->lr owns this, since its entries keep a pointer to it. */
	log->prefix = tal_vfmt(log->lr, fmt, ap);
	va_end(ap);

	return log;
}

void set_log_level(struct log_record *lr, enum log_level level)
{
	lr->print_level = level;
}

void set_log_prefix(struct log *log, const char *prefix)
{
	/* log->lr owns this, since it keeps a pointer to it. */
	log->prefix = tal_strdup(log->lr, prefix);
}

void set_log_outfn_(struct log_record *lr,
		    void (*print)(const char *prefix,
				  enum log_level level,
				  bool continued,
				  const char *str, void *arg),
		    void *arg)
{
	lr->print = print;
	lr->print_arg = arg;
}

const char *log_prefix(const struct log *log)
{
	return log->prefix;
}

size_t log_max_mem(const struct log_record *lr)
{
	return lr->max_mem;
}

size_t log_used(const struct log_record *lr)
{
	return lr->mem_used;
}

const struct timeabs *log_init_time(const struct log_record *lr)
{
	return &lr->init_time;
}

static void add_entry(struct log *log, struct log_entry *l)
{
	log->lr->mem_used += sizeof(*l) + log_bufsize(l);
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

	return l;
}

void logv(struct log *log, enum log_level level, const char *fmt, va_list ap)
{
	struct log_entry *l = new_log_entry(log, level);

	l->log = tal_vfmt(l, fmt, ap);

	if (level >= log->lr->print_level)
		log->lr->print(log->prefix, level, false, l->log,
			       log->lr->print_arg);

	add_entry(log, l);
}

void log_io(struct log *log, bool in, const void *data, size_t len)
{
	int save_errno = errno;
	struct log_entry *l = new_log_entry(log, LOG_IO);

	l->log = tal_arr(l, char, 1 + len);
	l->log[0] = in;
	memcpy(l->log + 1, data, len);

	if (LOG_IO >= log->lr->print_level) {
		const char *dir = in ? "[IN]" : "[OUT]";
		char *hex = tal_arr(l, char, strlen(dir) + hex_str_size(len));
		strcpy(hex, dir);
		hex_encode(data, len, hex + strlen(dir), hex_str_size(len));
		log->lr->print(log->prefix, LOG_IO, false, l->log,
			       log->lr->print_arg);
		tal_free(hex);
	}

	add_entry(log, l);
	errno = save_errno;
}

static void do_log_add(struct log *log, const char *fmt, va_list ap)
{
	struct log_entry *l = list_tail(&log->lr->log, struct log_entry, list);
	size_t oldlen = strlen(l->log);

	/* Remove from list, so it doesn't get pruned. */
	log->lr->mem_used -= sizeof(*l) + oldlen + 1;
	list_del_from(&log->lr->log, &l->list);

	tal_append_vfmt(&l->log, fmt, ap);
	add_entry(log, l);

	if (l->level >= log->lr->print_level)
		log->lr->print(log->prefix, l->level, true, l->log + oldlen,
			       log->lr->print_arg);
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
	do_log_add(log, fmt, ap);
	va_end(ap);
}

void log_add_hex(struct log *log, const void *data, size_t len)
{
	char hex[hex_str_size(len)];
	hex_encode(data, len, hex, hex_str_size(len));
	log_add(log, "%s", hex);
}

void log_each_line_(const struct log_record *lr,
		    void (*func)(unsigned int skipped,
				 struct timerel time,
				 enum log_level level,
				 const char *prefix,
				 const char *log,
				 void *arg),
		    void *arg)
{
	const struct log_entry *i;

	list_for_each(&lr->log, i, list) {
		func(i->skipped, time_between(i->time, lr->init_time),
		     i->level, i->prefix, i->log, arg);
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
			 struct log_data *data)
{
	char buf[101];

	if (skipped) {
		sprintf(buf, "%s... %u skipped...", data->prefix, skipped);
		write_all(data->fd, buf, strlen(buf));
		data->prefix = "\n";
	}

	sprintf(buf, "%s+%lu.%09u %s%s: ",
		data->prefix,
		(unsigned long)diff.ts.tv_sec,
		(unsigned)diff.ts.tv_nsec,
		prefix,
		level == LOG_IO ? (log[0] ? "IO-IN" : "IO-OUT")
		: level == LOG_DBG ? "DEBUG"
		: level == LOG_INFORM ? "INFO"
		: level == LOG_UNUSUAL ? "UNUSUAL"
		: level == LOG_BROKEN ? "BROKEN"
		: "**INVALID**");

	write_all(data->fd, buf, strlen(buf));
	if (level == LOG_IO) {
		size_t off, used, len = tal_count(log)-1;

		/* No allocations, may be in signal handler. */
		for (off = 0; off < len; off += used) {
			used = len - off;
			if (hex_str_size(used) > sizeof(buf))
				used = hex_data_size(sizeof(buf));
			hex_encode(log + 1 + off, used, buf, hex_str_size(used));
			write_all(data->fd, buf, strlen(buf));
		}
	} else {
		write_all(data->fd, log, strlen(log));
	}

	data->prefix = "\n";
}

static struct {
	const char *name;
	enum log_level level;
} log_levels[] = {
	{ "IO", LOG_IO },
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

static char *arg_log_prefix(const char *arg, struct log *log)
{
	set_log_prefix(log, arg);
	return NULL;
}

static void log_to_file(const char *prefix,
			enum log_level level,
			bool continued,
			const char *str,
			FILE *logf)
{
	if (!continued) {
		fprintf(logf, "%s %s\n", prefix, str);
	} else {
		fprintf(logf, "%s \t%s\n", prefix, str);
	}
}

static char *arg_log_to_file(const char *arg, struct log *log)
{
	FILE *logf = fopen(arg, "a");
	if (!logf)
		return tal_fmt(NULL, "Failed to open: %s", strerror(errno));
	set_log_outfn(log->lr, log_to_file, logf);
	return NULL;
}

void opt_register_logging(struct log *log)
{
	opt_register_arg("--log-level", arg_log_level, NULL, log,
			 "log level (debug, info, unusual, broken)");
	opt_register_arg("--log-prefix", arg_log_prefix, NULL, log,
			 "log prefix");
	opt_register_arg("--log-file=<file>", arg_log_to_file, NULL, log,
			 "log to file instead of stdout");
}

static struct log *crashlog;

static void log_crash(int sig)
{
	const char *logfile = NULL;

	if (sig) {
		/* FIXME: Backtrace! */
		log_broken(crashlog, "FATAL SIGNAL %i RECEIVED", sig);
	}

	if (crashlog->lr->print == log_default_print) {
		int fd;

		/* We expect to be in config dir. */
		logfile = "crash.log";
		fd = open(logfile, O_WRONLY|O_CREAT, 0600);
		if (fd < 0) {
			logfile = "/tmp/lighning-crash.log";
			fd = open(logfile, O_WRONLY|O_CREAT, 0600);
		}

		/* Dump entire log. */
		if (fd >= 0) {
			log_dump_to_file(fd, crashlog->lr);
			close(fd);
		} else
			logfile = NULL;
	}

	if (sig)
		fprintf(stderr, "Fatal signal %u. ", sig);
	if (logfile)
		fprintf(stderr, "Log dumped in %s", logfile);
	fprintf(stderr, "\n");
}

void crashlog_activate(struct log *log)
{
	struct sigaction sa;
	crashlog = log;

	sa.sa_handler = log_crash;
	sigemptyset(&sa.sa_mask);
	/* We want to fall through to default handler */
	sa.sa_flags = SA_RESETHAND;
	sigaction(SIGILL, &sa, NULL);
	sigaction(SIGABRT, &sa, NULL);
	sigaction(SIGFPE, &sa, NULL);
	sigaction(SIGSEGV, &sa, NULL);
	sigaction(SIGBUS, &sa, NULL);
}

void log_dump_to_file(int fd, const struct log_record *lr)
{
	const struct log_entry *i;
	char buf[100];
	struct log_data data;
	time_t start;

	i = list_top(&lr->log, const struct log_entry, list);
	if (!i) {
		write_all(fd, "0 bytes:\n\n", strlen("0 bytes:\n\n"));
		return;
	}

	start = lr->init_time.ts.tv_sec;
	sprintf(buf, "%zu bytes, %s", lr->mem_used, ctime(&start));
	write_all(fd, buf, strlen(buf));

	/* ctime includes \n... WTF? */
	data.prefix = "";
	data.fd = fd;
	log_each_line(lr, log_one_line, &data);
	write_all(fd, "\n\n", strlen("\n\n"));
}

void fatal(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);

	/* Early on, we just dump errors to stderr. */
	if (crashlog) {
		va_start(ap, fmt);
		logv(crashlog, LOG_BROKEN, fmt, ap);
		va_end(ap);
		log_crash(0);
	}
	exit(1);
}
