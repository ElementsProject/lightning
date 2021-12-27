#include "config.h"
#include <ccan/err/err.h>
#include <ccan/io/io.h>
#include <ccan/opt/opt.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/str/hex/hex.h>
#include <ccan/tal/link/link.h>
#include <ccan/tal/str/str.h>
#include <common/json_command.h>
#include <common/json_helpers.h>
#include <common/memleak.h>
#include <common/param.h>
#include <errno.h>
#include <fcntl.h>
#include <lightningd/log.h>
#include <lightningd/notification.h>
#include <signal.h>
#include <stdio.h>

/* What logging level to use if they didn't specify */
#define DEFAULT_LOGLEVEL LOG_INFORM

/* Once we're up and running, this is set up. */
struct log *crashlog;

struct print_filter {
	struct list_node list;

	const char *prefix;
	enum log_level level;
};

struct log_book {
	size_t mem_used;
	size_t max_mem;
	size_t num_entries;
	struct list_head print_filters;

	/* Non-null once it's been initialized */
	enum log_level *default_print_level;
	struct timeabs init_time;
	FILE *outf;
	bool print_timestamps;

	struct log_entry *log;

	/* Although log_book will copy log entries to parent log_book
	 * (the log_book belongs to lightningd), a pointer to lightningd
	 *  is more directly because the notification needs ld->plugins.
	 */
	struct lightningd *ld;
	/* Cache of all node_ids, to avoid multiple copies. */
	struct node_id_map *cache;
};

struct log {
	struct log_book *lr;
	const struct node_id *default_node_id;
	struct log_prefix *prefix;

	/* Non-NULL once it's been initialized */
	enum log_level *print_level;
};

static struct log_prefix *log_prefix_new(const tal_t *ctx,
					 const char *prefix TAKES)
{
	struct log_prefix *lp = tal(ctx, struct log_prefix);
	lp->refcnt = 1;
	lp->prefix = tal_strdup(lp, prefix);
	return lp;
}

static void log_prefix_drop(struct log_prefix *lp)
{
	if (--lp->refcnt == 0)
		tal_free(lp);
}

static struct log_prefix *log_prefix_get(struct log_prefix *lp)
{
	assert(lp->refcnt);
	lp->refcnt++;
	return lp;
}

/* Avoids duplicate node_id entries. */
struct node_id_cache {
	size_t count;
	struct node_id node_id;
};

static const struct node_id *node_cache_id(const struct node_id_cache *nc)
{
	return &nc->node_id;
}

static size_t node_id_hash(const struct node_id *id)
{
	return siphash24(siphash_seed(), id->k, sizeof(id->k));
}

static bool node_id_cache_eq(const struct node_id_cache *nc,
			     const struct node_id *node_id)
{
	return node_id_eq(&nc->node_id, node_id);
}

HTABLE_DEFINE_TYPE(struct node_id_cache,
		   node_cache_id, node_id_hash, node_id_cache_eq,
		   node_id_map);

static const char *level_prefix(enum log_level level)
{
	switch (level) {
	case LOG_IO_OUT:
	case LOG_IO_IN:
		return "IO     ";
	case LOG_DBG:
		return "DEBUG  ";
	case LOG_INFORM:
		return "INFO   ";
	case LOG_UNUSUAL:
		return "UNUSUAL";
	case LOG_BROKEN:
		return "**BROKEN**";
	}
	abort();
}

static void log_to_file(const char *prefix,
			enum log_level level,
			const struct node_id *node_id,
			const struct timeabs *time,
			const char *str,
			const u8 *io,
			size_t io_len,
			bool print_timestamps,
			FILE *logf)
{
	char tstamp[sizeof("YYYY-mm-ddTHH:MM:SS.nnnZ ")];

	if (print_timestamps) {
		char iso8601_msec_fmt[sizeof("YYYY-mm-ddTHH:MM:SS.%03dZ ")];
		strftime(iso8601_msec_fmt, sizeof(iso8601_msec_fmt), "%FT%T.%%03dZ ", gmtime(&time->ts.tv_sec));
		snprintf(tstamp, sizeof(tstamp), iso8601_msec_fmt, (int) time->ts.tv_nsec / 1000000);
	} else
		tstamp[0] = '\0';

	if (level == LOG_IO_IN || level == LOG_IO_OUT) {
		const char *dir = level == LOG_IO_IN ? "[IN]" : "[OUT]";
		char *hex = tal_hexstr(NULL, io, io_len);
		if (!node_id)
			fprintf(logf, "%s%s: %s%s %s\n",
				tstamp, prefix, str, dir, hex);
		else
			fprintf(logf, "%s%s-%s: %s%s %s\n",
				tstamp,
				node_id_to_hexstr(tmpctx, node_id),
				prefix, str, dir, hex);
		tal_free(hex);
	} else {
		if (!node_id)
			fprintf(logf, "%s%s %s: %s\n",
				tstamp, level_prefix(level), prefix, str);
		else
			fprintf(logf, "%s%s %s-%s: %s\n",
				tstamp, level_prefix(level),
				node_id_to_hexstr(tmpctx, node_id),
				prefix, str);
	}
	fflush(logf);
}

static size_t mem_used(const struct log_entry *e)
{
	return sizeof(*e) + strlen(e->log) + 1 + tal_count(e->io);
}

/* Threshold (of 1000) to delete */
static u32 delete_threshold(enum log_level level)
{
	switch (level) {
	/* Delete 90% of log_io */
	case LOG_IO_OUT:
	case LOG_IO_IN:
		return 900;
	/* 50% of LOG_DBG */
	case LOG_DBG:
		return 500;
	/* 25% of LOG_INFORM */
	case LOG_INFORM:
		return 250;
	/* 5% of LOG_UNUSUAL / LOG_BROKEN */
	case LOG_UNUSUAL:
	case LOG_BROKEN:
		return 50;
	}
	abort();
}

/* Delete a log entry: returns how many now deleted */
static size_t delete_entry(struct log_book *log, struct log_entry *i)
{
	log->mem_used -= mem_used(i);
	log->num_entries--;
	if (i->nc && --i->nc->count == 0)
		tal_free(i->nc);
	free(i->log);
	log_prefix_drop(i->prefix);
	tal_free(i->io);

	return 1 + i->skipped;
}

static size_t prune_log(struct log_book *log)
{
	size_t skipped = 0, deleted = 0, count = 0, dst = 0, max, tail;

	/* Never delete the last 10% (and definitely not last one!). */
	tail = log->num_entries / 10 + 1;
	max = log->num_entries - tail;

	for (count = 0; count < max; count++) {
		struct log_entry *i = &log->log[count];

		if (pseudorand(1000) > delete_threshold(i->level)) {
			i->skipped += skipped;
			skipped = 0;
			/* Move down if necesary. */
			log->log[dst++] = *i;
			continue;
		}

		skipped += delete_entry(log, i);
		deleted++;
	}

	/* Any skipped at tail go on the next entry */
	log->log[count].skipped += skipped;

	/* Move down the last 10% */
	memmove(log->log + dst, log->log + count, tail * sizeof(*log->log));
	return deleted;
}

static void destroy_log_book(struct log_book *log)
{
	size_t num = log->num_entries;

	for (size_t i = 0; i < num; i++)
		delete_entry(log, &log->log[i]);

	assert(log->num_entries == 0);
	assert(log->mem_used == 0);
}

struct log_book *new_log_book(struct lightningd *ld, size_t max_mem)
{
	struct log_book *lr = tal_linkable(tal(NULL, struct log_book));

	/* Give a reasonable size for memory limit! */
	assert(max_mem > sizeof(struct log) * 2);
	lr->mem_used = 0;
	lr->num_entries = 0;
	lr->max_mem = max_mem;
	lr->outf = stdout;
	lr->default_print_level = NULL;
	list_head_init(&lr->print_filters);
	lr->init_time = time_now();
	lr->ld = ld;
	lr->cache = tal(lr, struct node_id_map);
	node_id_map_init(lr->cache);
	lr->log = tal_arr(lr, struct log_entry, 128);
	lr->print_timestamps = true;
	tal_add_destructor(lr, destroy_log_book);

	return lr;
}

static enum log_level filter_level(struct log_book *lr,
				   const struct log_prefix *lp)
{
	struct print_filter *i;

	assert(lr->default_print_level != NULL);
	list_for_each(&lr->print_filters, i, list) {
		if (strstr(lp->prefix, i->prefix))
			return i->level;
	}
	return *lr->default_print_level;
}

/* With different entry points */
struct log *
new_log(const tal_t *ctx, struct log_book *record,
	const struct node_id *default_node_id,
	const char *fmt, ...)
{
	struct log *log = tal(ctx, struct log);
	va_list ap;

	log->lr = tal_link(log, record);
	va_start(ap, fmt);
	/* Owned by the log book itself, since it can be referenced
	 * by log entries, too */
	log->prefix = log_prefix_new(log->lr, take(tal_vfmt(NULL, fmt, ap)));
	va_end(ap);
	log->default_node_id = tal_dup_or_null(log, struct node_id,
					       default_node_id);

	/* Initialized on first use */
	log->print_level = NULL;
	return log;
}

const char *log_prefix(const struct log *log)
{
	return log->prefix->prefix;
}

enum log_level log_print_level(struct log *log)
{
	if (!log->print_level) {
		/* Not set globally yet?  Print UNUSUAL / BROKEN messages only */
		if (!log->lr->default_print_level)
			return LOG_UNUSUAL;
		log->print_level = tal(log, enum log_level);
		*log->print_level = filter_level(log->lr, log->prefix);
	}
	return *log->print_level;
}


/* This may move entry! */
static void add_entry(struct log *log, struct log_entry **l)
{
	log->lr->mem_used += mem_used(*l);
	log->lr->num_entries++;

	if (log->lr->mem_used > log->lr->max_mem) {
		size_t old_mem = log->lr->mem_used, deleted;
		deleted = prune_log(log->lr);
		/* Will have moved, but will be last entry. */
		*l = &log->lr->log[log->lr->num_entries-1];
		log_debug(log, "Log pruned %zu entries (mem %zu -> %zu)",
			  deleted, old_mem, log->lr->mem_used);
	}
}

static void destroy_node_id_cache(struct node_id_cache *nc, struct log_book *lr)
{
	node_id_map_del(lr->cache, nc);
}

static struct log_entry *new_log_entry(struct log *log, enum log_level level,
				       const struct node_id *node_id)
{
	struct log_entry *l;

	if (log->lr->num_entries == tal_count(log->lr->log))
		tal_resize(&log->lr->log, tal_count(log->lr->log) * 2);

	l = &log->lr->log[log->lr->num_entries];
	l->time = time_now();
	l->level = level;
	l->skipped = 0;
	l->prefix = log_prefix_get(log->prefix);
	l->io = NULL;
	if (!node_id)
		node_id = log->default_node_id;
	if (node_id) {
		l->nc = node_id_map_get(log->lr->cache, node_id);
		if (!l->nc) {
			l->nc = tal(log->lr->cache, struct node_id_cache);
			l->nc->count = 0;
			l->nc->node_id = *node_id;
			node_id_map_add(log->lr->cache, l->nc);
			tal_add_destructor2(l->nc, destroy_node_id_cache,
					    log->lr);
		}
		l->nc->count++;
	} else
		l->nc = NULL;

	return l;
}

static void maybe_print(struct log *log, const struct log_entry *l)
{
	if (l->level >= log_print_level(log))
		log_to_file(log->prefix->prefix, l->level,
			    l->nc ? &l->nc->node_id : NULL,
			    &l->time, l->log,
			    l->io, tal_bytelen(l->io),
			    log->lr->print_timestamps,
			    log->lr->outf);
}

void logv(struct log *log, enum log_level level,
	  const struct node_id *node_id,
	  bool call_notifier,
	  const char *fmt, va_list ap)
{
	int save_errno = errno;
	struct log_entry *l = new_log_entry(log, level, node_id);

	/* This is WARN_UNUSED_RESULT, because everyone should somehow deal
	 * with OOM, even though nobody does. */
	if (vasprintf(&l->log, fmt, ap) == -1)
		abort();

	size_t log_len = strlen(l->log);

	/* Sanitize any non-printable characters, and replace with '?' */
	for (size_t i=0; i<log_len; i++)
		if (l->log[i] < ' ' || l->log[i] >= 0x7f)
			l->log[i] = '?';

	maybe_print(log, l);

	add_entry(log, &l);

	if (call_notifier)
		notify_warning(log->lr->ld, l);

	errno = save_errno;
}

void log_io(struct log *log, enum log_level dir,
	    const struct node_id *node_id,
	    const char *str TAKES,
	    const void *data TAKES, size_t len)
{
	int save_errno = errno;
	struct log_entry *l = new_log_entry(log, dir, node_id);

	assert(dir == LOG_IO_IN || dir == LOG_IO_OUT);

	/* Print first, in case we need to truncate. */
	if (l->level >= log_print_level(log))
		log_to_file(log->prefix->prefix, l->level,
			    l->nc ? &l->nc->node_id : NULL,
			    &l->time, str,
			    data, len,
			    log->lr->print_timestamps,
			    log->lr->outf);

	/* Save a tal header, by using raw malloc. */
	l->log = strdup(str);
	if (taken(str))
		tal_free(str);

	/* Don't immediately fill buffer with giant IOs */
	if (len > log->lr->max_mem / 64) {
		l->skipped++;
		len = log->lr->max_mem / 64;
	}

	/* FIXME: We could save 4 pointers by using a raw allow, but saving
	 * the length. */
	l->io = tal_dup_arr(log->lr, u8, data, len, 0);

	add_entry(log, &l);
	errno = save_errno;
}

void log_(struct log *log, enum log_level level,
	  const struct node_id *node_id,
	  bool call_notifier,
	  const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	logv(log, level, node_id, call_notifier, fmt, ap);
	va_end(ap);
}

#define log_each_line(lr, func, arg)					\
	log_each_line_((lr),						\
		       typesafe_cb_preargs(void, void *, (func), (arg),	\
					   unsigned int,		\
					   struct timerel,		\
					   enum log_level,		\
					   const struct node_id *,	\
					   const char *,		\
					   const char *,		\
					   const u8 *), (arg))

static void log_each_line_(const struct log_book *lr,
			   void (*func)(unsigned int skipped,
					struct timerel time,
					enum log_level level,
					const struct node_id *node_id,
					const char *prefix,
					const char *log,
					const u8 *io,
					void *arg),
			   void *arg)
{
	for (size_t i = 0; i < lr->num_entries; i++) {
		const struct log_entry *l = &lr->log[i];

		func(l->skipped, time_between(l->time, lr->init_time),
		     l->level, l->nc ? &l->nc->node_id : NULL,
		     l->prefix->prefix, l->log, l->io, arg);
	}
}

struct log_data {
	int fd;
	const char *prefix;
};

static void log_one_line(unsigned int skipped,
			 struct timerel diff,
			 enum log_level level,
			 const struct node_id *node_id,
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

char *opt_log_level(const char *arg, struct log *log)
{
	enum log_level level;
	int len;

	len = strcspn(arg, ":");
	if (!log_level_parse(arg, len, &level))
		return tal_fmt(NULL, "unknown log level %.*s", len, arg);

	if (arg[len]) {
		struct print_filter *f = tal(log->lr, struct print_filter);
		f->prefix = arg + len + 1;
		f->level = level;
		list_add_tail(&log->lr->print_filters, &f->list);
	} else {
		tal_free(log->lr->default_print_level);
		log->lr->default_print_level = tal(log->lr, enum log_level);
		*log->lr->default_print_level = level;
	}
	return NULL;
}

void json_add_opt_log_levels(struct json_stream *response, struct log *log)
{
	struct print_filter *i;

	list_for_each(&log->lr->print_filters, i, list) {
		json_add_member(response, "log-level", true, "%s:%s",
				log_level_name(i->level), i->prefix);
	}
}

static void show_log_level(char buf[OPT_SHOW_LEN], const struct log *log)
{
	enum log_level l;

	if (log->lr->default_print_level)
		l = *log->lr->default_print_level;
	else
		l = DEFAULT_LOGLEVEL;
	strncpy(buf, log_level_name(l), OPT_SHOW_LEN-1);
}

static char *arg_log_prefix(const char *arg, struct log *log)
{
	/* log->lr owns this, since it keeps a pointer to it. */
	tal_free(log->prefix);
	log->prefix = log_prefix_new(log->lr, arg);
	return NULL;
}

static void show_log_prefix(char buf[OPT_SHOW_LEN], const struct log *log)
{
	strncpy(buf, log->prefix->prefix, OPT_SHOW_LEN);
}

static int signalfds[2];

static void handle_sighup(int sig)
{
	/* Writes a single 0x00 byte to the signalfds pipe. This may fail if
	 * we're hammered with SIGHUP.  We don't care. */
	if (write(signalfds[1], "", 1))
		;
}

/* Mutual recursion */
static struct io_plan *setup_read(struct io_conn *conn, struct lightningd *ld);

static struct io_plan *rotate_log(struct io_conn *conn, struct lightningd *ld)
{
	log_info(ld->log, "Ending log due to SIGHUP");
	fclose(ld->log->lr->outf);

	ld->log->lr->outf = fopen(ld->logfile, "a");
	if (!ld->log->lr->outf)
		err(1, "failed to reopen log file %s", ld->logfile);

	log_info(ld->log, "Started log due to SIGHUP");
	return setup_read(conn, ld);
}

static struct io_plan *setup_read(struct io_conn *conn, struct lightningd *ld)
{
	/* We read and discard. */
	static char discard;
	return io_read(conn, &discard, 1, rotate_log, ld);
}

static void setup_log_rotation(struct lightningd *ld)
{
	struct sigaction act;
	if (pipe(signalfds) != 0)
		errx(1, "Pipe for signalfds");

	notleak(io_new_conn(ld, signalfds[0], setup_read, ld));

	io_fd_block(signalfds[1], false);
	memset(&act, 0, sizeof(act));
	act.sa_handler = handle_sighup;
	/* We do not need any particular flags; the sigaction
	 * default behavior (EINTR any system calls, pass only
	 * the signo to the handler, retain the same signal
	 * handler throughout) is fine with us.
	 */
	act.sa_flags = 0;
	/* Block all signals while handling SIGHUP.
	 * Without this, e.g. an inopportune SIGCHLD while we
	 * are doing a `write` to the SIGHUP signal pipe could
	 * prevent us from sending the byte and performing the
	 * log rotation in the main loop.
	 *
	 * The SIGHUP handler does very little anyway, and
	 * the blocked signals will get delivered soon after
	 * the SIGHUP handler returns.
	 */
	sigfillset(&act.sa_mask);

	if (sigaction(SIGHUP, &act, NULL) != 0)
		err(1, "Setting up SIGHUP handler");
}

char *arg_log_to_file(const char *arg, struct lightningd *ld)
{
	int size;

	if (ld->logfile) {
		fclose(ld->log->lr->outf);
		ld->logfile = tal_free(ld->logfile);
	} else
		setup_log_rotation(ld);

	ld->logfile = tal_strdup(ld, arg);
	ld->log->lr->outf = fopen(arg, "a");
	if (!ld->log->lr->outf)
		return tal_fmt(NULL, "Failed to open: %s", strerror(errno));

	/* For convenience make a block of empty lines just like Bitcoin Core */
	size = ftell(ld->log->lr->outf);
	if (size > 0)
		fprintf(ld->log->lr->outf, "\n\n\n\n");

	log_debug(ld->log, "Opened log file %s", arg);
	return NULL;
}

void opt_register_logging(struct lightningd *ld)
{
	opt_register_early_arg("--log-level",
			       opt_log_level, show_log_level, ld->log,
			       "log level (io, debug, info, unusual, broken) [:prefix]");
	opt_register_early_arg("--log-timestamps",
			       opt_set_bool_arg, opt_show_bool, &ld->log->lr->print_timestamps,
			       "prefix log messages with timestamp");
	opt_register_early_arg("--log-prefix", arg_log_prefix, show_log_prefix,
			       ld->log,
			       "log prefix");
	opt_register_early_arg("--log-file=<file>", arg_log_to_file, NULL, ld,
			       "log to file instead of stdout");
}

void logging_options_parsed(struct log_book *lr)
{
	/* If they didn't set an explicit level, set to info */
	if (!lr->default_print_level) {
		lr->default_print_level = tal(lr, enum log_level);
		*lr->default_print_level = DEFAULT_LOGLEVEL;
	}

	/* Catch up, since before we were only printing BROKEN msgs */
	for (size_t i = 0; i < lr->num_entries; i++) {
		const struct log_entry *l = &lr->log[i];

		if (l->level >= filter_level(lr, l->prefix))
			log_to_file(l->prefix->prefix, l->level,
				    l->nc ? &l->nc->node_id : NULL,
				    &l->time, l->log,
				    l->io, tal_bytelen(l->io),
				    lr->print_timestamps,
				    lr->outf);
	}
}

void log_backtrace_print(const char *fmt, ...)
{
	va_list ap;

	if (!crashlog)
		return;

	va_start(ap, fmt);
	logv(crashlog, LOG_BROKEN, NULL, false, fmt, ap);
	va_end(ap);
}

static void log_dump_to_file(int fd, const struct log_book *lr)
{
	char buf[100];
	int len;
	struct log_data data;
	time_t start;

	if (lr->num_entries == 0) {
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

void log_backtrace_exit(void)
{
	int fd;
	char timebuf[sizeof("YYYYmmddHHMMSS")];
	char logfile[sizeof("/tmp/lightning-crash.log.") + sizeof(timebuf)];
	struct timeabs time = time_now();

	strftime(timebuf, sizeof(timebuf), "%Y%m%d%H%M%S", gmtime(&time.ts.tv_sec));

	if (!crashlog)
		return;

	/* We expect to be in config dir. */
	snprintf(logfile, sizeof(logfile), "crash.log.%s", timebuf);

	fd = open(logfile, O_WRONLY|O_CREAT|O_TRUNC, 0600);
	if (fd < 0) {
		snprintf(logfile, sizeof(logfile),
			 "/tmp/lightning-crash.log.%s", timebuf);
		fd = open(logfile, O_WRONLY|O_CREAT|O_TRUNC, 0600);
	}

	/* Dump entire log. */
	if (fd >= 0) {
		log_dump_to_file(fd, crashlog->lr);
		close(fd);
		fprintf(stderr, "Log dumped in %s\n", logfile);
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
	logv(crashlog, LOG_BROKEN, NULL, true, fmt, ap);
	va_end(ap);
	abort();
}

struct log_info {
	enum log_level level;
	struct json_stream *response;
	unsigned int num_skipped;
	/* If non-null, only show messages about this peer */
	const struct node_id *node_id;
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

static void log_to_json(unsigned int skipped,
			struct timerel diff,
			enum log_level level,
			const struct node_id *node_id,
			const char *prefix,
			const char *log,
			const u8 *io,
			struct log_info *info)
{
	info->num_skipped += skipped;

	if (info->node_id) {
		if (!node_id || !node_id_eq(node_id, info->node_id))
			return;
	}

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
	if (node_id)
		json_add_node_id(info->response, "node_id", node_id);
	json_add_string(info->response, "source", prefix);
	json_add_string(info->response, "log", log);
	if (io)
		json_add_hex_talarr(info->response, "data", io);

	json_object_end(info->response);
}

void json_add_log(struct json_stream *response,
		  const struct log_book *lr,
		  const struct node_id *node_id,
		  enum log_level minlevel)
{
	struct log_info info;

	info.level = minlevel;
	info.response = response;
	info.num_skipped = 0;
	info.node_id = node_id;

	json_array_start(info.response, "log");
	log_each_line(lr, log_to_json, &info);
	add_skipped(&info);
	json_array_end(info.response);
}

struct command_result *param_loglevel(struct command *cmd,
				      const char *name,
				      const char *buffer,
				      const jsmntok_t *tok,
				      enum log_level **level)
{
	*level = tal(cmd, enum log_level);
	if (log_level_parse(buffer + tok->start, tok->end - tok->start, *level))
		return NULL;

	return command_fail_badparam(cmd, name, buffer, tok,
				     "should be 'io', 'debug', 'info', or "
				     "'unusual'");
}

static struct command_result *json_getlog(struct command *cmd,
					  const char *buffer,
					  const jsmntok_t *obj UNNEEDED,
					  const jsmntok_t * params)
{
	struct json_stream *response;
	enum log_level *minlevel;
	struct log_book *lr = cmd->ld->log_book;

	if (!param(cmd, buffer, params,
		   p_opt_def("level", param_loglevel, &minlevel, LOG_INFORM),
		   NULL))
		return command_param_failed();

	response = json_stream_success(cmd);
	/* Suppress logging for this stream, to not bloat io logs */
	json_stream_log_suppress_for_cmd(response, cmd);
	json_add_time(response, "created_at", lr->init_time.ts);
	json_add_num(response, "bytes_used", (unsigned int)lr->mem_used);
	json_add_num(response, "bytes_max", (unsigned int)lr->max_mem);
	json_add_log(response, lr, NULL, *minlevel);
	return command_success(cmd, response);
}

static const struct json_command getlog_command = {
	"getlog",
	"utility",
	json_getlog,
	"Show logs, with optional log {level} (info|unusual|debug|io)"
};
AUTODATA(json_command, &getlog_command);
