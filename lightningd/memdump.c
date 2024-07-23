/* Only possible if we're in developer mode. */
#include "config.h"
#include <backtrace.h>
#include <ccan/tal/str/str.h>
#include <common/json_command.h>
#include <common/json_param.h>
#include <common/memleak.h>
#include <common/timeout.h>
#include <connectd/connectd_wiregen.h>
#include <errno.h>
#include <gossipd/gossipd_wiregen.h>
#include <hsmd/hsmd_wiregen.h>
#include <lightningd/chaintopology.h>
#include <lightningd/hsm_control.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/lightningd.h>
#include <lightningd/memdump.h>
#include <lightningd/opening_common.h>
#include <lightningd/peer_control.h>
#include <lightningd/subd.h>

static void json_add_ptr(struct json_stream *response, const char *name,
			 const void *ptr)
{
	char ptrstr[STR_MAX_CHARS(void *)];
	snprintf(ptrstr, sizeof(ptrstr), "%p", ptr);
	json_add_string(response, name, ptrstr);
}

static size_t add_memdump(struct json_stream *response,
			  const char *fieldname, const tal_t *root,
			  struct command *cmd)
{
	size_t cumulative_size = 0;

	json_array_start(response, fieldname);
	for (const tal_t *i = tal_first(root); i; i = tal_next(i)) {
		const char *name = tal_name(i);
		size_t size = tal_bytelen(i);

		/* Don't try to dump this command! */
		if (i == cmd || i == cmd->jcon)
			continue;

		/* Don't dump logs, we know they grow. */
		if (name && streq(name, "struct log_book"))
			continue;

		json_object_start(response, NULL);
		json_add_ptr(response, "parent", tal_parent(i));
		json_add_ptr(response, "value", i);
		json_add_u64(response, "size", size);
		if (name)
			json_add_string(response, "label", name);

		if (tal_first(i))
			size += add_memdump(response, "children", i, cmd);
		json_add_u64(response, "cumulative_size", size);
		json_object_end(response);
		cumulative_size += size;
	}
	json_array_end(response);
	return cumulative_size;
}

static struct command_result *json_memdump(struct command *cmd,
					   const char *buffer,
					   const jsmntok_t *obj UNNEEDED,
					   const jsmntok_t *params)
{
	struct json_stream *response;

	if (!param(cmd, buffer, params, NULL))
		return command_param_failed();

	response = json_stream_success(cmd);
	add_memdump(response, "memdump", NULL, cmd);

	return command_success(cmd, response);
}

static const struct json_command dev_memdump_command = {
	"dev-memdump",
	json_memdump,
	"Show memory objects currently in use",
	.dev_only = true,
};
AUTODATA(json_command, &dev_memdump_command);

static void memleak_log(struct logger *log, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	logv(log, LOG_BROKEN, NULL, true, fmt, ap);
	va_end(ap);
}

static void finish_report(const struct leak_detect *leaks)
{
	struct htable *memtable;
	struct command *cmd;
	struct lightningd *ld;
	struct json_stream *response;

	/* If it timed out, we free ourselved and exit! */
	if (!leaks->cmd) {
		tal_free(leaks);
		return;
	}

	/* Convenience variables */
	cmd = leaks->cmd;
	ld = cmd->ld;

	/* Enter everything, except this cmd and its jcon */
	memtable = memleak_start(cmd);

	/* This command is not a leak! */
	memleak_ptr(memtable, cmd);
	memleak_ignore_children(memtable, cmd);

	/* First delete known false positives. */
	memleak_scan_htable(memtable, &ld->topology->txwatches->raw);
	memleak_scan_htable(memtable, &ld->topology->txowatches->raw);
	memleak_scan_htable(memtable, &ld->topology->outgoing_txs->raw);
	memleak_scan_htable(memtable, &ld->htlcs_in->raw);
	memleak_scan_htable(memtable, &ld->htlcs_out->raw);
	memleak_scan_htable(memtable, &ld->htlc_sets->raw);
	memleak_scan_htable(memtable, &ld->peers->raw);
	memleak_scan_htable(memtable, &ld->peers_by_dbid->raw);

	/* Now delete ld and those which it has pointers to. */
	memleak_scan_obj(memtable, ld);

	if (dump_memleak(memtable, memleak_log, ld->log))
		tal_arr_expand(&leaks->leakers, "lightningd");

	response = json_stream_success(cmd);
	json_array_start(response, "leaks");
	for (size_t num_leakers = 0;
	     num_leakers < tal_count(leaks->leakers);
	     num_leakers++) {
		json_object_start(response, NULL);
		json_add_string(response, "subdaemon", leaks->leakers[num_leakers]);
		json_object_end(response);
	}
	json_array_end(response);

	/* Command is now done. */
	was_pending(command_success(cmd, response));
}

static void leak_detect_timeout(struct leak_detect *leak_detect)
{
	/* We actually *do* leak the leak_detect, but cmd is about
	 * to exit. */
	notleak(tal_steal(NULL, leak_detect));
	finish_report(leak_detect);
	leak_detect->cmd = NULL;
}

static void leak_detect_req_done(const struct subd_req *req,
				 struct leak_detect *leak_detect)
{
	leak_detect->num_outstanding_requests--;
	if (leak_detect->num_outstanding_requests == 0)
		finish_report(leak_detect);
}

/* Start a leak request: decrements num_outstanding_requests when freed. */
void start_leak_request(const struct subd_req *req,
			struct leak_detect *leak_detect)
{
	leak_detect->num_outstanding_requests++;
	/* When req is freed, request finished. */
	tal_add_destructor2(req, leak_detect_req_done, leak_detect);
}

/* Yep, found a leak in this subd. */
void report_subd_memleak(struct leak_detect *leak_detect, struct subd *leaker)
{
	tal_arr_expand(&leak_detect->leakers,
		       tal_strdup(leak_detect, leaker->name));
}

static void gossip_dev_memleak_done(struct subd *gossipd,
				    const u8 *reply,
				    const int *fds UNUSED,
				    struct leak_detect *leaks)
{
	bool found_leak;

	if (!fromwire_gossipd_dev_memleak_reply(reply, &found_leak))
		fatal("Bad gossip_dev_memleak");

	if (found_leak)
		report_subd_memleak(leaks, gossipd);
}

static void connect_dev_memleak_done(struct subd *connectd,
				     const u8 *reply,
				     const int *fds UNUSED,
				     struct leak_detect *leaks)
{
	bool found_leak;

	if (!fromwire_connectd_dev_memleak_reply(reply, &found_leak))
		fatal("Bad connect_dev_memleak");

	if (found_leak)
		report_subd_memleak(leaks, connectd);
}

static struct command_result *json_memleak(struct command *cmd,
					   const char *buffer,
					   const jsmntok_t *obj UNNEEDED,
					   const jsmntok_t *params)
{
	struct lightningd *ld = cmd->ld;
	const u8 *msg;
	bool found_leak;
	struct leak_detect *leaks;

	if (!param_check(cmd, buffer, params, NULL))
		return command_param_failed();

	if (!getenv("LIGHTNINGD_DEV_MEMLEAK")) {
		return command_fail(cmd, LIGHTNINGD,
				    "Leak detection needs $LIGHTNINGD_DEV_MEMLEAK");
	}

	if (command_check_only(cmd))
		return command_check_done(cmd);

	leaks = tal(cmd, struct leak_detect);
	leaks->cmd = cmd;
	leaks->num_outstanding_requests = 0;
	leaks->leakers = tal_arr(leaks, const char *, 0);

	/* hsmd is sync, so do that first. */
	msg = hsm_sync_req(tmpctx, cmd->ld, take(towire_hsmd_dev_memleak(NULL)));
	if (!fromwire_hsmd_dev_memleak_reply(msg, &found_leak))
		fatal("Bad HSMD_DEV_MEMLEAK_REPLY: %s", tal_hex(tmpctx, msg));

	if (found_leak)
		report_subd_memleak(leaks, ld->hsm);

	/* Now do all the async ones. */
	start_leak_request(subd_req(ld->connectd, ld->connectd,
				    take(towire_connectd_dev_memleak(NULL)),
				    -1, 0, connect_dev_memleak_done, leaks),
			   leaks);
	start_leak_request(subd_req(ld->gossip, ld->gossip,
				    take(towire_gossipd_dev_memleak(NULL)),
				    -1, 0, gossip_dev_memleak_done, leaks),
			   leaks);

	/* Ask all per-peer daemons */
	peer_dev_memleak(ld, leaks);

	/* Set timer: dualopend doesn't always listen! */
	notleak(new_reltimer(ld->timers, leaks, time_from_sec(20),
			     leak_detect_timeout, leaks));
	return command_still_pending(cmd);
}

static const struct json_command dev_memleak_command = {
	"dev-memleak",
	json_memleak,
	"Show unreferenced memory objects",
	.dev_only = true,
};
AUTODATA(json_command, &dev_memleak_command);
