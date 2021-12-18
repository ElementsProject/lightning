/* Only possible if we're in developer mode. */
#include "config.h"
#if DEVELOPER
#include <backtrace.h>
#include <ccan/tal/str/str.h>
#include <common/json_command.h>
#include <common/memleak.h>
#include <common/param.h>
#include <common/timeout.h>
#include <connectd/connectd_wiregen.h>
#include <errno.h>
#include <gossipd/gossipd_wiregen.h>
#include <hsmd/hsmd_wiregen.h>
#include <lightningd/chaintopology.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/lightningd.h>
#include <lightningd/memdump.h>
#include <lightningd/opening_common.h>
#include <lightningd/peer_control.h>
#include <lightningd/subd.h>
#include <wire/wire_sync.h>

static void json_add_ptr(struct json_stream *response, const char *name,
			 const void *ptr)
{
	char ptrstr[STR_MAX_CHARS(void *)];
	snprintf(ptrstr, sizeof(ptrstr), "%p", ptr);
	json_add_string(response, name, ptrstr);
}

static size_t add_memdump(struct json_stream *response,
			const char *name, const tal_t *root,
			struct command *cmd)
{
	const tal_t *i;
	size_t cumulative_size = 0;

	json_array_start(response, name);
	for (i = tal_first(root); i; i = tal_next(i)) {
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
	"developer",
	json_memdump,
	"Show memory objects currently in use"
};
AUTODATA(json_command, &dev_memdump_command);

static int json_add_syminfo(void *data, uintptr_t pc UNUSED,
			    const char *filename, int lineno,
			    const char *function)
{
	struct json_stream *response = data;
	char *str;

	/* This can happen in backtraces. */
	if (!filename || !function)
		return 0;

	str = tal_fmt(response, "%s:%u (%s)", filename, lineno, function);
	json_add_string(response, NULL, str);
	tal_free(str);
	return 0;
}

static void json_add_backtrace(struct json_stream *response,
			       const uintptr_t *bt)
{
	size_t i;

	if (!bt)
		return;

	json_array_start(response, "backtrace");
	/* First one serves as counter. */
	for (i = 1; i < bt[0]; i++) {
		backtrace_pcinfo(backtrace_state,
				 bt[i], json_add_syminfo,
				 NULL, response);
	}
	json_array_end(response);
}

static void scan_mem(struct command *cmd,
		     struct json_stream *response,
		     struct lightningd *ld,
		     const struct subd *leaking_subd)
{
	struct htable *memtable;
	const tal_t *i;
	const uintptr_t *backtrace;

	/* Enter everything, except this cmd and its jcon */
	memtable = memleak_find_allocations(cmd, cmd, cmd->jcon);

	/* First delete known false positives. */
	memleak_remove_htable(memtable, &ld->topology->txwatches.raw);
	memleak_remove_htable(memtable, &ld->topology->txowatches.raw);
	memleak_remove_htable(memtable, &ld->htlcs_in.raw);
	memleak_remove_htable(memtable, &ld->htlcs_out.raw);
	memleak_remove_htable(memtable, &ld->htlc_sets.raw);

	/* Now delete ld and those which it has pointers to. */
	memleak_remove_region(memtable, ld, sizeof(*ld));

	json_array_start(response, "leaks");
	while ((i = memleak_get(memtable, &backtrace)) != NULL) {
		const tal_t *p;

		json_object_start(response, NULL);
		json_add_ptr(response, "value", i);
		if (tal_name(i))
			json_add_string(response, "label", tal_name(i));

		json_add_backtrace(response, backtrace);
		json_array_start(response, "parents");
		for (p = tal_parent(i); p; p = tal_parent(p)) {
			json_add_string(response, NULL, tal_name(p));
			p = tal_parent(p);
		}
		json_array_end(response);
		json_object_end(response);
	}

	if (leaking_subd) {
		json_object_start(response, NULL);
		json_add_string(response, "subdaemon", leaking_subd->name);
		json_object_end(response);
	}
	json_array_end(response);
}

struct leak_info {
	struct command *cmd;
	struct subd *leaker;
};

static void report_leak_info2(struct leak_info *leak_info)
{
	struct json_stream *response = json_stream_success(leak_info->cmd);

	scan_mem(leak_info->cmd, response, leak_info->cmd->ld, leak_info->leaker);

	was_pending(command_success(leak_info->cmd, response));
}

static void report_leak_info(struct command *cmd, struct subd *leaker)
{
	struct leak_info *leak_info = tal(cmd, struct leak_info);

	leak_info->cmd = cmd;
	leak_info->leaker = leaker;

	/* Leak detection in a reply handler thinks we're leaking conn. */
	notleak(new_reltimer(leak_info->cmd->ld->timers, leak_info->cmd,
			     time_from_sec(0),
			     report_leak_info2, leak_info));
}

static void gossip_dev_memleak_done(struct subd *gossipd,
				    const u8 *reply,
				    const int *fds UNUSED,
				    struct command *cmd)
{
	bool found_leak;

	if (!fromwire_gossipd_dev_memleak_reply(reply, &found_leak)) {
		was_pending(command_fail(cmd, LIGHTNINGD,
					 "Bad gossip_dev_memleak"));
		return;
	}

	report_leak_info(cmd, found_leak ? gossipd : NULL);
}

static void connect_dev_memleak_done(struct subd *connectd,
				     const u8 *reply,
				     const int *fds UNUSED,
				     struct command *cmd)
{
	bool found_leak;

	if (!fromwire_connectd_dev_memleak_reply(reply, &found_leak)) {
		was_pending(command_fail(cmd, LIGHTNINGD,
					 "Bad connect_dev_memleak"));
		return;
	}

	if (found_leak) {
		report_leak_info(cmd, connectd);
		return;
	}

	/* No leak?  Ask openingd. */
	opening_dev_memleak(cmd);
}

static void hsm_dev_memleak_done(struct subd *hsmd,
				 const u8 *reply,
				 struct command *cmd)
{
	struct lightningd *ld = cmd->ld;
	bool found_leak;

	if (!fromwire_hsmd_dev_memleak_reply(reply, &found_leak)) {
		was_pending(command_fail(cmd, LIGHTNINGD,
					 "Bad hsm_dev_memleak"));
		return;
	}

	if (found_leak) {
		report_leak_info(cmd, hsmd);
		return;
	}

	/* No leak?  Ask gossipd. */
	subd_req(ld->gossip, ld->gossip, take(towire_gossipd_dev_memleak(NULL)),
		 -1, 0, gossip_dev_memleak_done, cmd);
}

void peer_memleak_done(struct command *cmd, struct subd *leaker)
{
	if (leaker)
		report_leak_info(cmd, leaker);
	else {
		/* No leak there, try hsmd (we talk to hsm sync) */
		u8 *msg = towire_hsmd_dev_memleak(NULL);
		if (!wire_sync_write(cmd->ld->hsm_fd, take(msg)))
			fatal("Could not write to HSM: %s", strerror(errno));

		hsm_dev_memleak_done(cmd->ld->hsm,
				     wire_sync_read(tmpctx, cmd->ld->hsm_fd),
				     cmd);
	}
}

void opening_memleak_done(struct command *cmd, struct subd *leaker)
{
	if (leaker)
		report_leak_info(cmd, leaker);
	else {
		/* No leak there, try normal peers. */
		peer_dev_memleak(cmd);
	}
}

static struct command_result *json_memleak(struct command *cmd,
					   const char *buffer,
					   const jsmntok_t *obj UNNEEDED,
					   const jsmntok_t *params)
{
	struct lightningd *ld = cmd->ld;

	if (!param(cmd, buffer, params, NULL))
		return command_param_failed();

	if (!getenv("LIGHTNINGD_DEV_MEMLEAK")) {
		return command_fail(cmd, LIGHTNINGD,
				    "Leak detection needs $LIGHTNINGD_DEV_MEMLEAK");
	}

	/* Start by asking connectd, which is always async. */
	subd_req(ld->connectd, ld->connectd,
		 take(towire_connectd_dev_memleak(NULL)),
		 -1, 0, connect_dev_memleak_done, cmd);

	return command_still_pending(cmd);
}

static const struct json_command dev_memleak_command = {
	"dev-memleak",
	"developer",
	json_memleak,
	"Show unreferenced memory objects"
};
AUTODATA(json_command, &dev_memleak_command);
#endif /* DEVELOPER */
