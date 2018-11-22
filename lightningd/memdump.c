/* Only possible if we're in developer mode. */
#include "memdump.h"
#if DEVELOPER
#include <backtrace.h>
#include <ccan/tal/str/str.h>
#include <common/daemon.h>
#include <common/memleak.h>
#include <common/timeout.h>
#include <connectd/gen_connect_wire.h>
#include <errno.h>
#include <gossipd/gen_gossip_wire.h>
#include <hsmd/gen_hsm_wire.h>
#include <lightningd/chaintopology.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/jsonrpc_errors.h>
#include <lightningd/lightningd.h>
#include <lightningd/log.h>
#include <lightningd/opening_control.h>
#include <lightningd/param.h>
#include <lightningd/peer_control.h>
#include <lightningd/subd.h>
#include <stdio.h>
#include <wire/wire_sync.h>

static void json_add_ptr(struct json_stream *response, const char *name,
			 const void *ptr)
{
	char ptrstr[STR_MAX_CHARS(void *)];
	snprintf(ptrstr, sizeof(ptrstr), "%p", ptr);
	json_add_string(response, name, ptrstr);
}

static void add_memdump(struct json_stream *response,
			const char *name, const tal_t *root,
			struct command *cmd)
{
	const tal_t *i;

	json_array_start(response, name);
	for (i = tal_first(root); i; i = tal_next(i)) {
		const char *name = tal_name(i);

		/* Don't try to dump this command! */
		if (i == cmd || i == cmd->jcon)
			continue;

		/* Don't dump logs, we know they grow. */
		if (name && streq(name, "struct log_book"))
			continue;

		json_object_start(response, NULL);
		json_add_ptr(response, "parent", tal_parent(i));
		json_add_ptr(response, "value", i);
		if (name)
			json_add_string(response, "label", name);

		if (tal_first(i))
			add_memdump(response, "children", i, cmd);
		json_object_end(response);
	}
	json_array_end(response);
}

static void json_memdump(struct command *cmd,
			 const char *buffer UNNEEDED,
			 const jsmntok_t *params UNNEEDED)
{
	struct json_stream *response;

	if (!param(cmd, buffer, params, NULL))
		return;

	response = json_stream_success(cmd);
	add_memdump(response, NULL, NULL, cmd);

	command_success(cmd, response);
}

static const struct json_command dev_memdump_command = {
	"dev-memdump",
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
	memtable = memleak_enter_allocations(cmd, cmd, cmd->jcon);

	/* First delete known false positives. */
	memleak_remove_htable(memtable, &ld->topology->txwatches.raw);
	memleak_remove_htable(memtable, &ld->topology->txowatches.raw);
	memleak_remove_htable(memtable, &ld->htlcs_in.raw);
	memleak_remove_htable(memtable, &ld->htlcs_out.raw);

	/* Now delete ld and those which it has pointers to. */
	memleak_remove_referenced(memtable, ld);

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

	json_object_start(response, NULL);
	scan_mem(leak_info->cmd, response, leak_info->cmd->ld, leak_info->leaker);
	json_object_end(response);

	command_success(leak_info->cmd, response);
}

static void report_leak_info(struct command *cmd, struct subd *leaker)
{
	struct leak_info *leak_info = tal(cmd, struct leak_info);

	leak_info->cmd = cmd;
	leak_info->leaker = leaker;

	/* Leak detection in a reply handler thinks we're leaking conn. */
	notleak(new_reltimer(&leak_info->cmd->ld->timers, leak_info->cmd,
			     time_from_sec(0),
			     report_leak_info2, leak_info));
}

static void gossip_dev_memleak_done(struct subd *gossipd,
				    const u8 *reply,
				    const int *fds UNUSED,
				    struct command *cmd)
{
	bool found_leak;

	if (!fromwire_gossip_dev_memleak_reply(reply, &found_leak)) {
		command_fail(cmd, LIGHTNINGD, "Bad gossip_dev_memleak");
		return;
	}

	report_leak_info(cmd, found_leak ? gossipd : NULL);
}

static void connect_dev_memleak_done(struct subd *connectd,
				     const u8 *reply,
				     const int *fds UNUSED,
				     struct command *cmd)
{
	struct lightningd *ld = cmd->ld;
	bool found_leak;

	if (!fromwire_connect_dev_memleak_reply(reply, &found_leak)) {
		command_fail(cmd, LIGHTNINGD, "Bad connect_dev_memleak");
		return;
	}

	if (found_leak) {
		report_leak_info(cmd, connectd);
		return;
	}

	/* No leak?  Ask gossipd. */
	subd_req(ld->gossip, ld->gossip, take(towire_gossip_dev_memleak(NULL)),
		 -1, 0, gossip_dev_memleak_done, cmd);
}

static void hsm_dev_memleak_done(struct subd *hsmd,
				 const u8 *reply,
				 struct command *cmd)
{
	struct lightningd *ld = cmd->ld;
	bool found_leak;

	if (!fromwire_hsm_dev_memleak_reply(reply, &found_leak)) {
		command_fail(cmd, LIGHTNINGD, "Bad hsm_dev_memleak");
		return;
	}

	if (found_leak) {
		report_leak_info(cmd, hsmd);
		return;
	}

	/* No leak?  Ask connectd. */
	subd_req(ld->connectd, ld->connectd,
		 take(towire_connect_dev_memleak(NULL)),
		 -1, 0, connect_dev_memleak_done, cmd);
}

void peer_memleak_done(struct command *cmd, struct subd *leaker)
{
	if (leaker)
		report_leak_info(cmd, leaker);
	else {
		/* No leak there, try hsmd (we talk to hsm sync) */
		u8 *msg = towire_hsm_dev_memleak(NULL);
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

static void json_memleak(struct command *cmd,
			 const char *buffer UNNEEDED,
			 const jsmntok_t *params UNNEEDED)
{
	if (!param(cmd, buffer, params, NULL))
		return;

	if (!getenv("LIGHTNINGD_DEV_MEMLEAK")) {
		command_fail(cmd, LIGHTNINGD,
			     "Leak detection needs $LIGHTNINGD_DEV_MEMLEAK");
		return;
	}

	/* For simplicity, we mark pending, though an error may complete it
	 * immediately. */
	command_still_pending(cmd);

	/* This calls opening_memleak_done() async when all done. */
	opening_dev_memleak(cmd);
}

static const struct json_command dev_memleak_command = {
	"dev-memleak",
	json_memleak,
	"Show unreferenced memory objects"
};
AUTODATA(json_command, &dev_memleak_command);
#endif /* DEVELOPER */
