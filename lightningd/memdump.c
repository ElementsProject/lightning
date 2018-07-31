/* Only possible if we're in developer mode. */
#include "config.h"
#if DEVELOPER
#include <backtrace.h>
#include <ccan/tal/str/str.h>
#include <common/memleak.h>
#include <lightningd/chaintopology.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/jsonrpc_errors.h>
#include <lightningd/lightningd.h>
#include <lightningd/log.h>
#include <stdio.h>

static void json_add_ptr(struct json_result *response, const char *name,
			 const void *ptr)
{
	char ptrstr[STR_MAX_CHARS(void *)];
	snprintf(ptrstr, sizeof(ptrstr), "%p", ptr);
	json_add_string(response, name, ptrstr);
}

static void add_memdump(struct json_result *response,
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
	struct json_result *response = new_json_result(cmd);

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
	struct json_result *response = data;
	char *str;

	/* This can happen in backtraces. */
	if (!filename || !function)
		return 0;

	str = tal_fmt(response, "%s:%u (%s)", filename, lineno, function);
	json_add_string(response, NULL, str);
	tal_free(str);
	return 0;
}

static void json_add_backtrace(struct json_result *response,
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
		     struct json_result *response,
		     struct lightningd *ld)
{
	struct htable *memtable;
	const tal_t *i;
	const uintptr_t *backtrace;

	/* Enter everything, except this cmd and its jcon */
	memtable = memleak_enter_allocations(cmd, cmd, cmd->jcon);

	/* First delete known false positives. */
	chaintopology_mark_pointers_used(memtable, ld->topology);
	htlc_inmap_mark_pointers_used(memtable, &ld->htlcs_in);
	htlc_outmap_mark_pointers_used(memtable, &ld->htlcs_out);

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
	json_array_end(response);
}

static void json_memleak(struct command *cmd,
			 const char *buffer UNNEEDED,
			 const jsmntok_t *params UNNEEDED)
{
	struct json_result *response = new_json_result(cmd);

	if (!getenv("LIGHTNINGD_DEV_MEMLEAK")) {
		command_fail(cmd, LIGHTNINGD,
			     "Leak detection needs $LIGHTNINGD_DEV_MEMLEAK");
		return;
	}

	json_object_start(response, NULL);
	scan_mem(cmd, response, cmd->ld);
	json_object_end(response);

	command_success(cmd, response);
}

static const struct json_command dev_memleak_command = {
	"dev-memleak",
	json_memleak,
	"Show unreferenced memory objects"
};
AUTODATA(json_command, &dev_memleak_command);
#endif /* DEVELOPER */
