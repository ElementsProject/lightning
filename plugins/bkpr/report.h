#ifndef LIGHTNING_PLUGINS_BKPR_REPORT_H
#define LIGHTNING_PLUGINS_BKPR_REPORT_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <common/json_parse_simple.h>

struct command;

enum escape_format {
	REPORT_FMT_NONE,
	REPORT_FMT_CSV,
};

struct report_info {
	struct report_format *format;
	const char **headers;
	enum escape_format *escapes;
	u64 *start_time, *end_time;
};

struct command_result *do_bkpr_report(struct command *cmd,
				      struct report_info *info);

struct command_result *param_report_format(struct command *cmd, const char *name,
					   const char *buffer, const jsmntok_t *tok,
					   struct report_format **format);
struct command_result *param_escape_format(struct command *cmd, const char *name,
					   const char *buffer, const jsmntok_t *tok,
					   enum escape_format **escape);
#endif /* LIGHTNING_PLUGINS_BKPR_REPORT_H */
