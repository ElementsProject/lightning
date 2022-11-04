/*
 * Helpers for filtering JSON results while generating.
 */
#ifndef LIGHTNING_COMMON_JSON_FILTER_H
#define LIGHTNING_COMMON_JSON_FILTER_H
#include "config.h"
#include <ccan/tal/tal.h>
#include <common/json_parse_simple.h>
#include <stdbool.h>

struct command;
struct json_filter;

/* Print this? */
bool json_filter_ok(const struct json_filter *filter, const char *member);

/* Returns true if we should print this new obj/array */
bool json_filter_down(struct json_filter **filter, const char *member);

/* Returns true if we were printing (i.e. close object/arr) */
bool json_filter_up(struct json_filter **filter);

/* Is filter finished (i.e. balanced!) */
bool json_filter_finished(const struct json_filter *filter);

/* Has filter been misused?  If so, returns explanatory string, otherwise NULL */
const char *json_filter_misused(const tal_t *ctx, const struct json_filter *f);

/* Filter allocation */
struct json_filter *json_filter_new(const tal_t *ctx);
struct json_filter *json_filter_subobj(struct json_filter *filter,
				       const char *fieldname,
				       size_t fieldnamelen);
struct json_filter *json_filter_subarr(struct json_filter *filter);

/* Turn this "filter" field into cmd->filter and return NULL, or fail command */
struct command_result *parse_filter(struct command *cmd,
				    const char *name,
				    const char *buffer,
				    const jsmntok_t *tok);
#endif /* LIGHTNING_COMMON_JSON_FILTER_H */
