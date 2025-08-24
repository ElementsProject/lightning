#ifndef LIGHTNING_PLUGINS_BKPR_SQL_H
#define LIGHTNING_PLUGINS_BKPR_SQL_H

#include "config.h"
#include <ccan/tal/str/str.h>
#include <common/json_parse_simple.h>

struct command;
struct command_result;

#define SELECT_CHANNEL_EVENTS \
	"SELECT" \
	"  created_index" \
	", account_id" \
	", primary_tag" \
	", credit_msat" \
	", debit_msat" \
	", fees_msat" \
	", payment_hash" \
	", part_id" \
	", timestamp" \
	" FROM channelmoves "

#define SELECT_CHAIN_EVENTS						\
	"SELECT"							\
	"  created_index"						\
	", account_id"							\
	", originating_account"						\
	", primary_tag"							\
	", credit_msat"							\
	", debit_msat"							\
	", output_msat"							\
	", timestamp"							\
	", blockheight"							\
	", utxo"							\
	", spending_txid"							\
	", payment_hash"						\
	", EXISTS (SELECT 1 FROM chainmoves_extra_tags et"		\
        "          WHERE et.row = cm.rowid"				\
	"          AND et.extra_tags = 'stealable') AS stealable"	\
	", EXISTS (SELECT 1 FROM chainmoves_extra_tags et"		\
	"          WHERE et.row = cm.rowid"				\
	"          AND et.extra_tags = 'splice') AS spliced"		\
	" FROM chainmoves cm "

const jsmntok_t *PRINTF_FMT(4, 5) sql_req(const tal_t *ctx,
					  struct command *cmd, const char **buf,
					  const char *fmt, ...);

const jsmntok_t *sql_reqv(const tal_t *ctx,
			  struct command *cmd, const char **buf,
			  const char *fmt, va_list ap);

struct channel_event **
PRINTF_FMT(3, 4) channel_events_from_sql(const tal_t *ctx,
					 struct command *cmd,
					 const char *fmt, ...);

struct chain_event **
PRINTF_FMT(4, 5) chain_events_from_sql(const tal_t *ctx,
				       const struct bkpr *bkpr,
				       struct command *cmd,
				       const char *fmt, ...);

/* FIXME: The sql plugin should support bound parameters to avoid this! */
/* Return with escaped quotes, if any */
const char *sql_string(const tal_t *ctx, const char *str);

#endif /* LIGHTNING_PLUGINS_BKPR_SQL_H */
