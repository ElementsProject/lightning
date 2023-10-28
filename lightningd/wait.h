#ifndef LIGHTNING_LIGHTNINGD_WAIT_H
#define LIGHTNING_LIGHTNINGD_WAIT_H
#include "config.h"
#include <common/json_param.h>

struct lightningd;

/* This WAIT_SUBSYSTEM_X corresponds to listXs */
enum wait_subsystem {
	WAIT_SUBSYSTEM_FORWARD,
	WAIT_SUBSYSTEM_SENDPAY,
	WAIT_SUBSYSTEM_INVOICE,
};
#define NUM_WAIT_SUBSYSTEM (WAIT_SUBSYSTEM_INVOICE+1)

enum wait_index {
	WAIT_INDEX_CREATED,
	WAIT_INDEX_UPDATED,
	WAIT_INDEX_DELETED,
};
#define NUM_WAIT_INDEX (WAIT_INDEX_DELETED+1)

/**
 * structure for keeping created/updated/deleted indexes in the db
 */
struct indexes {
	u64 i[NUM_WAIT_INDEX];
};

/* Get a string */
const char *wait_index_name(enum wait_index index);
const char *wait_subsystem_name(enum wait_subsystem subsystem);

/**
 * wait_index_increment - increment an index, tell waiters.
 * @ld: the lightningd
 * @subsystem: subsystem for index
 * @index: which index
 * ...: name/value pairs, followed by NULL.
 *
 * Increase index, write to db, wake any waiters, give them any name/value pairs.
 * If the value is NULL, omit that name.
 * If the name starts with '=', the value is a JSON literal (and skip over the =)
 *
 * Returns the updated index value (always > 0).
 */
u64 LAST_ARG_NULL wait_index_increment(struct lightningd *ld,
				       enum wait_subsystem subsystem,
				       enum wait_index index,
				       ...);

/* For passing in index parameters. */
struct command_result *param_index(struct command *cmd, const char *name,
				   const char *buffer,
				   const jsmntok_t *tok,
				   enum wait_index **index);

#endif /* LIGHTNING_LIGHTNINGD_WAIT_H */
