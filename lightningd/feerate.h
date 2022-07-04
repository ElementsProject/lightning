#ifndef LIGHTNING_LIGHTNINGD_FEERATE_H
#define LIGHTNING_LIGHTNINGD_FEERATE_H
#include "config.h"
#include <bitcoin/feerate.h>
#include <common/json_parse_simple.h>

struct command;

enum feerate {
	/* DO NOT REORDER: force-feerates uses this order! */
	FEERATE_OPENING,
	FEERATE_MUTUAL_CLOSE,
	FEERATE_UNILATERAL_CLOSE,
	FEERATE_DELAYED_TO_US,
	FEERATE_HTLC_RESOLUTION,
	FEERATE_PENALTY,
	FEERATE_MIN,
	FEERATE_MAX,
};
#define NUM_FEERATES (FEERATE_MAX+1)

const char *feerate_name(enum feerate feerate);

/* Extract a feerate style. */
struct command_result *param_feerate_style(struct command *cmd,
					   const char *name,
					   const char *buffer,
					   const jsmntok_t *tok,
					   enum feerate_style **style);

/* Set feerate_per_kw to this estimate & return NULL, or fail cmd */
struct command_result *param_feerate_estimate(struct command *cmd,
					      u32 **feerate_per_kw,
					      enum feerate feerate);

/* Extract a feerate with optional style suffix. */
struct command_result *param_feerate_val(struct command *cmd,
					 const char *name, const char *buffer,
					 const jsmntok_t *tok,
					 u32 **feerate_per_kw);

/* This also accepts names like "slow" etc */
struct command_result *param_feerate(struct command *cmd, const char *name,
				     const char *buffer, const jsmntok_t *tok,
				     u32 **feerate);

#endif /* LIGHTNING_LIGHTNINGD_FEERATE_H */
