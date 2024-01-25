#include "config.h"
#include <common/configdir.h>
#include <common/json_command.h>
#include <lightningd/chaintopology.h>
#include <lightningd/feerate.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/lightningd.h>

const char *feerate_name(enum feerate feerate)
{
	switch (feerate) {
	case FEERATE_OPENING: return "opening";
	case FEERATE_MUTUAL_CLOSE: return "mutual_close";
	case FEERATE_UNILATERAL_CLOSE: return "unilateral_close";
	case FEERATE_DELAYED_TO_US: return "delayed_to_us";
	case FEERATE_HTLC_RESOLUTION: return "htlc_resolution";
	case FEERATE_PENALTY: return "penalty";
	case FEERATE_MIN: return "min_acceptable";
	case FEERATE_MAX: return "max_acceptable";
	}
	abort();
}

struct command_result *param_feerate_style(struct command *cmd,
					   const char *name,
					   const char *buffer,
					   const jsmntok_t *tok,
					   enum feerate_style **style)
{
	*style = tal(cmd, enum feerate_style);
	if (json_tok_streq(buffer, tok,
			   feerate_style_name(FEERATE_PER_KSIPA))) {
		**style = FEERATE_PER_KSIPA;
		return NULL;
	} else if (json_tok_streq(buffer, tok,
				  feerate_style_name(FEERATE_PER_KBYTE))) {
		**style = FEERATE_PER_KBYTE;
		return NULL;
	}

	return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			    "'%s' should be '%s' or '%s', not '%.*s'",
			    name,
			    feerate_style_name(FEERATE_PER_KSIPA),
			    feerate_style_name(FEERATE_PER_KBYTE),
			    json_tok_full_len(tok), json_tok_full(buffer, tok));
}

/* This can set **feerate to 0, if it's unknown. */
static struct command_result *param_feerate_unchecked(struct command *cmd,
						      const char *name,
						      const char *buffer,
						      const jsmntok_t *tok,
						      u32 **feerate)
{
	*feerate = tal(cmd, u32);

	if (json_tok_streq(buffer, tok, "opening")) {
		**feerate = opening_feerate(cmd->ld->topology);
		return NULL;
	}
	if (json_tok_streq(buffer, tok, "mutual_close")) {
		**feerate = mutual_close_feerate(cmd->ld->topology);
		return NULL;
	}
	if (json_tok_streq(buffer, tok, "penalty")) {
		**feerate = penalty_feerate(cmd->ld->topology);
		return NULL;
	}
	if (json_tok_streq(buffer, tok, "unilateral_close")) {
		**feerate = unilateral_feerate(cmd->ld->topology, false);
		return NULL;
	}
	if (json_tok_streq(buffer, tok, "unilateral_anchor_close")) {
		**feerate = unilateral_feerate(cmd->ld->topology, true);
		return NULL;
	}

	/* Other names are deprecated */
	for (size_t i = 0; i < NUM_FEERATES; i++) {
		bool unknown;

		if (!json_tok_streq(buffer, tok, feerate_name(i)))
			continue;
		if (!command_deprecated_in_ok(cmd, feerate_name(i), "v23.05", "v23.05")) {
			return command_fail_badparam(cmd, name, buffer, tok,
						     "removed feerate by names");
		}
		switch (i) {
		case FEERATE_OPENING:
		case FEERATE_MUTUAL_CLOSE:
		case FEERATE_PENALTY:
		case FEERATE_UNILATERAL_CLOSE:
			/* Handled above */
			abort();
		case FEERATE_DELAYED_TO_US:
			**feerate = delayed_to_us_feerate(cmd->ld->topology);
			return NULL;
		case FEERATE_HTLC_RESOLUTION:
			**feerate = htlc_resolution_feerate(cmd->ld->topology);
			return NULL;
		case FEERATE_MAX:
			**feerate = feerate_max(cmd->ld, &unknown);
			if (unknown)
				**feerate = 0;
			return NULL;
		case FEERATE_MIN:
			**feerate = feerate_min(cmd->ld, &unknown);
			if (unknown)
				**feerate = 0;
			return NULL;
		}
		abort();
	}

	/* We used SLOW, NORMAL, and URGENT as feerate targets previously,
	 * and many commands rely on this syntax now.
	 * It's also really more natural for an user interface. */
	if (json_tok_streq(buffer, tok, "slow")) {
		**feerate = feerate_for_deadline(cmd->ld->topology, 100);
		return NULL;
	} else if (json_tok_streq(buffer, tok, "normal")) {
		**feerate = feerate_for_deadline(cmd->ld->topology, 12);
		return NULL;
	} else if (json_tok_streq(buffer, tok, "urgent")) {
		**feerate = feerate_for_deadline(cmd->ld->topology, 6);
		return NULL;
	} else if (json_tok_streq(buffer, tok, "minimum")) {
		**feerate = get_feerate_floor(cmd->ld->topology);
		return NULL;
	}

	/* Can specify number of blocks as a target */
	if (json_tok_endswith(buffer, tok, "blocks")) {
		jsmntok_t base = *tok;
		base.end -= strlen("blocks");
		u32 numblocks;

		if (!json_to_number(buffer, &base, &numblocks)) {
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "'%s' should be an integer not '%.*s'",
					    name, base.end - base.start,
					    buffer + base.start);
		}
		**feerate = feerate_for_deadline(cmd->ld->topology, numblocks);
		return NULL;
	}

	/* It's a number... */
	tal_free(*feerate);
	return param_feerate_val(cmd, name, buffer, tok, feerate);
}

struct command_result *param_feerate(struct command *cmd, const char *name,
				     const char *buffer, const jsmntok_t *tok,
				     u32 **feerate)
{
	struct command_result *ret;

	ret = param_feerate_unchecked(cmd, name, buffer, tok, feerate);
	if (ret)
		return ret;

	if (**feerate == 0)
		return command_fail(cmd, BCLI_NO_FEE_ESTIMATES,
				    "Cannot estimate fees (yet)");

	return NULL;
}

struct command_result *param_feerate_val(struct command *cmd,
					 const char *name, const char *buffer,
					 const jsmntok_t *tok,
					 u32 **feerate_per_kw)
{
	jsmntok_t base = *tok;
	enum feerate_style style;
	unsigned int num;

	if (json_tok_endswith(buffer, tok,
			      feerate_style_name(FEERATE_PER_KBYTE))) {
		style = FEERATE_PER_KBYTE;
		base.end -= strlen(feerate_style_name(FEERATE_PER_KBYTE));
	} else if (json_tok_endswith(buffer, tok,
				     feerate_style_name(FEERATE_PER_KSIPA))) {
		style = FEERATE_PER_KSIPA;
		base.end -= strlen(feerate_style_name(FEERATE_PER_KSIPA));
	} else
		style = FEERATE_PER_KBYTE;

	if (!json_to_number(buffer, &base, &num)) {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "'%s' should be an integer with optional perkw/perkb, not '%.*s'",
				    name, base.end - base.start,
				    buffer + base.start);
	}

	*feerate_per_kw = tal(cmd, u32);
	**feerate_per_kw = feerate_from_style(num, style);
	if (**feerate_per_kw < FEERATE_FLOOR)
		**feerate_per_kw = FEERATE_FLOOR;
	return NULL;
}
