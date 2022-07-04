#include "config.h"
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

struct command_result *param_feerate(struct command *cmd, const char *name,
				     const char *buffer, const jsmntok_t *tok,
				     u32 **feerate)
{
	for (size_t i = 0; i < NUM_FEERATES; i++) {
		if (json_tok_streq(buffer, tok, feerate_name(i)))
			return param_feerate_estimate(cmd, feerate, i);
	}
	/* We used SLOW, NORMAL, and URGENT as feerate targets previously,
	 * and many commands rely on this syntax now.
	 * It's also really more natural for an user interface. */
	if (json_tok_streq(buffer, tok, "slow"))
		return param_feerate_estimate(cmd, feerate, FEERATE_MIN);
	else if (json_tok_streq(buffer, tok, "normal"))
		return param_feerate_estimate(cmd, feerate, FEERATE_OPENING);
	else if (json_tok_streq(buffer, tok, "urgent"))
		return param_feerate_estimate(cmd, feerate, FEERATE_UNILATERAL_CLOSE);

	/* It's a number... */
	return param_feerate_val(cmd, name, buffer, tok, feerate);
}

struct command_result *param_feerate_estimate(struct command *cmd,
					      u32 **feerate_per_kw,
					      enum feerate feerate)
{
	*feerate_per_kw = tal(cmd, u32);
	**feerate_per_kw = try_get_feerate(cmd->ld->topology, feerate);
	if (!**feerate_per_kw)
		return command_fail(cmd, LIGHTNINGD, "Cannot estimate fees");

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
