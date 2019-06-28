#include <bitcoin/preimage.h>
#include <ccan/array_size/array_size.h>
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/json_escape/json_escape.h>
#include <ccan/str/hex/hex.h>
#include <ccan/tal/str/str.h>
#include <common/amount.h>
#include <common/json_command.h>
#include <common/json_tok.h>
#include <common/jsonrpc_errors.h>
#include <common/overflows.h>
#include <common/param.h>

struct command_result *param_array(struct command *cmd, const char *name,
				   const char *buffer, const jsmntok_t *tok,
				   const jsmntok_t **arr)
{
	if (tok->type == JSMN_ARRAY) {
		*arr = tok;
		return NULL;
	}

	return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			    "'%s' should be an array, not '%.*s'",
			    name, tok->end - tok->start, buffer + tok->start);
}

struct command_result *param_bool(struct command *cmd, const char *name,
				  const char *buffer, const jsmntok_t *tok,
				  bool **b)
{
	*b = tal(cmd, bool);
	if (json_to_bool(buffer, tok, *b))
		return NULL;
	return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			    "'%s' should be 'true' or 'false', not '%.*s'",
			    name, tok->end - tok->start, buffer + tok->start);
}

struct command_result *param_double(struct command *cmd, const char *name,
				    const char *buffer, const jsmntok_t *tok,
				    double **num)
{
	*num = tal(cmd, double);
	if (json_to_double(buffer, tok, *num))
		return NULL;

	return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			    "'%s' should be a double, not '%.*s'",
			    name, tok->end - tok->start, buffer + tok->start);
}

struct command_result *param_escaped_string(struct command *cmd,
					    const char *name,
					    const char * buffer,
					    const jsmntok_t *tok,
					    const char **str)
{
	if (tok->type == JSMN_STRING) {
		struct json_escape *esc;
		/* jsmn always gives us ~ well-formed strings. */
		esc = json_escape_string_(cmd, buffer + tok->start,
					  tok->end - tok->start);
		*str = json_escape_unescape(cmd, esc);
		if (*str)
			return NULL;
	}
	return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			    "'%s' should be a string, not '%.*s'"
			    " (note, we don't allow \\u)",
			    name,
			    tok->end - tok->start, buffer + tok->start);
}

struct command_result *param_string(struct command *cmd, const char *name,
				    const char * buffer, const jsmntok_t *tok,
				    const char **str)
{
	*str = tal_strndup(cmd, buffer + tok->start,
			   tok->end - tok->start);
	return NULL;
}

struct command_result *param_label(struct command *cmd, const char *name,
				   const char * buffer, const jsmntok_t *tok,
				   struct json_escape **label)
{
	/* We accept both strings and number literals here. */
	*label = json_escape_string_(cmd, buffer + tok->start, tok->end - tok->start);
	if (*label && (tok->type == JSMN_STRING || json_tok_is_num(buffer, tok)))
		return NULL;

	return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			    "'%s' should be a string or number, not '%.*s'",
			    name, tok->end - tok->start, buffer + tok->start);
}

struct command_result *param_number(struct command *cmd, const char *name,
				    const char *buffer, const jsmntok_t *tok,
				    unsigned int **num)
{
	*num = tal(cmd, unsigned int);
	if (json_to_number(buffer, tok, *num))
		return NULL;

	return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			    "'%s' should be an integer, not '%.*s'",
			    name, tok->end - tok->start, buffer + tok->start);
}

struct command_result *param_sha256(struct command *cmd, const char *name,
				    const char *buffer, const jsmntok_t *tok,
				    struct sha256 **hash)
{
	*hash = tal(cmd, struct sha256);
	if (hex_decode(buffer + tok->start,
		       tok->end - tok->start,
		       *hash, sizeof(**hash)))
		return NULL;

	return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			    "'%s' should be a 32 byte hex value, not '%.*s'",
			    name, tok->end - tok->start, buffer + tok->start);
}

struct command_result *param_percent(struct command *cmd, const char *name,
				     const char *buffer, const jsmntok_t *tok,
				     double **num)
{
	*num = tal(cmd, double);
	if (json_to_double(buffer, tok, *num) && **num >= 0.0)
		return NULL;

	return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			    "'%s' should be a positive double, not '%.*s'",
			    name, tok->end - tok->start, buffer + tok->start);
}

struct command_result *param_u64(struct command *cmd, const char *name,
				 const char *buffer, const jsmntok_t *tok,
				 uint64_t **num)
{
	*num = tal(cmd, uint64_t);
	if (json_to_u64(buffer, tok, *num))
		return NULL;

	return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			    "'%s' should be an unsigned 64 bit integer, not '%.*s'",
			    name, tok->end - tok->start, buffer + tok->start);
}

struct command_result *param_tok(struct command *cmd, const char *name,
				 const char *buffer, const jsmntok_t * tok,
				 const jsmntok_t **out)
{
	*out = tok;
	return NULL;
}

struct command_result *param_msat(struct command *cmd, const char *name,
				  const char *buffer, const jsmntok_t *tok,
				  struct amount_msat **msat)
{
	*msat = tal(cmd, struct amount_msat);
	if (parse_amount_msat(*msat, buffer + tok->start, tok->end - tok->start))
		return NULL;

	return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			    "'%s' should be a millisatoshi amount, not '%.*s'",
			    name, tok->end - tok->start, buffer + tok->start);
}

struct command_result *param_sat(struct command *cmd, const char *name,
				 const char *buffer, const jsmntok_t *tok,
				 struct amount_sat **sat)
{
	*sat = tal(cmd, struct amount_sat);
	if (parse_amount_sat(*sat, buffer + tok->start, tok->end - tok->start))
		return NULL;

	return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			    "'%s' should be a satoshi amount, not '%.*s'",
			    name, tok->end - tok->start, buffer + tok->start);
}

struct command_result *param_preimage(struct command *cmd,
				      const char *name,
				      const char *buffer,
				      const jsmntok_t *tok,
				      struct preimage **preimage)
{
	*preimage = tal(cmd, struct preimage);
	if (hex_decode(buffer + tok->start,
		       tok->end - tok->start,
		       *preimage, sizeof(**preimage)))
		return NULL;

	return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			    "'%s' should be a %d byte hex value, "
			    "not '%.*s'",
			    name,
			    (int)sizeof(**preimage),
			    tok->end - tok->start,
			    buffer + tok->start);
}

/* Parse time with optional suffix, return seconds */
struct command_result *param_time(struct command *cmd, const char *name,
				  const char *buffer,
				  const jsmntok_t *tok,
				  uint64_t **secs)
{
	/* We need to manipulate this, so make copy */
	jsmntok_t timetok = *tok;
	u64 mul;
	char s;
	struct {
		char suffix;
		u64 mul;
	} suffixes[] = {
		{ 's', 1 },
		{ 'm', 60 },
		{ 'h', 60*60 },
		{ 'd', 24*60*60 },
		{ 'w', 7*24*60*60 } };

	mul = 1;
	if (timetok.end == timetok.start)
		s = '\0';
	else
		s = buffer[timetok.end - 1];
	for (size_t i = 0; i < ARRAY_SIZE(suffixes); i++) {
		if (s == suffixes[i].suffix) {
			mul = suffixes[i].mul;
			timetok.end--;
			break;
		}
	}

	*secs = tal(cmd, uint64_t);
	if (json_to_u64(buffer, &timetok, *secs)) {
		if (mul_overflows_u64(**secs, mul)) {
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "'%s' string '%.*s' is too large",
					    name, tok->end - tok->start,
					    buffer + tok->start);
		}
		**secs *= mul;
		return NULL;
	}

	return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			    "'%s' should be a number with optional {s,m,h,d,w} suffix, not '%.*s'",
			    name, tok->end - tok->start, buffer + tok->start);
}
