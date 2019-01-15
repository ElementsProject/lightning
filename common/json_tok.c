#include <ccan/crypto/sha256/sha256.h>
#include <ccan/str/hex/hex.h>
#include <ccan/tal/str/str.h>
#include <common/json_command.h>
#include <common/json_escaped.h>
#include <common/json_tok.h>
#include <common/jsonrpc_errors.h>
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
	struct json_escaped *esc = json_to_escaped_string(cmd, buffer, tok);
	if (esc) {
		*str = json_escaped_unescape(cmd, esc);
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
				   struct json_escaped **label)
{
	/* We accept both strings and number literals here. */
	*label = json_escaped_string_(cmd, buffer + tok->start, tok->end - tok->start);
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

struct command_result *param_msat(struct command *cmd, const char *name,
				  const char *buffer, const jsmntok_t * tok,
				  u64 **msatoshi_val)
{
	if (json_tok_streq(buffer, tok, "any")) {
		*msatoshi_val = NULL;
		return NULL;
	}
	*msatoshi_val = tal(cmd, u64);

	if (json_to_u64(buffer, tok, *msatoshi_val) && *msatoshi_val != 0)
		return NULL;

	return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			    "'%s' should be a positive number or 'any', not '%.*s'",
			    name,
			    tok->end - tok->start,
			    buffer + tok->start);
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
