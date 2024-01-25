#include "config.h"
#include <bitcoin/address.h>
#include <bitcoin/base58.h>
#include <bitcoin/feerate.h>
#include <bitcoin/psbt.h>
#include <bitcoin/script.h>
#include <ccan/asort/asort.h>
#include <ccan/json_escape/json_escape.h>
#include <ccan/mem/mem.h>
#include <ccan/str/hex/hex.h>
#include <ccan/tal/str/str.h>
#include <common/bech32.h>
#include <common/configdir.h>
#include <common/json_command.h>
#include <common/json_param.h>
#include <common/route.h>

/* Overridden by run-param.c */
#ifndef paramcheck_assert
#define paramcheck_assert assert
#endif

/* Overridden by run-param.c */
#ifndef paramcheck_assert
#define paramcheck_assert assert
#endif

struct param {
	const char *name;
	bool is_set;
	enum param_style style;
	param_cbx cbx;
	void *arg;
};

static void param_add(struct param **params,
		      const char *name,
		      enum param_style style,
		      param_cbx cbx, void *arg)
{
	struct param last;

	paramcheck_assert(name);
	paramcheck_assert(cbx);
	paramcheck_assert(arg);

	last.is_set = false;
	last.name = name;
	last.style = style;
	last.cbx = cbx;
	last.arg = arg;

	tal_arr_expand(params, last);
}

static bool is_required(enum param_style style)
{
	return style == PARAM_REQUIRED;
}

static struct command_result *make_callback(struct command *cmd,
					     struct param *def,
					     const char *buffer,
					     const jsmntok_t *tok)
{
	/* If it had a default, free that now to avoid leak */
	if ((def->style == PARAM_OPTIONAL_WITH_DEFAULT
	     || def->style == PARAM_OPTIONAL_DEV_WITH_DEFAULT)
	    && !def->is_set)
		tal_free(*(void **)def->arg);

	def->is_set = true;

	return def->cbx(cmd, def->name, buffer, tok, def->arg);
}

static struct command_result *post_check(struct command *cmd,
					 struct param *params)
{
	struct param *first = params;
	struct param *last = first + tal_count(params);

	/* Make sure required params were provided. */
	while (first != last && is_required(first->style)) {
		if (!first->is_set) {
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "missing required parameter: %s",
					    first->name);
		}
		first++;
	}
	return NULL;
}

static struct command_result *parse_by_position(struct command *cmd,
						struct param *params,
						const char *buffer,
						const jsmntok_t tokens[],
						bool allow_extra)
{
	struct command_result *res;
	const jsmntok_t *tok;
	size_t i;

	json_for_each_arr(i, tok, tokens) {
		/* check for unexpected trailing params */
		if (i == tal_count(params)) {
			if (!allow_extra) {
				return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
						    "too many parameters:"
						    " got %u, expected %zu",
						    tokens->size,
						    tal_count(params));
			}
			break;
		}

		if (!json_tok_is_null(buffer, tok)) {
			if (params[i].style == PARAM_OPTIONAL_DEV_WITH_DEFAULT
			    && !command_dev_apis(cmd)) {
				return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
						    "Parameter %zu is developer-only", i);
			}
			res = make_callback(cmd, params+i, buffer, tok);
			if (res)
				return res;
		}
	}

	return post_check(cmd, params);
}

static struct param *find_param(struct command *cmd,
				struct param *params, const char *start,
				size_t n)
{
	struct param *first = params;
	struct param *last = first + tal_count(params);

	while (first != last) {
		size_t arglen = strcspn(first->name, "|");
		if (memeq(first->name, arglen, start, n))
			return first;
		if (first->name[arglen]
		    && memeq(first->name + arglen + 1,
			     strlen(first->name + arglen + 1),
			     start, n)
		    && command_deprecated_apis(cmd))
			return first;
		first++;
	}
	return NULL;
}

static struct command_result *parse_by_name(struct command *cmd,
					    struct param *params,
					    const char *buffer,
					    const jsmntok_t tokens[],
					    bool allow_extra)
{
	size_t i;
	const jsmntok_t *t;

	json_for_each_obj(i, t, tokens) {
		struct param *p = find_param(cmd, params, buffer + t->start,
					     t->end - t->start);
		if (!p) {
			if (!allow_extra) {
				return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
						    "unknown parameter: %.*s, this may be caused by a failure to autodetect key=value-style parameters. Please try using the -k flag and explicit key=value pairs of parameters.",
						    t->end - t->start,
						    buffer + t->start);
			}
		} else {
			struct command_result *res;

			if (p->is_set) {
				return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
						    "duplicate json names: %s",
						    p->name);
			}

			if (p->style == PARAM_OPTIONAL_DEV_WITH_DEFAULT
			    && !command_dev_apis(cmd)) {
				return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
						    "Parameter '%s' is developer-only",
						    p->name);
			}
			res = make_callback(cmd, p, buffer, t + 1);
			if (res)
				return res;
		}
	}
	return post_check(cmd, params);
}

static int comp_by_name(const struct param *a, const struct param *b,
			void *unused)
{
	return strcmp(a->name, b->name);
}

static int comp_by_arg(const struct param *a, const struct param *b,
		       void *unused)
{
	/* size_t could be larger than int: don't turn a 4bn difference into 0 */
	if (a->arg > b->arg)
		return 1;
	else if (a->arg < b->arg)
		return -1;
	return 0;
}

/* This comparator is a bit different, but works well.
 * Return 0 if @a is optional and @b is required. Otherwise return 1.
 */
static int comp_req_order(const struct param *a, const struct param *b,
			  void *unused)
{
	if (!is_required(a->style) && is_required(b->style))
		return 0;
	return 1;
}

/*
 * Make sure 2 sequential items in @params are not equal (based on
 * provided comparator).
 */
static void check_distinct(const struct param *params,
			   int (*compar)(const struct param *a,
					 const struct param *b, void *unused))
{
	const struct param *first = params;
	const struct param *last = first + tal_count(params);
	first++;
	while (first != last) {
		paramcheck_assert(compar(first - 1, first, NULL) != 0);
		first++;
	}
}

static void check_unique(struct param *copy,
			 int (*compar) (const struct param *a,
					const struct param *b, void *unused))
{
	asort(copy, tal_count(copy), compar, NULL);
	check_distinct(copy, compar);
}

/*
 * Verify consistent internal state.
 */
static void check_params(const struct param *params)
{
	if (tal_count(params) < 2)
		return;

	/* make sure there are no required params following optional */
	check_distinct(params, comp_req_order);

	/* duplicate so we can sort */
	struct param *copy = tal_dup_talarr(params, struct param, params);

	/* check for repeated names and args */
	check_unique(copy, comp_by_name);
	check_unique(copy, comp_by_arg);

	tal_free(copy);
}

static char *param_usage(const tal_t *ctx,
			 const struct param *params)
{
	char *usage = tal_strdup(ctx, "");
	for (size_t i = 0; i < tal_count(params); i++) {
		/* Don't print |deprecated part! */
		int len = strcspn(params[i].name, "|");
		if (i != 0)
			tal_append_fmt(&usage, " ");
		if (is_required(params[i].style))
			tal_append_fmt(&usage, "%.*s", len, params[i].name);
		else
			tal_append_fmt(&usage, "[%.*s]", len, params[i].name);
	}
	return usage;
}

static struct command_result *param_arr(struct command *cmd, const char *buffer,
					const jsmntok_t tokens[],
					struct param *params,
					bool allow_extra)
{
	if (tokens->type == JSMN_ARRAY)
		return parse_by_position(cmd, params, buffer, tokens, allow_extra);
	else if (tokens->type == JSMN_OBJECT)
		return parse_by_name(cmd, params, buffer, tokens, allow_extra);

	return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			    "Expected array or object for params");
}

const char *param_subcommand(struct command *cmd, const char *buffer,
			     const jsmntok_t tokens[],
			     const char *name, ...)
{
	va_list ap;
	struct param *params = tal_arr(cmd, struct param, 0);
	const char *arg, **names = tal_arr(tmpctx, const char *, 1);
	const char *subcmd;

	param_add(&params, "subcommand", PARAM_REQUIRED, (void *)param_string, &subcmd);
	names[0] = name;
	va_start(ap, name);
	while ((arg = va_arg(ap, const char *)) != NULL)
		tal_arr_expand(&names, arg);
	va_end(ap);

	if (command_usage_only(cmd)) {
		char *usage = tal_strdup(cmd, "subcommand");
		for (size_t i = 0; i < tal_count(names); i++)
			tal_append_fmt(&usage, "%c%s",
				       i == 0 ? '=' : '|', names[i]);
		check_params(params);
		command_set_usage(cmd, usage);
		return NULL;
	}

	/* Check it's valid */
	if (param_arr(cmd, buffer, tokens, params, true) != NULL) {
		return NULL;
	}

	/* Check it's one of the known ones. */
	for (size_t i = 0; i < tal_count(names); i++)
		if (streq(subcmd, names[i]))
			return subcmd;

	/* We really do ignore this. */
	struct command_result *ignore;
	ignore = command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			      "Unknown subcommand '%s'", subcmd);
	assert(ignore);
	return NULL;
}

static bool param_core(struct command *cmd,
		       const char *buffer,
		       const jsmntok_t tokens[],
		       va_list ap)
{
	struct param *params = tal_arr(tmpctx, struct param, 0);
	const char *name;
	bool allow_extra = false;

	while ((name = va_arg(ap, const char *)) != NULL) {
		enum param_style style = va_arg(ap, enum param_style);
		param_cbx cbx = va_arg(ap, param_cbx);
		void *arg = va_arg(ap, void *);
		if (streq(name, "")) {
			allow_extra = true;
			continue;
		}
		param_add(&params, name, style, cbx, arg);
	}

	if (command_usage_only(cmd)) {
		check_params(params);
		command_set_usage(cmd, param_usage(cmd, params));
		return false;
	}

	return param_arr(cmd, buffer, tokens, params, allow_extra) == NULL;
}

bool param(struct command *cmd,
	   const char *buffer,
	   const jsmntok_t tokens[], ...)
{
	bool ret;
	va_list ap;

	va_start(ap, tokens);
	ret = param_core(cmd, buffer, tokens, ap);
	va_end(ap);

	/* Always fail if we're just checking! */
	if (ret && command_check_only(cmd))
		ret = false;
	return ret;
}

bool param_check(struct command *cmd,
		 const char *buffer,
		 const jsmntok_t tokens[], ...)
{
	bool ret;
	va_list ap;

	va_start(ap, tokens);
	ret = param_core(cmd, buffer, tokens, ap);
	va_end(ap);

	return ret;
}

struct command_result *param_array(struct command *cmd, const char *name,
				   const char *buffer, const jsmntok_t *tok,
				   const jsmntok_t **arr)
{
	if (tok->type == JSMN_ARRAY) {
		*arr = tok;
		return NULL;
	}

	return command_fail_badparam(cmd, name, buffer, tok, "should be an array");
}

struct command_result *param_bool(struct command *cmd, const char *name,
				  const char *buffer, const jsmntok_t *tok,
				  bool **b)
{
	*b = tal(cmd, bool);
	if (json_to_bool(buffer, tok, *b))
		return NULL;
	return command_fail_badparam(cmd, name, buffer, tok,
				     "should be 'true' or 'false'");
}

struct command_result *param_millionths(struct command *cmd, const char *name,
					const char *buffer,
					const jsmntok_t *tok, uint64_t **num)
{
	*num = tal(cmd, uint64_t);
	if (json_to_millionths(buffer, tok, *num))
		return NULL;

	return command_fail_badparam(cmd, name, buffer, tok,
				     "should be a non-negative floating-point number");
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
	return command_fail_badparam(cmd, name, buffer, tok,
				     "should be a string (without \\u)");
}

struct command_result *param_string(struct command *cmd, const char *name,
				    const char * buffer, const jsmntok_t *tok,
				    const char **str)
{
	*str = tal_strndup(cmd, buffer + tok->start,
			   tok->end - tok->start);
	return NULL;
}

struct command_result *param_invstring(struct command *cmd, const char *name,
				       const char * buffer, const jsmntok_t *tok,
				       const char **str)
{
	const char *strtmp = json_strdup(cmd, buffer, tok);
	*str = to_canonical_invstr(cmd, strtmp);
	return NULL;
}

struct command_result *param_ignore(struct command *cmd, const char *name,
				    const char *buffer, const jsmntok_t *tok,
				    const void *unused)
{
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

	return command_fail_badparam(cmd, name, buffer, tok,
				     "should be a string or number");
}

struct command_result *param_number(struct command *cmd, const char *name,
				    const char *buffer, const jsmntok_t *tok,
				    unsigned int **num)
{
	*num = tal(cmd, unsigned int);
	if (json_to_number(buffer, tok, *num))
		return NULL;

	return command_fail_badparam(cmd, name, buffer, tok,
				     "should be an integer");
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

	return command_fail_badparam(cmd, name, buffer, tok,
				     "should be a 32 byte hex value");
}

struct command_result *param_u32(struct command *cmd, const char *name,
				 const char *buffer, const jsmntok_t *tok,
				 uint32_t **num)
{
	*num = tal(cmd, uint32_t);
	if (json_to_u32(buffer, tok, *num))
		return NULL;

	return command_fail_badparam(cmd, name, buffer, tok,
				     "should be an unsigned 32 bit integer");
}

struct command_result *param_u64(struct command *cmd, const char *name,
				 const char *buffer, const jsmntok_t *tok,
				 uint64_t **num)
{
	*num = tal(cmd, uint64_t);
	if (json_to_u64(buffer, tok, *num))
		return NULL;

	return command_fail_badparam(cmd, name, buffer, tok,
				     "should be an unsigned 64 bit integer");
}

struct command_result *param_s64(struct command *cmd, const char *name,
				 const char *buffer, const jsmntok_t *tok,
				 int64_t **num)
{
	*num = tal(cmd, int64_t);
	if (json_to_s64(buffer, tok, *num))
		return NULL;

	return command_fail_badparam(cmd, name, buffer, tok,
				     "should be an sign 64 bit integer");
}

struct command_result *param_msat(struct command *cmd, const char *name,
				  const char *buffer, const jsmntok_t *tok,
				  struct amount_msat **msat)
{
	*msat = tal(cmd, struct amount_msat);
	if (parse_amount_msat(*msat, buffer + tok->start, tok->end - tok->start))
		return NULL;

	return command_fail_badparam(cmd, name, buffer, tok,
				     "should be a millisatoshi amount");
}

struct command_result *param_sat(struct command *cmd, const char *name,
				 const char *buffer, const jsmntok_t *tok,
				 struct amount_sat **sat)
{
	*sat = tal(cmd, struct amount_sat);
	if (parse_amount_sat(*sat, buffer + tok->start, tok->end - tok->start))
		return NULL;

	return command_fail_badparam(cmd, name, buffer, tok,
				     "should be a satoshi amount");
}

struct command_result *param_sat_or_all(struct command *cmd, const char *name,
					const char *buffer, const jsmntok_t *tok,
					struct amount_sat **sat)
{
	if (json_tok_streq(buffer, tok, "all")) {
		*sat = tal(cmd, struct amount_sat);
		**sat = AMOUNT_SAT(-1ULL);
		return NULL;
	}
	return param_sat(cmd, name, buffer, tok, sat);
}

struct command_result *param_node_id(struct command *cmd, const char *name,
		  		     const char *buffer, const jsmntok_t *tok,
				     struct node_id **id)
{
	*id = tal(cmd, struct node_id);
	if (json_to_node_id(buffer, tok, *id))
		return NULL;

	return command_fail_badparam(cmd, name, buffer, tok,
				     "should be a node id");
}

struct command_result *param_channel_id(struct command *cmd, const char *name,
					const char *buffer, const jsmntok_t *tok,
					struct channel_id **cid)
{
	*cid = tal(cmd, struct channel_id);
	if (json_to_channel_id(buffer, tok, *cid))
		return NULL;

	return command_fail_badparam(cmd, name, buffer, tok,
				     "should be a channel id");
}

struct command_result *param_short_channel_id(struct command *cmd,
					      const char *name,
					      const char *buffer,
					      const jsmntok_t *tok,
					      struct short_channel_id **scid)
{
	*scid = tal(cmd, struct short_channel_id);
	if (json_to_short_channel_id(buffer, tok, *scid))
		return NULL;

	return command_fail_badparam(cmd, name, buffer, tok,
				     "should be a short_channel_id of form NxNxN");
}

struct command_result *param_secret(struct command *cmd, const char *name,
				    const char *buffer, const jsmntok_t *tok,
				    struct secret **secret)
{
	*secret = tal(cmd, struct secret);
	if (hex_decode(buffer + tok->start,
		       tok->end - tok->start,
		       *secret, sizeof(**secret)))
		return NULL;

	return command_fail_badparam(cmd, name, buffer, tok,
				     "should be a 32 byte hex value");
}

struct command_result *param_bin_from_hex(struct command *cmd, const char *name,
				    const char *buffer, const jsmntok_t *tok,
				    u8 **bin)
{
	*bin = json_tok_bin_from_hex(cmd, buffer, tok);
	if (bin != NULL)
		return NULL;

	return command_fail_badparam(cmd, name, buffer, tok,
				     "should be a hex value");
}

struct command_result *param_hops_array(struct command *cmd, const char *name,
					const char *buffer, const jsmntok_t *tok,
					struct sphinx_hop **hops)
{
	const jsmntok_t *hop, *payloadtok, *pubkeytok;
	struct sphinx_hop h;
	size_t i;
	if (tok->type != JSMN_ARRAY) {
		return command_fail_badparam(cmd, name, buffer, tok,
					     "should be an array of hops");
	}

	*hops = tal_arr(cmd, struct sphinx_hop, 0);

	json_for_each_arr(i, hop, tok) {
		payloadtok = json_get_member(buffer, hop, "payload");
		pubkeytok = json_get_member(buffer, hop, "pubkey");

		if (!pubkeytok)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Hop %zu does not have a pubkey", i);

		if (!payloadtok)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Hop %zu does not have a payload", i);

		h.raw_payload = json_tok_bin_from_hex(*hops, buffer, payloadtok);
		if (!json_to_pubkey(buffer, pubkeytok, &h.pubkey))
			return command_fail_badparam(cmd, name, buffer, pubkeytok,
						     "should be a pubkey");

		if (!h.raw_payload)
			return command_fail_badparam(cmd, name, buffer,
						     payloadtok,
						     "should be hex");

		tal_arr_expand(hops, h);
	}

	if (tal_count(*hops) == 0) {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "At least one hop must be specified.");
	}

	return NULL;
}

struct command_result *param_secrets_array(struct command *cmd,
					   const char *name, const char *buffer,
					   const jsmntok_t *tok,
					   struct secret **secrets)
{
	size_t i;
	const jsmntok_t *s;
	struct secret secret;

	if (tok->type != JSMN_ARRAY) {
		return command_fail_badparam(cmd, name, buffer, tok,
					     "should be an array of secrets");
	}

	*secrets = tal_arr(cmd, struct secret, 0);
	json_for_each_arr(i, s, tok) {
		if (!hex_decode(buffer + s->start, s->end - s->start, &secret,
				sizeof(secret)))
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "'%s[%zu]' should be a 32 byte hex "
					    "value, not '%.*s'",
					    name, i, s->end - s->start,
					    buffer + s->start);

		tal_arr_expand(secrets, secret);
	}
	return NULL;
}

/**
 * segwit_addr_net_decode - Try to decode a Bech32(m) address and detect
 * testnet/mainnet/regtest/signet
 *
 * This processes the address and returns a string if it is a Bech32
 * address specified by BIP173 or Bech32m as by BIP350. The string is
 * set whether it is testnet or signet (both "tb"),  mainnet ("bc"),
 * regtest ("bcrt"). It does not check witness version and program size
 * restrictions.
 *
 *  Out: witness_version: Pointer to an int that will be updated to contain
 *                 the witness program version (between 0 and 16 inclusive).
 *       witness_program: Pointer to a buffer of size 40 that will be updated
 *                 to contain the witness program bytes.
 *       witness_program_len: Pointer to a size_t that will be updated to
 *                 contain the length of bytes in witness_program.
 *  In:  addrz:    Pointer to the null-terminated address.
 *  Returns string containing the human readable segment of bech32 address
 */
static const char *segwit_addr_net_decode(int *witness_version,
					  uint8_t *witness_program,
					  size_t *witness_program_len,
					  const char *addrz,
					  const struct chainparams *chainparams)
{
	if (segwit_addr_decode(witness_version, witness_program,
			       witness_program_len, chainparams->onchain_hrp,
			       addrz))
		return chainparams->onchain_hrp;
	else
		return NULL;
}

enum address_parse_result
json_to_address_scriptpubkey(const tal_t *ctx,
			      const struct chainparams *chainparams,
			      const char *buffer,
			      const jsmntok_t *tok, const u8 **scriptpubkey)
{
	struct bitcoin_address destination;
	int witness_version;
	/* segwit_addr_net_decode requires a buffer of size 40, and will
	 * not write to the buffer if the address is too long, so a buffer
	 * of fixed size 40 will not overflow. */
	uint8_t witness_program[40];
	size_t witness_program_len;

	char *addrz;
	const char *bech32;

	u8 addr_version;

	if (ripemd160_from_base58(&addr_version, &destination.addr,
				  buffer + tok->start, tok->end - tok->start)) {
		if (addr_version == chainparams->p2pkh_version) {
			*scriptpubkey = scriptpubkey_p2pkh(ctx, &destination);
			return ADDRESS_PARSE_SUCCESS;
		} else if (addr_version == chainparams->p2sh_version) {
			*scriptpubkey =
			    scriptpubkey_p2sh_hash(ctx, &destination.addr);
			return ADDRESS_PARSE_SUCCESS;
		} else {
			return ADDRESS_PARSE_WRONG_NETWORK;
		}
		/* Insert other parsers that accept pointer+len here. */
		return ADDRESS_PARSE_UNRECOGNIZED;
	}

	/* Generate null-terminated address. */
	addrz = tal_dup_arr(tmpctx, char, buffer + tok->start, tok->end - tok->start, 1);
	addrz[tok->end - tok->start] = '\0';

	bech32 = segwit_addr_net_decode(&witness_version, witness_program,
					&witness_program_len, addrz, chainparams);
	if (bech32) {
		bool witness_ok;

		/* Only V0 has restricted lengths of witness programs */
		if (witness_version == 0) {
			witness_ok = (witness_program_len == 20 ||
				       witness_program_len == 32);
		} else
			witness_ok = true;

		if (!witness_ok)
			return ADDRESS_PARSE_UNRECOGNIZED;

		if (!streq(bech32, chainparams->onchain_hrp))
			return ADDRESS_PARSE_WRONG_NETWORK;

		*scriptpubkey = scriptpubkey_witness_raw(ctx, witness_version,
							 witness_program, witness_program_len);
		return ADDRESS_PARSE_SUCCESS;
	}

	/* Insert other parsers that accept null-terminated string here. */
	return ADDRESS_PARSE_UNRECOGNIZED;
}

struct command_result *param_txid(struct command *cmd,
				  const char *name,
				  const char *buffer,
				  const jsmntok_t *tok,
				  struct bitcoin_txid **txid)
{
	*txid = tal(cmd, struct bitcoin_txid);
	if (json_to_txid(buffer, tok, *txid))
		return NULL;
	return command_fail_badparam(cmd, name, buffer, tok,
				     "should be a txid");
}

struct command_result *param_bitcoin_address(struct command *cmd,
					     const char *name,
					     const char *buffer,
					     const jsmntok_t *tok,
					     const u8 **scriptpubkey)
{
	/* Parse address. */
	switch (json_to_address_scriptpubkey(cmd,
					     chainparams,
					     buffer, tok,
					     scriptpubkey)) {
	case ADDRESS_PARSE_UNRECOGNIZED:
		return command_fail(cmd, LIGHTNINGD,
				    "Could not parse destination address, "
				    "%s should be a valid address",
				    name ? name : "address field");
	case ADDRESS_PARSE_WRONG_NETWORK:
		return command_fail(cmd, LIGHTNINGD,
				    "Destination address is not on network %s",
				    chainparams->network_name);
	case ADDRESS_PARSE_SUCCESS:
		return NULL;
	}
	abort();
}

struct command_result *param_psbt(struct command *cmd,
				  const char *name,
				  const char *buffer,
				  const jsmntok_t *tok,
				  struct wally_psbt **psbt)
{
	*psbt = psbt_from_b64(cmd, buffer + tok->start, tok->end - tok->start);
	if (*psbt)
		return NULL;

	return command_fail_badparam(cmd, name, buffer, tok,
				     "Expected a PSBT");
}

struct command_result *param_outpoint_arr(struct command *cmd,
					  const char *name,
					  const char *buffer,
					  const jsmntok_t *tok,
					  struct bitcoin_outpoint **outpoints)
{
	size_t i;
	const jsmntok_t *curr;
	if (tok->type != JSMN_ARRAY) {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Could not decode the outpoint array for %s: "
				    "\"%s\" is not a valid outpoint array.",
				    name, json_strdup(tmpctx, buffer, tok));
	}

	*outpoints = tal_arr(cmd, struct bitcoin_outpoint, tok->size);

	json_for_each_arr(i, curr, tok) {
		if (!json_to_outpoint(buffer, curr, &(*outpoints)[i]))
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Could not decode outpoint \"%.*s\", "
					    "expected format: txid:output",
					    json_tok_full_len(curr), json_tok_full(buffer, curr));
	}
	return NULL;
}

struct command_result *param_extra_tlvs(struct command *cmd, const char *name,
					const char *buffer,
					const jsmntok_t *tok,
					struct tlv_field **fields)
{
	size_t i;
	const jsmntok_t *curr;
	struct tlv_field *f, *temp;

	if (tok->type != JSMN_OBJECT) {
		return command_fail(
		    cmd, JSONRPC2_INVALID_PARAMS,
		    "Could not decode the TLV object from %s: "
		    "\"%s\" is not a valid JSON object.",
		    name, json_strdup(tmpctx, buffer, tok));
	}

	temp = tal_arr(cmd, struct tlv_field, tok->size);
	json_for_each_obj(i, curr, tok) {
		f = &temp[i];
		/* Accept either bare ints as keys (not spec
		 * compliant, but simpler), or ints in strings, which
		 * are JSON spec compliant. */
		if (!(json_str_to_u64(buffer, curr, &f->numtype) ||
		      json_to_u64(buffer, curr, &f->numtype))) {
			return command_fail(
			    cmd, JSONRPC2_INVALID_PARAMS,
			    "\"%s\" is not a valid numeric TLV type.",
			    json_strdup(tmpctx, buffer, curr));
		}
		f->value = json_tok_bin_from_hex(temp, buffer, curr + 1);

		if (f->value == NULL) {
			return command_fail(
			    cmd, JSONRPC2_INVALID_PARAMS,
			    "\"%s\" is not a valid hex encoded TLV value.",
			    json_strdup(tmpctx, buffer, curr));
		}
		f->length = tal_bytelen(f->value);
		f->meta = NULL;
	}
	*fields = temp;
	return NULL;
}

static struct command_result *param_routehint(struct command *cmd,
					      const char *name,
					      const char *buffer,
					      const jsmntok_t *tok,
					      struct route_info **ri)
{
	size_t i;
	const jsmntok_t *curr;
	const char *err;

	if (tok->type != JSMN_ARRAY) {
		return command_fail(
		    cmd, JSONRPC2_INVALID_PARAMS,
		    "Routehint %s (\"%s\") is not an array of hop objects",
		    name, json_strdup(tmpctx, buffer, tok));
	}

	*ri = tal_arr(cmd, struct route_info, tok->size);
	json_for_each_arr(i, curr, tok) {
		struct route_info *e = &(*ri)[i];
		struct amount_msat temp;

		err = json_scan(tmpctx, buffer, curr,
				"{id:%,scid:%,feebase:%,feeprop:%,expirydelta:%}",
				JSON_SCAN(json_to_node_id, &e->pubkey),
				JSON_SCAN(json_to_short_channel_id, &e->short_channel_id),
				JSON_SCAN(json_to_msat, &temp),
				JSON_SCAN(json_to_u32, &e->fee_proportional_millionths),
				JSON_SCAN(json_to_u16, &e->cltv_expiry_delta)
			);
		e->fee_base_msat =
		    temp.millisatoshis; /* Raw: internal conversion. */
		if (err != NULL) {
			return command_fail(
			    cmd, JSONRPC2_INVALID_PARAMS,
			    "Error parsing routehint %s[%zu]: %s", name, i,
			    err);
		}
	}
	return NULL;
}

struct command_result *
param_routehint_array(struct command *cmd, const char *name, const char *buffer,
		      const jsmntok_t *tok, struct route_info ***ris)
{
	size_t i;
	const jsmntok_t *curr;
	char *element_name;
	struct command_result *err;
	if (tok->type != JSMN_ARRAY) {
		return command_fail(
		    cmd, JSONRPC2_INVALID_PARAMS,
		    "Routehint array %s (\"%s\") is not an array",
		    name, json_strdup(tmpctx, buffer, tok));
	}

	*ris = tal_arr(cmd, struct route_info *, 0);
	json_for_each_arr(i, curr, tok) {
		struct route_info *element;
		element_name = tal_fmt(cmd, "%s[%zu]", name, i);
		err = param_routehint(cmd, element_name, buffer, curr, &element);
		if (err != NULL) {
			return err;
		}
		tal_arr_expand(ris, element);

		tal_free(element_name);
	}
	return NULL;
}

struct command_result *param_route_exclusion(struct command *cmd,
					const char *name, const char *buffer, const jsmntok_t *tok,
					struct route_exclusion **re)
{
	*re = tal(cmd, struct route_exclusion);
	struct short_channel_id_dir *chan_id =
					tal(tmpctx, struct short_channel_id_dir);
	if (!short_channel_id_dir_from_str(buffer + tok->start,
						tok->end - tok->start,
						chan_id)) {
		struct node_id *node_id = tal(tmpctx, struct node_id);

		if (!json_to_node_id(buffer, tok, node_id))
			return command_fail_badparam(cmd, "exclude",
								buffer, tok,
								"should be short_channel_id_dir or node_id");

		(*re)->type = EXCLUDE_NODE;
		(*re)->u.node_id = *node_id;
	} else {
		(*re)->type = EXCLUDE_CHANNEL;
		(*re)->u.chan_id = *chan_id;
	}

	return NULL;
}

struct command_result *
param_route_exclusion_array(struct command *cmd, const char *name,
					const char *buffer, const jsmntok_t *tok,
					struct route_exclusion ***res)
{
	size_t i;
	const jsmntok_t *curr;
	char *element_name;
	struct command_result *err;
	if (tok->type != JSMN_ARRAY) {
		return command_fail(
		    cmd, JSONRPC2_INVALID_PARAMS,
		    "Exclude array %s (\"%s\") is not an array",
		    name, json_strdup(tmpctx, buffer, tok));
	}

	*res = tal_arr(cmd, struct route_exclusion *, 0);
	json_for_each_arr(i, curr, tok) {
		struct route_exclusion *element;
		element_name = tal_fmt(cmd, "%s[%zu]", name, i);
		err = param_route_exclusion(cmd, element_name, buffer, curr, &element);
		if (err != NULL) {
			return err;
		}
		tal_arr_expand(res, element);

		tal_free(element_name);
	}
	return NULL;
}

struct command_result *param_lease_hex(struct command *cmd,
				       const char *name,
				       const char *buffer,
				       const jsmntok_t *tok,
				       struct lease_rates **rates)
{
	*rates = lease_rates_fromhex(cmd, buffer + tok->start,
				     tok->end - tok->start);
	if (!*rates)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Could not decode '%s' %.*s",
				    name, json_tok_full_len(tok),
				    json_tok_full(buffer, tok));
	return NULL;
}

struct command_result *param_pubkey(struct command *cmd, const char *name,
				    const char *buffer, const jsmntok_t *tok,
				    struct pubkey **pubkey)
{
	*pubkey = tal(cmd, struct pubkey);
	if (json_to_pubkey(buffer, tok, *pubkey))
		return NULL;

	return command_fail_badparam(cmd, name, buffer, tok,
				     "should be a compressed pubkey");
}

