#include <bitcoin/address.h>
#include <bitcoin/base58.h>
#include <bitcoin/chainparams.h>
#include <bitcoin/feerate.h>
#include <bitcoin/script.h>
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/json_escape/json_escape.h>
#include <ccan/str/hex/hex.h>
#include <ccan/tal/str/str.h>
#include <common/amount.h>
#include <common/bech32.h>
#include <common/channel_id.h>
#include <common/json.h>
#include <common/json_command.h>
#include <common/json_helpers.h>
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

struct command_result *param_millionths(struct command *cmd, const char *name,
					const char *buffer,
					const jsmntok_t *tok, uint64_t **num)
{
	*num = tal(cmd, uint64_t);
	if (json_to_millionths(buffer, tok, *num))
		return NULL;

	return command_fail(
	    cmd, JSONRPC2_INVALID_PARAMS,
	    "'%s' should be a non-negative floating-point number, not '%.*s'",
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
			    "%s should be a satoshi amount, not '%.*s'",
			    name ? name : "amount field",
			    tok->end - tok->start, buffer + tok->start);
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

	return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			    "'%s' should be a node id, not '%.*s'",
			    name, json_tok_full_len(tok),
			    json_tok_full(buffer, tok));
}

struct command_result *param_channel_id(struct command *cmd, const char *name,
					const char *buffer, const jsmntok_t *tok,
					struct channel_id **cid)
{
	*cid = tal(cmd, struct channel_id);
	if (json_to_channel_id(buffer, tok, *cid))
		return NULL;

	return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			    "'%s' should be a channel id, not '%.*s'",
			    name, json_tok_full_len(tok),
			    json_tok_full(buffer, tok));
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

	return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			    "'%s' should be a 32 byte hex value, not '%.*s'",
			    name, tok->end - tok->start, buffer + tok->start);
}

struct command_result *param_bin_from_hex(struct command *cmd, const char *name,
				    const char *buffer, const jsmntok_t *tok,
				    u8 **bin)
{
	*bin = json_tok_bin_from_hex(cmd, buffer, tok);
	if (bin != NULL)
		return NULL;
	else
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "'%s' should be a hex value, not '%.*s'",
				    name, tok->end - tok->start, buffer + tok->start);
}

struct command_result *param_hops_array(struct command *cmd, const char *name,
					const char *buffer, const jsmntok_t *tok,
					struct sphinx_hop **hops)
{
	const jsmntok_t *hop, *payloadtok, *pubkeytok;
	struct sphinx_hop h;
	size_t i;
	if (tok->type != JSMN_ARRAY) {
		return command_fail(
		    cmd, JSONRPC2_INVALID_PARAMS,
		    "'%s' should be an array of hops, got '%.*s'", name,
		    tok->end - tok->start, buffer + tok->start);
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
			return command_fail(
			    cmd, JSONRPC2_INVALID_PARAMS,
			    "'pubkey' should be a pubkey, not '%.*s'",
			    pubkeytok->end - pubkeytok->start,
			    buffer + pubkeytok->start);

		if (!h.raw_payload)
			return command_fail(
			    cmd, JSONRPC2_INVALID_PARAMS,
			    "'payload' should be a hex encoded binary, not '%.*s'",
			    pubkeytok->end - pubkeytok->start,
			    buffer + pubkeytok->start);

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
		return command_fail(
		    cmd, JSONRPC2_INVALID_PARAMS,
		    "'%s' should be an array of secrets, got '%.*s'", name,
		    tok->end - tok->start, buffer + tok->start);
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

struct command_result *param_feerate_val(struct command *cmd,
					 const char *name, const char *buffer,
					 const jsmntok_t *tok,
					 u32 **feerate_per_kw)
{
	jsmntok_t base = *tok, suffix = *tok;
	enum feerate_style style;
	unsigned int num;

	/* We have to split the number and suffix. */
	suffix.start = suffix.end;
	while (suffix.start > base.start && !isdigit(buffer[suffix.start-1])) {
		suffix.start--;
		base.end--;
	}

	if (!json_to_number(buffer, &base, &num)) {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "'%s' prefix should be an integer, not '%.*s'",
				    name, base.end - base.start,
				    buffer + base.start);
	}

	if (suffix.end == suffix.start
	    || json_tok_streq(buffer, &suffix,
			      feerate_style_name(FEERATE_PER_KBYTE))) {
		style = FEERATE_PER_KBYTE;
	} else if (json_tok_streq(buffer, &suffix,
				feerate_style_name(FEERATE_PER_KSIPA))) {
		style = FEERATE_PER_KSIPA;
	} else {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "'%s' suffix should be '%s' or '%s', not '%.*s'",
				    name,
				    feerate_style_name(FEERATE_PER_KSIPA),
				    feerate_style_name(FEERATE_PER_KBYTE),
				    suffix.end - suffix.start,
				    buffer + suffix.start);
	}

	*feerate_per_kw = tal(cmd, u32);
	**feerate_per_kw = feerate_from_style(num, style);
	if (**feerate_per_kw < FEERATE_FLOOR)
		**feerate_per_kw = FEERATE_FLOOR;
	return NULL;
}

/**
 * segwit_addr_net_decode - Try to decode a Bech32 address and detect
 * testnet/mainnet/regtest/signet
 *
 * This processes the address and returns a string if it is a Bech32
 * address specified by BIP173. The string is set whether it is
 * testnet ("tb"),  mainnet ("bc"), regtest ("bcrt"), or signet ("sb")
 * It does not check, witness version and program size restrictions.
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
			       witness_program_len, chainparams->bip173_name,
			       addrz))
		return chainparams->bip173_name;
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
	const char *bip173;

	bool parsed;
	bool right_network;
	u8 addr_version;

	parsed =
	    ripemd160_from_base58(&addr_version, &destination.addr,
				  buffer + tok->start, tok->end - tok->start);

	if (parsed) {
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
	}

	/* Generate null-terminated address. */
	addrz = tal_dup_arr(ctx, char, buffer + tok->start, tok->end - tok->start, 1);
	addrz[tok->end - tok->start] = '\0';

	bip173 = segwit_addr_net_decode(&witness_version, witness_program,
					&witness_program_len, addrz, chainparams);

	if (bip173) {
		bool witness_ok = false;
		if (witness_version == 0 && (witness_program_len == 20 ||
					     witness_program_len == 32)) {
			witness_ok = true;
		}
		/* Insert other witness versions here. */

		if (witness_ok) {
			*scriptpubkey = scriptpubkey_witness_raw(ctx, witness_version,
								 witness_program, witness_program_len);
			parsed = true;
			right_network = streq(bip173, chainparams->bip173_name);
		}
	}
	/* Insert other parsers that accept null-terminated string here. */

	tal_free(addrz);

	if (parsed) {
		if (right_network)
			return ADDRESS_PARSE_SUCCESS;
		else
			return ADDRESS_PARSE_WRONG_NETWORK;
	}

	return ADDRESS_PARSE_UNRECOGNIZED;
}
