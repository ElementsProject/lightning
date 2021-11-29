#include "config.h"
#include <bitcoin/address.h>
#include <bitcoin/base58.h>
#include <bitcoin/feerate.h>
#include <bitcoin/psbt.h>
#include <bitcoin/script.h>
#include <ccan/json_escape/json_escape.h>
#include <ccan/str/hex/hex.h>
#include <ccan/tal/str/str.h>
#include <common/bech32.h>
#include <common/json_command.h>
#include <common/json_helpers.h>
#include <common/json_tok.h>
#include <common/route.h>

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

/**
 * segwit_addr_net_decode - Try to decode a Bech32 address and detect
 * testnet/mainnet/regtest/signet
 *
 * This processes the address and returns a string if it is a Bech32
 * address specified by BIP173. The string is set whether it is
 * testnet or signet (both "tb"),  mainnet ("bc"), regtest ("bcrt")
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
		bool witness_ok;

		/* We know the rules for v0, rest remain undefined */
		if (witness_version == 0) {
			witness_ok = (witness_program_len == 20 ||
				       witness_program_len == 32);
		} else
			witness_ok = true;

		if (witness_ok) {
			*scriptpubkey = scriptpubkey_witness_raw(ctx, witness_version,
								 witness_program, witness_program_len);
			parsed = true;
			right_network = streq(bip173, chainparams->onchain_hrp);
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
		if (!json_to_u64(buffer, curr, &f->numtype)) {
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
