#include <arpa/inet.h>
#include <bitcoin/address.h>
#include <bitcoin/base58.h>
#include <bitcoin/feerate.h>
#include <bitcoin/script.h>
#include <ccan/json_escape/json_escape.h>
#include <ccan/mem/mem.h>
#include <ccan/str/hex/hex.h>
#include <ccan/tal/str/str.h>
#include <common/bech32.h>
#include <common/channel_id.h>
#include <common/json.h>
#include <common/json_command.h>
#include <common/json_helpers.h>
#include <common/jsonrpc_errors.h>
#include <common/memleak.h>
#include <common/param.h>
#include <common/type_to_string.h>
#include <common/utils.h>
#include <gossipd/routing.h>
#include <lightningd/chaintopology.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/options.h>
#include <sys/socket.h>
#include <wire/wire.h>

struct command_result *param_pubkey(struct command *cmd, const char *name,
				    const char *buffer, const jsmntok_t *tok,
				    struct pubkey **pubkey)
{
	*pubkey = tal(cmd, struct pubkey);
	if (json_to_pubkey(buffer, tok, *pubkey))
		return NULL;

	return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			    "'%s' should be a pubkey, not '%.*s'",
			    name, json_tok_full_len(tok),
			    json_tok_full(buffer, tok));
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
	return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			    "'%s' should be txid, not '%.*s'",
			    name, json_tok_full_len(tok),
			    json_tok_full(buffer, tok));
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

	return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			    "'%s' should be a short channel id, not '%.*s'",
			    name, json_tok_full_len(tok),
			    json_tok_full(buffer, tok));
}

const char *json_feerate_style_name(enum feerate_style style)
{
	switch (style) {
	case FEERATE_PER_KBYTE:
		return "perkb";
	case FEERATE_PER_KSIPA:
		return "perkw";
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
			   json_feerate_style_name(FEERATE_PER_KSIPA))) {
		**style = FEERATE_PER_KSIPA;
		return NULL;
	} else if (json_tok_streq(buffer, tok,
				  json_feerate_style_name(FEERATE_PER_KBYTE))) {
		**style = FEERATE_PER_KBYTE;
		return NULL;
	}

	return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			    "'%s' should be '%s' or '%s', not '%.*s'",
			    name,
			    json_feerate_style_name(FEERATE_PER_KSIPA),
			    json_feerate_style_name(FEERATE_PER_KBYTE),
			    json_tok_full_len(tok), json_tok_full(buffer, tok));
}

struct command_result *param_feerate(struct command *cmd, const char *name,
				     const char *buffer, const jsmntok_t *tok,
				     u32 **feerate)
{
	jsmntok_t base = *tok, suffix = *tok;
	enum feerate_style style;
	unsigned int num;

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

	if (json_tok_streq(buffer, &suffix, "")
	    || json_tok_streq(buffer, &suffix,
			      json_feerate_style_name(FEERATE_PER_KBYTE))) {
		style = FEERATE_PER_KBYTE;
	} else if (json_tok_streq(buffer, &suffix,
				json_feerate_style_name(FEERATE_PER_KSIPA))) {
		style = FEERATE_PER_KSIPA;
	} else {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "'%s' suffix should be '%s' or '%s', not '%.*s'",
				    name,
				    json_feerate_style_name(FEERATE_PER_KSIPA),
				    json_feerate_style_name(FEERATE_PER_KBYTE),
				    suffix.end - suffix.start,
				    buffer + suffix.start);
	}

	*feerate = tal(cmd, u32);
	**feerate = feerate_from_style(num, style);
	if (**feerate < FEERATE_FLOOR)
		**feerate = FEERATE_FLOOR;
	return NULL;
}

bool
json_tok_channel_id(const char *buffer, const jsmntok_t *tok,
		    struct channel_id *cid)
{
	return hex_decode(buffer + tok->start, tok->end - tok->start,
			  cid, sizeof(*cid));
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
