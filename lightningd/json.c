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

bool
json_tok_channel_id(const char *buffer, const jsmntok_t *tok,
		    struct channel_id *cid)
{
	return hex_decode(buffer + tok->start, tok->end - tok->start,
			  cid, sizeof(*cid));
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
