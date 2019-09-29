#include <arpa/inet.h>
#include <bitcoin/address.h>
#include <bitcoin/base58.h>
#include <bitcoin/script.h>
#include <ccan/json_escape/json_escape.h>
#include <ccan/mem/mem.h>
#include <ccan/str/hex/hex.h>
#include <ccan/tal/str/str.h>
#include <common/bech32.h>
#include <common/json.h>
#include <common/json_command.h>
#include <common/json_helpers.h>
#include <common/jsonrpc_errors.h>
#include <common/memleak.h>
#include <common/node_id.h>
#include <common/param.h>
#include <common/type_to_string.h>
#include <common/wallet_tx.h>
#include <common/wireaddr.h>
#include <gossipd/routing.h>
#include <lightningd/chaintopology.h>
#include <lightningd/json.h>
#include <lightningd/json_stream.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/options.h>
#include <sys/socket.h>
#include <wallet/wallet.h>
#include <wire/wire.h>

/* Output a route hop */
static void
json_add_route_hop(struct json_stream *r, char const *n,
		   const struct route_hop *h)
{
	/* Imitate what getroute/sendpay use */
	json_object_start(r, n);
	json_add_node_id(r, "id", &h->nodeid);
	json_add_short_channel_id(r, "channel",
				  &h->channel_id);
	json_add_num(r, "direction", h->direction);
	json_add_amount_msat_compat(r, h->amount, "msatoshi", "amount_msat");
	json_add_num(r, "delay", h->delay);
	json_object_end(r);
}

/* Output a route */
void
json_add_route(struct json_stream *r, char const *n,
	       const struct route_hop *hops, size_t hops_len)
{
	size_t i;
	json_array_start(r, n);
	for (i = 0; i < hops_len; ++i) {
		json_add_route_hop(r, NULL, &hops[i]);
	}
	json_array_end(r);
}

void json_add_node_id(struct json_stream *response,
		      const char *fieldname,
		      const struct node_id *id)
{
	json_add_hex(response, fieldname, id->k, sizeof(id->k));
}

void json_add_pubkey(struct json_stream *response,
		     const char *fieldname,
		     const struct pubkey *key)
{
	u8 der[PUBKEY_CMPR_LEN];

	pubkey_to_der(der, key);
	json_add_hex(response, fieldname, der, sizeof(der));
}

void json_add_txid(struct json_stream *result, const char *fieldname,
		   const struct bitcoin_txid *txid)
{
	char hex[hex_str_size(sizeof(*txid))];

	bitcoin_txid_to_hex(txid, hex, sizeof(hex));
	json_add_string(result, fieldname, hex);
}

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

void json_add_short_channel_id(struct json_stream *response,
			       const char *fieldname,
			       const struct short_channel_id *scid)
{
	json_add_member(response, fieldname, true, "%dx%dx%d",
			short_channel_id_blocknum(scid),
			short_channel_id_txnum(scid),
			short_channel_id_outnum(scid));
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
	return NULL;
}

bool
json_tok_channel_id(const char *buffer, const jsmntok_t *tok,
		    struct channel_id *cid)
{
	return hex_decode(buffer + tok->start, tok->end - tok->start,
			  cid, sizeof(*cid));
}

void json_add_address(struct json_stream *response, const char *fieldname,
		      const struct wireaddr *addr)
{
	json_object_start(response, fieldname);
	char *addrstr = tal_arr(response, char, INET6_ADDRSTRLEN);
	if (addr->type == ADDR_TYPE_IPV4) {
		inet_ntop(AF_INET, addr->addr, addrstr, INET_ADDRSTRLEN);
		json_add_string(response, "type", "ipv4");
		json_add_string(response, "address", addrstr);
		json_add_num(response, "port", addr->port);
	} else if (addr->type == ADDR_TYPE_IPV6) {
		inet_ntop(AF_INET6, addr->addr, addrstr, INET6_ADDRSTRLEN);
		json_add_string(response, "type", "ipv6");
		json_add_string(response, "address", addrstr);
		json_add_num(response, "port", addr->port);
	} else if (addr->type == ADDR_TYPE_TOR_V2) {
		json_add_string(response, "type", "torv2");
		json_add_string(response, "address", fmt_wireaddr_without_port(tmpctx, addr));
		json_add_num(response, "port", addr->port);
	} else if (addr->type == ADDR_TYPE_TOR_V3) {
		json_add_string(response, "type", "torv3");
		json_add_string(response, "address", fmt_wireaddr_without_port(tmpctx, addr));
		json_add_num(response, "port", addr->port);
	}
	json_object_end(response);
}

void json_add_address_internal(struct json_stream *response,
			       const char *fieldname,
			       const struct wireaddr_internal *addr)
{
	switch (addr->itype) {
	case ADDR_INTERNAL_SOCKNAME:
		json_object_start(response, fieldname);
		json_add_string(response, "type", "local socket");
		json_add_string(response, "socket", addr->u.sockname);
		json_object_end(response);
		return;
	case ADDR_INTERNAL_ALLPROTO:
		json_object_start(response, fieldname);
		json_add_string(response, "type", "any protocol");
		json_add_num(response, "port", addr->u.port);
		json_object_end(response);
		return;
	case ADDR_INTERNAL_AUTOTOR:
		json_object_start(response, fieldname);
		json_add_string(response, "type", "Tor generated address");
		json_add_address(response, "service", &addr->u.torservice);
		json_object_end(response);
		return;
	case ADDR_INTERNAL_FORPROXY:
		json_object_start(response, fieldname);
		json_add_string(response, "type", "unresolved");
		json_add_string(response, "name", addr->u.unresolved.name);
		json_add_num(response, "port", addr->u.unresolved.port);
		json_object_end(response);
		return;
	case ADDR_INTERNAL_WIREADDR:
		json_add_address(response, fieldname, &addr->u.wireaddr);
		return;
	}
	abort();
}

void json_add_num(struct json_stream *result, const char *fieldname, unsigned int value)
{
	json_add_member(result, fieldname, false, "%u", value);
}

void json_add_double(struct json_stream *result, const char *fieldname, double value)
{
	json_add_member(result, fieldname, false, "%f", value);
}

void json_add_u64(struct json_stream *result, const char *fieldname,
		  uint64_t value)
{
	json_add_member(result, fieldname, false, "%"PRIu64, value);
}

void json_add_s64(struct json_stream *result, const char *fieldname,
		  int64_t value)
{
	json_add_member(result, fieldname, false, "%"PRIi64, value);
}

void json_add_u32(struct json_stream *result, const char *fieldname,
		  uint32_t value)
{
	json_add_member(result, fieldname, false, "%u", value);
}

void json_add_s32(struct json_stream *result, const char *fieldname,
		  int32_t value)
{
	json_add_member(result, fieldname, false, "%d", value);
}

void json_add_literal(struct json_stream *result, const char *fieldname,
		      const char *literal, int len)
{
	/* Literal may contain quotes, so bypass normal checks */
	char *dest = json_member_direct(result, fieldname, strlen(literal));
	if (dest)
		memcpy(dest, literal, strlen(literal));
}

void json_add_string(struct json_stream *result, const char *fieldname, const char *value TAKES)
{
	json_add_member(result, fieldname, true, "%s", value);
	if (taken(value))
		tal_free(value);
}

void json_add_bool(struct json_stream *result, const char *fieldname, bool value)
{
	json_add_member(result, fieldname, false, value ? "true" : "false");
}

void json_add_null(struct json_stream *stream, const char *fieldname)
{
	json_add_member(stream, fieldname, false, "null");
}

void json_add_hex(struct json_stream *js, const char *fieldname,
		  const void *data, size_t len)
{
	/* Size without NUL term */
	size_t hexlen = hex_str_size(len) - 1;
	char *dest;

	dest = json_member_direct(js, fieldname, 1 + hexlen + 1);
	if (dest) {
		dest[0] = '"';
		if (!hex_encode(data, len, dest + 1, hexlen + 1))
			abort();
		dest[1+hexlen] = '"';
	}
}

void json_add_hex_talarr(struct json_stream *result,
			 const char *fieldname,
			 const tal_t *data)
{
	json_add_hex(result, fieldname, data, tal_bytelen(data));
}

void json_add_tx(struct json_stream *result,
		 const char *fieldname,
		 const struct bitcoin_tx *tx)
{
	json_add_hex_talarr(result, fieldname, linearize_tx(tmpctx, tx));
}

void json_add_escaped_string(struct json_stream *result, const char *fieldname,
			     const struct json_escape *esc TAKES)
{
	/* Already escaped, don't re-escape! */
	char *dest = json_member_direct(result,	fieldname,
					1 + strlen(esc->s) + 1);

	if (dest) {
		dest[0] = '"';
		memcpy(dest + 1, esc->s, strlen(esc->s));
		dest[1+strlen(esc->s)] = '"';
	}
	if (taken(esc))
		tal_free(esc);
}

void json_add_amount_msat_compat(struct json_stream *result,
				 struct amount_msat msat,
				 const char *rawfieldname,
				 const char *msatfieldname)
{
	json_add_u64(result, rawfieldname, msat.millisatoshis); /* Raw: low-level helper */
	json_add_amount_msat_only(result, msatfieldname, msat);
}

void json_add_amount_msat_only(struct json_stream *result,
			  const char *msatfieldname,
			  struct amount_msat msat)
{
	json_add_string(result, msatfieldname,
			type_to_string(tmpctx, struct amount_msat, &msat));
}

void json_add_amount_sat_compat(struct json_stream *result,
				struct amount_sat sat,
				const char *rawfieldname,
				const char *msatfieldname)
{
	json_add_u64(result, rawfieldname, sat.satoshis); /* Raw: low-level helper */
	json_add_amount_sat_only(result, msatfieldname, sat);
}

void json_add_amount_sat_only(struct json_stream *result,
			 const char *msatfieldname,
			 struct amount_sat sat)
{
	struct amount_msat msat;
	if (amount_sat_to_msat(&msat, sat))
		json_add_string(result, msatfieldname,
				type_to_string(tmpctx, struct amount_msat, &msat));
}

void json_add_timeabs(struct json_stream *result, const char *fieldname,
		      struct timeabs t)
{
	json_add_member(result, fieldname, false, "%" PRIu64 ".%03" PRIu64,
			(u64)t.ts.tv_sec, (u64)t.ts.tv_nsec / 1000000);
}

void json_add_time(struct json_stream *result, const char *fieldname,
			  struct timespec ts)
{
	char timebuf[100];

	snprintf(timebuf, sizeof(timebuf), "%lu.%09u",
		(unsigned long)ts.tv_sec,
		(unsigned)ts.tv_nsec);
	json_add_string(result, fieldname, timebuf);
}

void json_add_secret(struct json_stream *response, const char *fieldname,
		     const struct secret *secret)
{
	json_add_hex(response, fieldname, secret, sizeof(struct secret));
}

void json_add_sha256(struct json_stream *result, const char *fieldname,
		     const struct sha256 *hash)
{
	json_add_hex(result, fieldname, hash, sizeof(*hash));
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
					     get_chainparams(cmd->ld),
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
				    get_chainparams(cmd->ld)->network_name);
	case ADDRESS_PARSE_SUCCESS:
		return NULL;
	}
	abort();
}
