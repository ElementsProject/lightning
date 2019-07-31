#include <arpa/inet.h>
#include <ccan/json_escape/json_escape.h>
#include <ccan/mem/mem.h>
#include <ccan/str/hex/hex.h>
#include <ccan/tal/str/str.h>
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

struct command_result *param_node_id(struct command *cmd,
				     const char *name,
				     const char *buffer,
				     const jsmntok_t *tok,
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
	if (json_to_short_channel_id(buffer, tok, *scid,
				     deprecated_apis))
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

struct command_result *param_route(struct command *cmd, const char *name,
				   const char *buffer, const jsmntok_t *tok,
				   struct route_hop **route)
{
	struct command_result *result;
	const jsmntok_t *routetok;
	const jsmntok_t *t;
	size_t i;

	result = param_array(cmd, name, buffer, tok, &routetok);
	if (result)
		return result;

	if (routetok->size == 0)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Empty route");

	*route = tal_arr(cmd, struct route_hop, routetok->size);
	json_for_each_arr(i, t, routetok) {
		struct amount_msat *msat, *amount_msat;
		struct node_id *id;
		struct short_channel_id *channel;
		unsigned *delay, *direction;

		if (!param(cmd, buffer, t,
			   /* Only *one* of these is required */
			   p_opt("msatoshi", param_msat, &msat),
			   p_opt("amount_msat", param_msat, &amount_msat),
			   /* These three actually required */
			   p_opt("id", param_node_id, &id),
			   p_opt("delay", param_number, &delay),
			   p_opt("channel", param_short_channel_id, &channel),
			   p_opt("direction", param_number, &direction),
			   NULL))
			return command_param_failed();

		if (!msat && !amount_msat)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "route[%zi]: must have msatoshi"
					    " or amount_msat", i);
		if (!id || !channel || !delay)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "route[%zi]: must have id, channel"
					    " and delay", i);
		if (msat && amount_msat && !amount_msat_eq(*msat, *amount_msat))
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "route[%zi]: msatoshi %s != amount_msat %s",
					    i,
					    type_to_string(tmpctx,
							   struct amount_msat,
							   msat),
					    type_to_string(tmpctx,
							   struct amount_msat,
							   amount_msat));
		if (!msat)
			msat = amount_msat;

		(*route)[i].amount = *msat;
		(*route)[i].nodeid = *id;
		(*route)[i].delay = *delay;
		(*route)[i].channel_id = *channel;
		/* FIXME: Actually ignored by sendpay code! */
		(*route)[i].direction = direction ? *direction : 0;
	}

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
