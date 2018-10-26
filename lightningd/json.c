#include "json.h"
#include <arpa/inet.h>
#include <ccan/mem/mem.h>
#include <ccan/str/hex/hex.h>
#include <ccan/tal/str/str.h>
#include <common/json.h>
#include <common/memleak.h>
#include <common/type_to_string.h>
#include <common/wireaddr.h>
#include <gossipd/routing.h>
#include <lightningd/json_escaped.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/jsonrpc_errors.h>
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
	json_add_pubkey(r, "id", &h->nodeid);
	json_add_short_channel_id(r, "channel",
				  &h->channel_id);
	json_add_u64(r, "msatoshi", h->amount);
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

/* Outputs fields, not a separate object*/
void
json_add_payment_fields(struct json_stream *response,
			const struct wallet_payment *t)
{
	json_add_u64(response, "id", t->id);
	json_add_hex(response, "payment_hash", &t->payment_hash, sizeof(t->payment_hash));
	json_add_pubkey(response, "destination", &t->destination);
	json_add_u64(response, "msatoshi", t->msatoshi);
	json_add_u64(response, "msatoshi_sent", t->msatoshi_sent);
	json_add_u64(response, "created_at", t->timestamp);

	switch (t->status) {
	case PAYMENT_PENDING:
		json_add_string(response, "status", "pending");
		break;
	case PAYMENT_COMPLETE:
		json_add_string(response, "status", "complete");
		break;
	case PAYMENT_FAILED:
		json_add_string(response, "status", "failed");
		break;
	}
	if (t->payment_preimage)
		json_add_hex(response, "payment_preimage",
			     t->payment_preimage,
			     sizeof(*t->payment_preimage));
	if (t->description)
		json_add_string(response, "description", t->description);
}

void json_add_pubkey(struct json_stream *response,
		     const char *fieldname,
		     const struct pubkey *key)
{
	u8 der[PUBKEY_DER_LEN];

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

bool json_tok_array(struct command *cmd, const char *name,
		    const char *buffer, const jsmntok_t *tok,
		    const jsmntok_t **arr)
{
	if (tok->type == JSMN_ARRAY)
		return (*arr = tok);

	command_fail(cmd, JSONRPC2_INVALID_PARAMS,
		     "'%s' should be an array, not '%.*s'",
		     name, tok->end - tok->start, buffer + tok->start);
	return false;
}

bool json_tok_bool(struct command *cmd, const char *name,
		   const char *buffer, const jsmntok_t *tok,
		   bool **b)
{
	*b = tal(cmd, bool);
	if (tok->type == JSMN_PRIMITIVE) {
		if (memeqstr(buffer + tok->start, tok->end - tok->start, "true")) {
			**b = true;
			return true;
		}
		if (memeqstr(buffer + tok->start, tok->end - tok->start, "false")) {
			**b = false;
			return true;
		}
	}
	command_fail(cmd, JSONRPC2_INVALID_PARAMS,
		     "'%s' should be 'true' or 'false', not '%.*s'",
		     name, tok->end - tok->start, buffer + tok->start);
	return false;
}

bool json_tok_double(struct command *cmd, const char *name,
		     const char *buffer, const jsmntok_t *tok,
		     double **num)
{
	*num = tal(cmd, double);
	if (json_to_double(buffer, tok, *num))
		return true;

	command_fail(cmd, JSONRPC2_INVALID_PARAMS,
		     "'%s' should be a double, not '%.*s'",
		     name, tok->end - tok->start, buffer + tok->start);
	return false;
}

bool json_tok_escaped_string(struct command *cmd, const char *name,
			     const char * buffer, const jsmntok_t *tok,
			     const char **str)
{
	struct json_escaped *esc = json_to_escaped_string(cmd, buffer, tok);
	if (esc) {
		*str = json_escaped_unescape(cmd, esc);
		if (*str)
			return true;
	}
	command_fail(cmd, JSONRPC2_INVALID_PARAMS,
		     "'%s' should be a string, not '%.*s'"
		     " (note, we don't allow \\u)",
		     name,
		     tok->end - tok->start, buffer + tok->start);
	return false;
}

bool json_tok_string(struct command *cmd, const char *name,
		     const char * buffer, const jsmntok_t *tok,
		     const char **str)
{
	*str = tal_strndup(cmd, buffer + tok->start,
			   tok->end - tok->start);
	return true;
}

bool json_tok_label(struct command *cmd, const char *name,
		    const char * buffer, const jsmntok_t *tok,
		    struct json_escaped **label)
{
	/* We accept both strings and number literals here. */
	*label = json_escaped_string_(cmd, buffer + tok->start, tok->end - tok->start);
	if (*label && (tok->type == JSMN_STRING || json_tok_is_num(buffer, tok)))
		    return true;

	command_fail(cmd, JSONRPC2_INVALID_PARAMS,
		     "'%s' should be a string or number, not '%.*s'",
		     name, tok->end - tok->start, buffer + tok->start);
	return false;
}

bool json_tok_number(struct command *cmd, const char *name,
		     const char *buffer, const jsmntok_t *tok,
		     unsigned int **num)
{
	*num = tal(cmd, unsigned int);
	if (json_to_number(buffer, tok, *num))
		return true;

	command_fail(cmd, JSONRPC2_INVALID_PARAMS,
		     "'%s' should be an integer, not '%.*s'",
		     name, tok->end - tok->start, buffer + tok->start);
	return false;
}

bool json_tok_sha256(struct command *cmd, const char *name,
		     const char *buffer, const jsmntok_t *tok,
		     struct sha256 **hash)
{
	*hash = tal(cmd, struct sha256);
	if (hex_decode(buffer + tok->start,
		       tok->end - tok->start,
		       *hash, sizeof(**hash)))
		return true;

	command_fail(cmd, JSONRPC2_INVALID_PARAMS,
		     "'%s' should be a 32 byte hex value, not '%.*s'",
		     name, tok->end - tok->start, buffer + tok->start);
	return false;
}

bool json_tok_msat(struct command *cmd, const char *name,
		   const char *buffer, const jsmntok_t * tok,
		   u64 **msatoshi_val)
{
	if (json_tok_streq(buffer, tok, "any")) {
		*msatoshi_val = NULL;
		return true;
	}
	*msatoshi_val = tal(cmd, u64);

	if (json_to_u64(buffer, tok, *msatoshi_val) && *msatoshi_val != 0)
		return true;

	command_fail(cmd, JSONRPC2_INVALID_PARAMS,
		     "'%s' should be a positive number or 'any', not '%.*s'",
		     name,
		     tok->end - tok->start,
		     buffer + tok->start);
	return false;
}

bool json_tok_percent(struct command *cmd, const char *name,
		      const char *buffer, const jsmntok_t *tok,
		      double **num)
{
	*num = tal(cmd, double);
	if (json_to_double(buffer, tok, *num) && **num >= 0.0)
		return true;

	command_fail(cmd, JSONRPC2_INVALID_PARAMS,
		     "'%s' should be a positive double, not '%.*s'",
		     name, tok->end - tok->start, buffer + tok->start);
	return false;
}

bool json_tok_u64(struct command *cmd, const char *name,
		  const char *buffer, const jsmntok_t *tok,
		  uint64_t **num)
{
	*num = tal(cmd, uint64_t);
	if (json_to_u64(buffer, tok, *num))
		return true;

	command_fail(cmd, JSONRPC2_INVALID_PARAMS,
		     "'%s' should be an unsigned 64 bit integer, not '%.*s'",
		     name, tok->end - tok->start, buffer + tok->start);
	return false;
}

bool json_to_pubkey(const char *buffer, const jsmntok_t *tok,
		    struct pubkey *pubkey)
{
	return pubkey_from_hexstr(buffer + tok->start,
				  tok->end - tok->start, pubkey);
}

bool json_tok_pubkey(struct command *cmd, const char *name,
		     const char *buffer, const jsmntok_t *tok,
		     struct pubkey **pubkey)
{
	*pubkey = tal(cmd, struct pubkey);
	if (json_to_pubkey(buffer, tok, *pubkey))
		return true;

	command_fail(cmd, JSONRPC2_INVALID_PARAMS,
		     "'%s' should be a pubkey, not '%.*s'",
		     name, tok->end - tok->start, buffer + tok->start);
	return false;
}

void json_add_short_channel_id(struct json_stream *response,
			       const char *fieldname,
			       const struct short_channel_id *id)
{
	json_add_string(response, fieldname,
			type_to_string(response, struct short_channel_id, id));
}

bool json_to_short_channel_id(const char *buffer, const jsmntok_t *tok,
			      struct short_channel_id *scid)
{
	return (short_channel_id_from_str(buffer + tok->start,
					  tok->end - tok->start, scid));
}

bool json_tok_short_channel_id(struct command *cmd, const char *name,
			       const char *buffer, const jsmntok_t *tok,
			       struct short_channel_id **scid)
{
	*scid = tal(cmd, struct short_channel_id);
	if (json_to_short_channel_id(buffer, tok, *scid))
		return true;

	command_fail(cmd, JSONRPC2_INVALID_PARAMS,
		     "'%s' should be a short channel id, not '%.*s'",
		     name, tok->end - tok->start, buffer + tok->start);
	return false;
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

bool json_tok_feerate_style(struct command *cmd, const char *name,
			    const char *buffer, const jsmntok_t *tok,
			    enum feerate_style **style)
{
	*style = tal(cmd, enum feerate_style);
	if (json_tok_streq(buffer, tok,
			   json_feerate_style_name(FEERATE_PER_KSIPA))) {
		**style = FEERATE_PER_KSIPA;
		return true;
	} else if (json_tok_streq(buffer, tok,
				  json_feerate_style_name(FEERATE_PER_KBYTE))) {
		**style = FEERATE_PER_KBYTE;
		return true;
	}

	command_fail(cmd, JSONRPC2_INVALID_PARAMS,
		     "'%s' should be '%s' or '%s', not '%.*s'",
		     name,
		     json_feerate_style_name(FEERATE_PER_KSIPA),
		     json_feerate_style_name(FEERATE_PER_KBYTE),
		     tok->end - tok->start, buffer + tok->start);
	return false;
}

bool json_tok_feerate(struct command *cmd, const char *name,
		      const char *buffer, const jsmntok_t *tok,
		      u32 **feerate)
{
	jsmntok_t base = *tok, suffix = *tok;
	enum feerate_style style;
	unsigned int num;

	for (size_t i = 0; i < NUM_FEERATES; i++) {
		if (json_tok_streq(buffer, tok, feerate_name(i)))
			return json_feerate_estimate(cmd, feerate, i);
	}

	/* We have to split the number and suffix. */
	suffix.start = suffix.end;
	while (suffix.start > base.start && !isdigit(buffer[suffix.start-1])) {
		suffix.start--;
		base.end--;
	}

	if (!json_to_number(buffer, &base, &num)) {
		command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			     "'%s' prefix should be an integer, not '%.*s'",
			     name, base.end - base.start, buffer + base.start);
		return false;
	}

	if (json_tok_streq(buffer, &suffix, "")
	    || json_tok_streq(buffer, &suffix,
			      json_feerate_style_name(FEERATE_PER_KBYTE))) {
		style = FEERATE_PER_KBYTE;
	} else if (json_tok_streq(buffer, &suffix,
				json_feerate_style_name(FEERATE_PER_KSIPA))) {
		style = FEERATE_PER_KSIPA;
	} else {
		command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			     "'%s' suffix should be '%s' or '%s', not '%.*s'",
			     name,
			     json_feerate_style_name(FEERATE_PER_KSIPA),
			     json_feerate_style_name(FEERATE_PER_KBYTE),
			     suffix.end - suffix.start, buffer + suffix.start);
		return false;
	}

	*feerate = tal(cmd, u32);
	**feerate = feerate_from_style(num, style);
	return true;
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

bool json_tok_tok(struct command *cmd, const char *name,
		  const char *buffer, const jsmntok_t * tok,
		  const jsmntok_t **out)
{
	return (*out = tok);
}

struct json_stream {
#if DEVELOPER
	/* tal_arr of types (JSMN_OBJECT/JSMN_ARRAY) we're enclosed in. */
	jsmntype_t *wrapping;
#endif
	/* How far to indent. */
	size_t indent;

	/* True if we haven't yet put an element in current wrapping */
	bool empty;

	/* The command we're attached to */
	struct command *cmd;
};

static void result_append(struct json_stream *res, const char *str)
{
	struct json_connection *jcon = res->cmd->jcon;

	/* Don't do anything if they're disconnected. */
	if (!jcon)
		return;

	jcon_append(jcon, str);
}

static void PRINTF_FMT(2,3)
result_append_fmt(struct json_stream *res, const char *fmt, ...)
{
	struct json_connection *jcon = res->cmd->jcon;
	va_list ap;

	/* Don't do anything if they're disconnected. */
	if (!jcon)
		return;

	va_start(ap, fmt);
	jcon_append_vfmt(jcon, fmt, ap);
	va_end(ap);
}

static void check_fieldname(const struct json_stream *result,
			    const char *fieldname)
{
#if DEVELOPER
	size_t n = tal_count(result->wrapping);
	if (n == 0)
		/* Can't have a fieldname if not in anything! */
		assert(!fieldname);
	else if (result->wrapping[n-1] == JSMN_ARRAY)
		/* No fieldnames in arrays. */
		assert(!fieldname);
	else
		/* Must have fieldnames in objects. */
		assert(fieldname);
#endif
}

static void result_append_indent(struct json_stream *result)
{
	static const char indent_buf[] = "                                ";
	size_t len;

	for (size_t i = 0; i < result->indent * 2; i += len) {
		len = result->indent * 2;
		if (len > sizeof(indent_buf)-1)
			len = sizeof(indent_buf)-1;
		/* Use tail of indent_buf string. */
		result_append(result, indent_buf + sizeof(indent_buf) - 1 - len);
	}
}

static void json_start_member(struct json_stream *result, const char *fieldname)
{
	/* Prepend comma if required. */
	if (!result->empty)
		result_append(result, ", \n");
	else
		result_append(result, "\n");

	result_append_indent(result);

	check_fieldname(result, fieldname);
	if (fieldname)
		result_append_fmt(result, "\"%s\": ", fieldname);
	result->empty = false;
}

static void result_indent(struct json_stream *result, jsmntype_t type)
{
#if DEVELOPER
	*tal_arr_expand(&result->wrapping) = type;
#endif
	result->empty = true;
	result->indent++;
}

static void result_unindent(struct json_stream *result, jsmntype_t type)
{
	assert(result->indent);
#if DEVELOPER
	assert(tal_count(result->wrapping) == result->indent);
	assert(result->wrapping[result->indent-1] == type);
	tal_resize(&result->wrapping, result->indent-1);
#endif
	result->empty = false;
	result->indent--;
}

void json_array_start(struct json_stream *result, const char *fieldname)
{
	json_start_member(result, fieldname);
	result_append(result, "[");
	result_indent(result, JSMN_ARRAY);
}

void json_array_end(struct json_stream *result)
{
	result_append(result, "\n");
	result_unindent(result, JSMN_ARRAY);
	result_append_indent(result);
	result_append(result, "]");
}

void json_object_start(struct json_stream *result, const char *fieldname)
{
	json_start_member(result, fieldname);
	result_append(result, "{");
	result_indent(result, JSMN_OBJECT);
}

void json_object_end(struct json_stream *result)
{
	result_append(result, "\n");
	result_unindent(result, JSMN_OBJECT);
	result_append_indent(result);
	result_append(result, "}");
}

void json_add_num(struct json_stream *result, const char *fieldname, unsigned int value)
{
	json_start_member(result, fieldname);
	result_append_fmt(result, "%u", value);
}

void json_add_double(struct json_stream *result, const char *fieldname, double value)
{
	json_start_member(result, fieldname);
	result_append_fmt(result, "%f", value);
}

void json_add_u64(struct json_stream *result, const char *fieldname,
		  uint64_t value)
{
	json_start_member(result, fieldname);
	result_append_fmt(result, "%"PRIu64, value);
}

void json_add_literal(struct json_stream *result, const char *fieldname,
		      const char *literal, int len)
{
	json_start_member(result, fieldname);
	result_append_fmt(result, "%.*s", len, literal);
}

void json_add_string(struct json_stream *result, const char *fieldname, const char *value)
{
	struct json_escaped *esc = json_partial_escape(NULL, value);

	json_start_member(result, fieldname);
	result_append_fmt(result, "\"%s\"", esc->s);
	tal_free(esc);
}

void json_add_bool(struct json_stream *result, const char *fieldname, bool value)
{
	json_start_member(result, fieldname);
	result_append(result, value ? "true" : "false");
}

void json_add_hex(struct json_stream *result, const char *fieldname,
		  const void *data, size_t len)
{
	char *hex = tal_arr(NULL, char, hex_str_size(len));

	hex_encode(data, len, hex, hex_str_size(len));
	json_add_string(result, fieldname, hex);
	tal_free(hex);
}

void json_add_hex_talarr(struct json_stream *result,
			 const char *fieldname,
			 const tal_t *data)
{
	json_add_hex(result, fieldname, data, tal_bytelen(data));
}

void json_add_object(struct json_stream *result, ...)
{
	va_list ap;
	const char *field;

	va_start(ap, result);
	json_object_start(result, NULL);
	while ((field = va_arg(ap, const char *)) != NULL) {
		jsmntype_t type = va_arg(ap, jsmntype_t);
		const char *value = va_arg(ap, const char *);
		if (type == JSMN_STRING)
			json_add_string(result, field, value);
		else
			json_add_literal(result, field, value, strlen(value));
	}
	json_object_end(result);
	va_end(ap);
}

void json_add_escaped_string(struct json_stream *result, const char *fieldname,
			     const struct json_escaped *esc TAKES)
{
	json_start_member(result, fieldname);
	result_append_fmt(result, "\"%s\"", esc->s);
	if (taken(esc))
		tal_free(esc);
}

static struct json_stream *new_json_stream(struct command *cmd)
{
	struct json_stream *r = tal(cmd, struct json_stream);

	r->cmd = cmd;
#if DEVELOPER
	r->wrapping = tal_arr(r, jsmntype_t, 0);
#endif
	r->indent = 0;
	r->empty = true;

	assert(!cmd->have_json_stream);
	cmd->have_json_stream = true;
	return r;
}

struct json_stream *json_stream_success(struct command *cmd)
{
	struct json_stream *r;
	r = new_json_stream(cmd);
	result_append(r, "\"result\" : ");
	return r;
}

struct json_stream *json_stream_fail_nodata(struct command *cmd,
					    int code,
					    const char *errmsg)
{
	struct json_stream *r = new_json_stream(cmd);

	assert(code);
	assert(errmsg);

	result_append_fmt(r, " \"error\" : "
			  "{ \"code\" : %d,"
			  " \"message\" : \"%s\"", code, errmsg);
	return r;
}

struct json_stream *json_stream_fail(struct command *cmd,
				     int code,
				     const char *errmsg)
{
	struct json_stream *r = json_stream_fail_nodata(cmd, code, errmsg);

	result_append(r, ", \"data\" : ");
	return r;
}
