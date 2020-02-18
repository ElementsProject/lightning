/* JSON core and helpers */
#include <arpa/inet.h>
#include <assert.h>
#include <bitcoin/preimage.h>
#include <bitcoin/privkey.h>
#include <bitcoin/pubkey.h>
#include <ccan/build_assert/build_assert.h>
#include <ccan/mem/mem.h>
#include <ccan/str/hex/hex.h>
#include <ccan/tal/str/str.h>
#include <ccan/time/time.h>
#include <common/amount.h>
#include <common/json.h>
#include <common/json_stream.h>
#include <common/node_id.h>
#include <common/utils.h>
#include <common/wireaddr.h>
#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

const char *json_tok_full(const char *buffer, const jsmntok_t *t)
{
	if (t->type == JSMN_STRING)
		return buffer + t->start - 1;
	return buffer + t->start;
}

/* Include " if it's a string. */
int json_tok_full_len(const jsmntok_t *t)
{
	if (t->type == JSMN_STRING)
		return t->end - t->start + 2;
	return t->end - t->start;
}

bool json_tok_streq(const char *buffer, const jsmntok_t *tok, const char *str)
{
	if (tok->type != JSMN_STRING)
		return false;
	if (tok->end - tok->start != strlen(str))
		return false;
	return strncmp(buffer + tok->start, str, tok->end - tok->start) == 0;
}

char *json_strdup(const tal_t *ctx, const char *buffer, const jsmntok_t *tok)
{
	return tal_strndup(ctx, buffer + tok->start, tok->end - tok->start);
}

bool json_to_u64(const char *buffer, const jsmntok_t *tok,
		  uint64_t *num)
{
	char *end;
	unsigned long long l;

	l = strtoull(buffer + tok->start, &end, 0);
	if (end != buffer + tok->end)
		return false;

	BUILD_ASSERT(sizeof(l) >= sizeof(*num));
	*num = l;

	/* Check for overflow */
	if (l == ULLONG_MAX && errno == ERANGE)
		return false;

	if (*num != l)
		return false;

	return true;
}

bool json_to_s64(const char *buffer, const jsmntok_t *tok, s64 *num)
{
	char *end;
	long long l;

	l = strtoll(buffer + tok->start, &end, 0);
	if (end != buffer + tok->end)
		return false;

	BUILD_ASSERT(sizeof(l) >= sizeof(*num));
	*num = l;

	/* Check for overflow/underflow */
	if ((l == LONG_MAX || l == LONG_MIN) && errno == ERANGE)
		return false;

	/* Check if the number did not fit in `s64` (in case `long long`
	is a bigger type). */
	if (*num != l)
		return false;

	return true;
}

bool json_to_double(const char *buffer, const jsmntok_t *tok, double *num)
{
	char *end;

	*num = strtod(buffer + tok->start, &end);
	if (end != buffer + tok->end)
		return false;
	return true;
}

bool json_to_number(const char *buffer, const jsmntok_t *tok,
		    unsigned int *num)
{
	uint64_t u64;

	if (!json_to_u64(buffer, tok, &u64))
		return false;
	*num = u64;

	/* Just in case it doesn't fit. */
	if (*num != u64)
		return false;
	return true;
}

bool json_to_u16(const char *buffer, const jsmntok_t *tok,
		 short unsigned int *num)
{
	uint64_t u64;

	if (!json_to_u64(buffer, tok, &u64))
		return false;
	*num = u64;

	/* Just in case it doesn't fit. */
	if (*num != u64)
		return false;
	return true;
}

bool json_to_u32(const char *buffer, const jsmntok_t *tok,
		 uint32_t *num)
{
	uint64_t u64;

	if (!json_to_u64(buffer, tok, &u64))
		return false;
	*num = u64;

	/* Just in case it doesn't fit. */
	if (*num != u64)
		return false;
	return true;
}

bool json_to_int(const char *buffer, const jsmntok_t *tok, int *num)
{
	s64 tmp;

	if (!json_to_s64(buffer, tok, &tmp))
		return false;
	*num = tmp;

	/* Just in case it doesn't fit. */
	if (*num != tmp)
		return false;

	return true;
}

bool json_to_errcode(const char *buffer, const jsmntok_t *tok, errcode_t *errcode)
{
	s64 tmp;

	if (!json_to_s64(buffer, tok, &tmp))
		return false;
	*errcode = tmp;

	/* Just in case it doesn't fit. */
	if (*errcode != tmp)
		return false;

	return true;
}

bool json_to_bool(const char *buffer, const jsmntok_t *tok, bool *b)
{
	if (tok->type != JSMN_PRIMITIVE)
		return false;
	if (memeqstr(buffer + tok->start, tok->end - tok->start, "true")) {
		*b = true;
		return true;
	}
	if (memeqstr(buffer + tok->start, tok->end - tok->start, "false")) {
		*b = false;
		return true;
	}
	return false;
}

bool json_to_secret(const char *buffer, const jsmntok_t *tok, struct secret *dest)
{
	return hex_decode(buffer + tok->start, tok->end - tok->start,
			  dest->data, sizeof(struct secret));
}

u8 *json_tok_bin_from_hex(const tal_t *ctx, const char *buffer, const jsmntok_t *tok)
{
	u8 *result;
	size_t hexlen, rawlen;
	hexlen = tok->end - tok->start;
	rawlen = hex_data_size(hexlen);

	result = tal_arr(ctx, u8, rawlen);
	if (!hex_decode(buffer + tok->start, hexlen, result, rawlen))
		return tal_free(result);

	return result;
}

bool json_to_preimage(const char *buffer, const jsmntok_t *tok, struct preimage *preimage)
{
	size_t hexlen = tok->end - tok->start;
	return hex_decode(buffer + tok->start, hexlen, preimage->r, sizeof(preimage->r));
}

bool json_tok_is_num(const char *buffer, const jsmntok_t *tok)
{
	if (tok->type != JSMN_PRIMITIVE)
		return false;

	for (int i = tok->start; i < tok->end; i++)
		if (!cisdigit(buffer[i]))
			return false;
	return true;
}

bool json_tok_is_null(const char *buffer, const jsmntok_t *tok)
{
	if (tok->type != JSMN_PRIMITIVE)
		return false;
	return buffer[tok->start] == 'n';
}

const jsmntok_t *json_next(const jsmntok_t *tok)
{
	const jsmntok_t *t;
	size_t i;

	for (t = tok + 1, i = 0; i < tok->size; i++)
		t = json_next(t);

	return t;
}

const jsmntok_t *json_get_member(const char *buffer, const jsmntok_t tok[],
				 const char *label)
{
	const jsmntok_t *t;
	size_t i;

	if (tok->type != JSMN_OBJECT)
		return NULL;

	json_for_each_obj(i, t, tok)
		if (json_tok_streq(buffer, t, label))
			return t + 1;

	return NULL;
}

const jsmntok_t *json_get_arr(const jsmntok_t tok[], size_t index)
{
	const jsmntok_t *t;
	size_t i;

	if (tok->type != JSMN_ARRAY)
		return NULL;

	json_for_each_arr(i, t, tok) {
		if (index == 0)
			return t;
		index--;
	}

	return NULL;
}

jsmntok_t *json_parse_input(const tal_t *ctx,
			    const char *input, int len, bool *valid)
{
	jsmn_parser parser;
	jsmntok_t *toks;
	int ret;

	toks = tal_arr(ctx, jsmntok_t, 10);
	toks[0].type = JSMN_UNDEFINED;

	jsmn_init(&parser);
again:
	ret = jsmn_parse(&parser, input, len, toks, tal_count(toks) - 1);

	switch (ret) {
	case JSMN_ERROR_INVAL:
		*valid = false;
		return tal_free(toks);
	case JSMN_ERROR_NOMEM:
		tal_resize(&toks, tal_count(toks) * 2);
		goto again;
	}

	/* Check whether we read at least one full root element, i.e., root
	 * element has its end set. */
	if (toks[0].type == JSMN_UNDEFINED || toks[0].end == -1) {
		*valid = true;
		return tal_free(toks);
	}

	/* If we read a partial element at the end of the stream we'll get a
	 * ret=JSMN_ERROR_PART, but due to the previous check we know we read at
	 * least one full element, so count tokens that are part of this root
	 * element. */
	ret = json_next(toks) - toks;

	/* Cut to length and return. */
	*valid = true;
	tal_resize(&toks, ret + 1);
	/* Make sure last one is always referenceable. */
	toks[ret].type = -1;
	toks[ret].start = toks[ret].end = toks[ret].size = 0;

	return toks;
}

const char *jsmntype_to_string(jsmntype_t t)
{
	switch (t) {
		case JSMN_UNDEFINED :
			return "UNDEFINED";
		case JSMN_OBJECT :
			return "OBJECT";
		case JSMN_ARRAY :
			return "ARRAY";
		case JSMN_STRING :
			return "STRING";
		case JSMN_PRIMITIVE :
			return "PRIMITIVE";
	}
	return "INVALID";
}

void json_tok_print(const char *buffer, const jsmntok_t *tok)
{
	const jsmntok_t *first = tok;
	const jsmntok_t *last = json_next(tok);
	printf("size: %d, count: %td\n", tok->size, last - first);
	while (first != last) {
		printf("%td. %.*s, %s\n", first - tok,
			first->end - first->start, buffer + first->start,
			jsmntype_to_string(first->type));
		first++;
	}
	printf("\n");
}

jsmntok_t *json_tok_copy(const tal_t *ctx, const jsmntok_t *tok)
{
	return tal_dup_arr(ctx, jsmntok_t, tok, json_next(tok) - tok, 0);
}

void json_tok_remove(jsmntok_t **tokens,
		     jsmntok_t *obj_or_array, const jsmntok_t *tok, size_t num)
{
	const jsmntok_t *src = tok;
	const jsmntok_t *end = json_next(*tokens);
	jsmntok_t *dest = *tokens + (tok - *tokens);
	int remove_count;

	assert(*tokens);
	assert(obj_or_array->type == JSMN_ARRAY
	       || obj_or_array->type == JSMN_OBJECT);
	/* obj_or_array must be inside tokens, and tok must be inside
	 * obj_or_array */
	assert(obj_or_array >= *tokens
	       && obj_or_array < *tokens + tal_count(*tokens));
	assert(tok >= obj_or_array
	       && tok < *tokens + tal_count(*tokens));

	for (int i = 0; i < num; i++)
		src = json_next(src);

	/* Don't give us a num which goes over end of obj_or_array. */
	assert(src <= json_next(obj_or_array));

	remove_count = src - tok;

	memmove(dest, src, sizeof(jsmntok_t) * (end - src));

	/* Subtract first: this ptr may move after tal_resize! */
	obj_or_array->size -= num;
	tal_resize(tokens, tal_count(*tokens) - remove_count);
}

const jsmntok_t *json_delve(const char *buffer,
			    const jsmntok_t *tok,
			    const char *guide)
{
       while (*guide) {
	       const char *key;
	       size_t len = strcspn(guide+1, ".[]");

	       key = tal_strndup(tmpctx, guide+1, len);
	       switch (guide[0]) {
	       case '.':
		       if (tok->type != JSMN_OBJECT)
			       return NULL;
		       tok = json_get_member(buffer, tok, key);
		       if (!tok)
			       return NULL;
		       break;
	       case '[':
		       if (tok->type != JSMN_ARRAY)
			       return NULL;
		       tok = json_get_arr(tok, atol(key));
		       if (!tok)
			       return NULL;
		       /* Must be terminated */
		       assert(guide[1+strlen(key)] == ']');
		       len++;
		       break;
	       default:
		       abort();
	       }
	       guide += len + 1;
       }

       return tok;
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

void json_add_short_channel_id(struct json_stream *response,
			       const char *fieldname,
			       const struct short_channel_id *scid)
{
	json_add_member(response, fieldname, true, "%dx%dx%d",
			short_channel_id_blocknum(scid),
			short_channel_id_txnum(scid),
			short_channel_id_outnum(scid));
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
		json_add_address(response, "service", &addr->u.torservice.address);
		json_object_end(response);
		return;
	case ADDR_INTERNAL_STATICTOR:
		json_object_start(response, fieldname);
		json_add_string(response, "type", "Tor from blob generated static address");
		json_add_address(response, "service", &addr->u.torservice.address);
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

void json_add_preimage(struct json_stream *result, const char *fieldname,
		     const struct preimage *preimage)
{
	json_add_hex(result, fieldname, preimage, sizeof(*preimage));
}

void json_add_tok(struct json_stream *result, const char *fieldname,
                  const jsmntok_t *tok, const char *buffer)
{
	int i = 0;
	const jsmntok_t *t;

	switch (tok->type) {
	case JSMN_PRIMITIVE:
		if (json_tok_is_num(buffer, tok)) {
			json_to_int(buffer, tok, &i);
			json_add_num(result, fieldname, i);
		}
		return;

	case JSMN_STRING:
		if (json_tok_streq(buffer, tok, "true"))
			json_add_bool(result, fieldname, true);
		else if (json_tok_streq(buffer, tok, "false"))
			json_add_bool(result, fieldname, false);
		else
			json_add_string(result, fieldname, json_strdup(tmpctx, buffer, tok));
		return;

	case JSMN_ARRAY:
		json_array_start(result, fieldname);
		json_for_each_arr(i, t, tok)
			json_add_tok(result, NULL, t, buffer);
		json_array_end(result);
		return;

	case JSMN_OBJECT:
		json_object_start(result, fieldname);
		json_for_each_obj(i, t, tok)
			json_add_tok(result, json_strdup(tmpctx, buffer, t), t+1, buffer);
		json_object_end(result);
		return;

	case JSMN_UNDEFINED:
		break;
	}
	abort();
}

void json_add_errcode(struct json_stream *result, const char *fieldname,
		      errcode_t code)
{
	json_add_member(result, fieldname, false, "%"PRIerrcode, code);
}
