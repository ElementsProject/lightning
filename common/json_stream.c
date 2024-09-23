#include "config.h"
#include <arpa/inet.h>
#include <bitcoin/preimage.h>
#include <bitcoin/privkey.h>
#include <bitcoin/psbt.h>
#include <bitcoin/signature.h>
#include <bitcoin/tx.h>
#include <ccan/io/io.h>
  /* To reach into io_plan: not a public header! */
  #include <ccan/io/backend.h>
#include <ccan/json_escape/json_escape.h>
#include <ccan/json_out/json_out.h>
#include <ccan/str/hex/hex.h>
#include <ccan/strmap/strmap.h>
#include <ccan/tal/str/str.h>
#include <common/channel_id.h>
#include <common/configdir.h>
#include <common/json_filter.h>
#include <common/json_parse.h>
#include <common/json_stream.h>
#include <common/node_id.h>
#include <common/route.h>
#include <common/wireaddr.h>
#include <inttypes.h>
#include <stdio.h>
#include <wire/peer_wire.h>

static void adjust_io_write(struct json_out *jout,
			    ptrdiff_t delta,
			    struct json_stream *js)
{
	/* If io_write is in progress, we shift it to point to new buffer pos */
	if (js->reader)
	/* FIXME: This, or something prettier (io_replan?) belong in ccan/io! */
		js->reader->plan[IO_OUT].arg.u1.cp += delta;
}

struct json_stream *new_json_stream(const tal_t *ctx,
				    struct command *writer,
				    struct logger *log)
{
	struct json_stream *js = tal(ctx, struct json_stream);

	/* FIXME: Add magic so tal_resize can fail! */
	js->jout = json_out_new(js);
	json_out_call_on_move(js->jout, adjust_io_write, js);
	js->writer = writer;
	js->reader = NULL;
	js->log = log;
	js->filter = NULL;
	return js;
}

void json_stream_attach_filter(struct json_stream *js,
			       struct json_filter *filter STEALS)
{
	assert(!js->filter);
	js->filter = tal_steal(js, filter);
}

const char *json_stream_detach_filter(const tal_t *ctx, struct json_stream *js)
{
	const char *err;
	assert(js->filter);
	/* Should be well-formed at this point! */
	assert(json_filter_finished(js->filter));

	err = json_filter_misused(ctx, js->filter);
	js->filter = tal_free(js->filter);
	return err;
}

struct json_stream *json_stream_dup(const tal_t *ctx,
				    struct json_stream *original,
				    struct logger *log)
{
	struct json_stream *js = tal_dup(ctx, struct json_stream, original);

	js->jout = json_out_dup(js, original->jout);
	js->log = log;
	/* You can't dup things with filters! */
	assert(!js->filter);
	return js;
}

/**
 * json_stream_still_writing - is someone currently writing to this stream?
 * @js: the json_stream.
 *
 * Has this json_stream not been closed yet?
 */
static bool json_stream_still_writing(const struct json_stream *js)
{
	return js->writer != NULL;
}

void json_stream_append(struct json_stream *js,
			const char *str, size_t len)
{
	char *dest;

	/* Only on low-level streams! */
	assert(!js->filter);
	dest = json_out_direct(js->jout, len);
	memcpy(dest, str, len);
}

/* We promise it will end in '\n\n' */
void json_stream_double_cr(struct json_stream *js)
{
	const char *contents;
	size_t len, cr_needed;

	/* Must be well-formed at this point! */
	json_out_finished(js->jout);

	contents = json_out_contents(js->jout, &len);
	/* It's an object (with an id!): definitely can't be less that "{}" */
	assert(len >= 2);
	if (contents[len-1] == '\n') {
		if (contents[len-2] == '\n')
			return;
		cr_needed = 1;
	} else
		cr_needed = 2;

	json_stream_append(js, "\n\n", cr_needed);
}

void json_stream_close(struct json_stream *js, struct command *writer)
{
	/* FIXME: We use writer == NULL for malformed: make writer a void *?
	 * I used to assert(writer); here. */
	assert(js->writer == writer);

	assert(!js->filter);
	json_stream_double_cr(js);
	json_stream_flush(js);
	js->writer = NULL;
}

/* Also called when we're oom, so it will kill reader. */
void json_stream_flush(struct json_stream *js)
{
	/* Wake the stream reader. FIXME:  Could have a flag here to optimize */
	io_wake(js);
}

void json_array_start(struct json_stream *js, const char *fieldname)
{
	if (json_filter_down(&js->filter, fieldname))
		json_out_start(js->jout, fieldname, '[');
}

void json_array_end(struct json_stream *js)
{
	if (json_filter_up(&js->filter))
		json_out_end(js->jout, ']');
}

void json_object_start(struct json_stream *js, const char *fieldname)
{
	if (json_filter_down(&js->filter, fieldname))
		json_out_start(js->jout, fieldname, '{');
}

void json_object_end(struct json_stream *js)
{
	if (json_filter_up(&js->filter))
		json_out_end(js->jout, '}');
}

void json_add_primitive_fmt(struct json_stream *js,
			    const char *fieldname,
			    const char *fmt, ...)
{
	va_list ap;

	if (json_filter_ok(js->filter, fieldname)) {
		va_start(ap, fmt);
		json_out_addv(js->jout, fieldname, false, fmt, ap);
		va_end(ap);
	}
}

void json_add_str_fmt(struct json_stream *js,
		      const char *fieldname,
		      const char *fmt, ...)
{
	va_list ap;

	if (json_filter_ok(js->filter, fieldname)) {
		va_start(ap, fmt);
		json_out_addv(js->jout, fieldname, true, fmt, ap);
		va_end(ap);
	}
}

void json_add_primitive(struct json_stream *js,
			const char *fieldname,
			const char *val TAKES)
{
	json_add_primitive_fmt(js, fieldname, "%s", val);
	if (taken(val))
		tal_free(val);
}

void json_add_string(struct json_stream *js,
		     const char *fieldname,
		     const char *str TAKES)
{
	if (json_filter_ok(js->filter, fieldname))
		json_out_addstr(js->jout, fieldname, str);
	if (taken(str))
		tal_free(str);
}

static char *json_member_direct(struct json_stream *js,
				const char *fieldname, size_t extra)
{
	char *dest;

	dest = json_out_member_direct(js->jout, fieldname, extra);
	return dest;
}

void json_add_jsonstr(struct json_stream *js,
		      const char *fieldname,
		      const char *jsonstr,
		      size_t jsonstrlen)
{
	char *p;

	/* NOTE: Filtering doesn't really work here! */
	if (!json_filter_ok(js->filter, fieldname))
		return;

	p = json_member_direct(js, fieldname, jsonstrlen);
	memcpy(p, jsonstr, jsonstrlen);
}

/* This is where we read the json_stream and write it to conn */
static struct io_plan *json_stream_output_write(struct io_conn *conn,
						struct json_stream *js)
{
	const char *p;

	/* For when we've just done some output */
	json_out_consume(js->jout, js->len_read);

	/* Get how much we can write out from js */
	p = json_out_contents(js->jout, &js->len_read);

	/* Nothing in buffer? */
	if (!p) {
		/* We're not doing io_write now, unset. */
		js->reader = NULL;
		if (!json_stream_still_writing(js))
			return js->reader_cb(conn, js, js->reader_arg);
		return io_out_wait(conn, js, json_stream_output_write, js);
	}

	js->reader = conn;
	return io_write(conn,
			p, js->len_read,
			json_stream_output_write, js);
}

struct io_plan *json_stream_output_(struct json_stream *js,
				    struct io_conn *conn,
				    struct io_plan *(*cb)(struct io_conn *conn,
							  struct json_stream *js,
							  void *arg),
				    void *arg)
{
	assert(!js->reader);

	js->reader_cb = cb;
	js->reader_arg = arg;

	js->len_read = 0;
	return json_stream_output_write(conn, js);
}

void json_add_num(struct json_stream *result, const char *fieldname, unsigned int value)
{
	json_add_primitive_fmt(result, fieldname, "%u", value);
}

void json_add_u64(struct json_stream *result, const char *fieldname,
		  uint64_t value)
{
	json_add_primitive_fmt(result, fieldname, "%"PRIu64, value);
}

void json_add_s64(struct json_stream *result, const char *fieldname,
		  int64_t value)
{
	json_add_primitive_fmt(result, fieldname, "%"PRIi64, value);
}

void json_add_u32(struct json_stream *result, const char *fieldname,
		  uint32_t value)
{
	json_add_primitive_fmt(result, fieldname, "%u", value);
}

void json_add_s32(struct json_stream *result, const char *fieldname,
		  int32_t value)
{
	json_add_primitive_fmt(result, fieldname, "%d", value);
}

void json_add_stringn(struct json_stream *result, const char *fieldname,
		      const char *value TAKES, size_t value_len)
{
	json_add_str_fmt(result, fieldname, "%.*s", (int)value_len, value);
	if (taken(value))
		tal_free(value);
}

void json_add_bool(struct json_stream *result, const char *fieldname, bool value)
{
	json_add_primitive(result, fieldname, value ? "true" : "false");
}

void json_add_null(struct json_stream *stream, const char *fieldname)
{
	json_add_primitive(stream, fieldname, "null");
}

void json_add_hex(struct json_stream *js, const char *fieldname,
		  const void *data, size_t len)
{
	/* Size without NUL term */
	size_t hexlen = hex_str_size(len);
	char str[hexlen];

	if (!hex_encode(data, len, str, hexlen))
		abort();

	json_add_string(js, fieldname, str);
}

void json_add_hex_talarr(struct json_stream *result,
			 const char *fieldname,
			 const tal_t *data)
{
	json_add_hex(result, fieldname, data, tal_bytelen(data));
}

void json_add_escaped_string(struct json_stream *result, const char *fieldname,
			     const struct json_escape *esc TAKES)
{
	if (json_filter_ok(result->filter, fieldname)) {
		/* Already escaped, don't re-escape! */
		char *dest = json_member_direct(result, fieldname,
						1 + strlen(esc->s) + 1);

		dest[0] = '"';
		memcpy(dest + 1, esc->s, strlen(esc->s));
		dest[1+strlen(esc->s)] = '"';
	}
	if (taken(esc))
		tal_free(esc);
}

void json_add_timeabs(struct json_stream *result, const char *fieldname,
		      struct timeabs t)
{
	json_add_primitive_fmt(result, fieldname,
			       "%" PRIu64 ".%09" PRIu64,
			       (u64)t.ts.tv_sec, (u64)t.ts.tv_nsec);
}

void json_add_timestr(struct json_stream *result, const char *fieldname,
			  struct timespec ts)
{
	char timebuf[100];

	snprintf(timebuf, sizeof(timebuf), "%lu.%09u",
		(unsigned long)ts.tv_sec,
		(unsigned)ts.tv_nsec);
	json_add_string(result, fieldname, timebuf);
}

void json_add_timeiso(struct json_stream *result,
		      const char *fieldname,
		      struct timeabs time)
{
	char iso8601_msec_fmt[sizeof("YYYY-mm-ddTHH:MM:SS.%03dZ")];
	char iso8601_s[sizeof("YYYY-mm-ddTHH:MM:SS.nnnZ")];

	strftime(iso8601_msec_fmt, sizeof(iso8601_msec_fmt),
		 "%FT%T.%%03dZ", gmtime(&time.ts.tv_sec));
	snprintf(iso8601_s, sizeof(iso8601_s),
		 iso8601_msec_fmt, (int) time.ts.tv_nsec / 1000000);

	json_add_string(result, fieldname, iso8601_s);
}


void json_add_tok(struct json_stream *result, const char *fieldname,
                  const jsmntok_t *tok, const char *buffer)
{
	char *space;
	assert(tok->type != JSMN_UNDEFINED);

	if (!json_filter_ok(result->filter, fieldname))
		return;

	space = json_member_direct(result, fieldname, json_tok_full_len(tok));
	memcpy(space, json_tok_full(buffer, tok), json_tok_full_len(tok));
}

void json_add_jsonrpc_errcode(struct json_stream *result, const char *fieldname,
			      enum jsonrpc_errcode code)
{
	json_add_primitive_fmt(result, fieldname, "%i", code);
}

void json_add_invstring(struct json_stream *result, const char *invstring)
{
	if (strstarts(invstring, "lni"))
		json_add_string(result, "bolt12", invstring);
	else
		json_add_string(result, "bolt11", invstring);
}

void json_add_node_id(struct json_stream *response,
		      const char *fieldname,
		      const struct node_id *id)
{
	json_add_hex(response, fieldname, id->k, sizeof(id->k));
}

void json_add_channel_id(struct json_stream *response,
			 const char *fieldname,
			 const struct channel_id *cid)
{
	json_add_hex(response, fieldname, cid->id, sizeof(cid->id));
}

void json_add_pubkey(struct json_stream *response,
		     const char *fieldname,
		     const struct pubkey *key)
{
	u8 der[PUBKEY_CMPR_LEN];

	pubkey_to_der(der, key);
	json_add_hex(response, fieldname, der, sizeof(der));
}

void json_add_bip340sig(struct json_stream *response,
			const char *fieldname,
			const struct bip340sig *sig)
{
	json_add_hex(response, fieldname, sig->u8, sizeof(sig->u8));
}

void json_add_txid(struct json_stream *result, const char *fieldname,
		   const struct bitcoin_txid *txid)
{
	char hex[hex_str_size(sizeof(*txid))];

	bitcoin_txid_to_hex(txid, hex, sizeof(hex));
	json_add_string(result, fieldname, hex);
}

void json_add_outpoint(struct json_stream *result, const char *fieldname,
		       const struct bitcoin_outpoint *out)
{
	char hex[hex_str_size(sizeof(out->txid))];
	bitcoin_txid_to_hex(&out->txid, hex, sizeof(hex));
	json_add_str_fmt(result, fieldname, "%s:%d", hex, out->n);
}

void json_add_short_channel_id(struct json_stream *response,
			       const char *fieldname,
			       struct short_channel_id scid)
{
	json_add_str_fmt(response, fieldname, "%dx%dx%d",
			 short_channel_id_blocknum(scid),
			 short_channel_id_txnum(scid),
			 short_channel_id_outnum(scid));
}

void json_add_short_channel_id_dir(struct json_stream *response,
			       const char *fieldname,
			       struct short_channel_id_dir scidd)
{
	json_add_str_fmt(response, fieldname, "%dx%dx%d/%d",
			 short_channel_id_blocknum(scidd.scid),
			 short_channel_id_txnum(scidd.scid),
			 short_channel_id_outnum(scidd.scid), scidd.dir);
}

void json_add_route_exclusion(struct json_stream *response,
			      const char *fieldname,
			      const struct route_exclusion *ex)
{
	if (ex->type == EXCLUDE_NODE)
		json_add_node_id(response, fieldname, &ex->u.node_id);
	else
		json_add_short_channel_id_dir(response, fieldname,
					      ex->u.chan_id);
}

static void json_add_address_fields(struct json_stream *response,
				    const struct wireaddr *addr,
				    const char *typefield)
{
	switch (addr->type) {
	case ADDR_TYPE_IPV4: {
		char addrstr[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, addr->addr, addrstr, INET_ADDRSTRLEN);
		json_add_string(response, typefield, "ipv4");
		json_add_string(response, "address", addrstr);
		json_add_num(response, "port", addr->port);
		return;
	}
	case ADDR_TYPE_IPV6: {
		char addrstr[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, addr->addr, addrstr, INET6_ADDRSTRLEN);
		json_add_string(response, typefield, "ipv6");
		json_add_string(response, "address", addrstr);
		json_add_num(response, "port", addr->port);
		return;
	}
	case ADDR_TYPE_TOR_V2_REMOVED: {
		json_add_string(response, typefield, "torv2");
		json_add_string(response, "address", fmt_wireaddr_without_port(tmpctx, addr));
		json_add_num(response, "port", addr->port);
		return;
	}
	case ADDR_TYPE_TOR_V3: {
		json_add_string(response, typefield, "torv3");
		json_add_string(response, "address", fmt_wireaddr_without_port(tmpctx, addr));
		json_add_num(response, "port", addr->port);
		return;
	}
	case ADDR_TYPE_DNS: {
		json_add_string(response, typefield, "dns");
		json_add_string(response, "address", fmt_wireaddr_without_port(tmpctx, addr));
		json_add_num(response, "port", addr->port);
		return;
	}
	}
	abort();
}

void json_add_address(struct json_stream *response, const char *fieldname,
		      const struct wireaddr *addr)
{
	json_object_start(response, fieldname);
	json_add_address_fields(response, addr, "type");
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
		if (addr->u.allproto.is_websocket) {
			json_add_string(response, "type", "websocket");
			json_add_string(response, "subtype", "any protocol");
		} else {
			json_add_string(response, "type", "any protocol");
		}
		json_add_num(response, "port", addr->u.allproto.port);
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
		json_object_start(response, fieldname);
		if (addr->u.wireaddr.is_websocket) {
			json_add_string(response, "type", "websocket");
			json_add_address_fields(response, &addr->u.wireaddr.wireaddr, "subtype");
		} else {
			json_add_address_fields(response, &addr->u.wireaddr.wireaddr, "type");
		}
		json_object_end(response);
		return;
	}
	abort();
}

void json_add_tx(struct json_stream *result,
		 const char *fieldname,
		 const struct bitcoin_tx *tx)
{
	json_add_hex_talarr(result, fieldname, linearize_tx(tmpctx, tx));
}

void json_add_psbt(struct json_stream *stream,
		   const char *fieldname,
		   const struct wally_psbt *psbt TAKES)
{
	const char *psbt_b64;
	psbt_b64 = fmt_wally_psbt(NULL, psbt);
	json_add_string(stream, fieldname, take(psbt_b64));
	if (taken(psbt))
		tal_free(psbt);
}

void json_add_amount_msat(struct json_stream *result,
			  const char *msatfieldname,
			  struct amount_msat msat)
{
	assert(strends(msatfieldname, "_msat") || streq(msatfieldname, "msat"));
	json_add_u64(result, msatfieldname, msat.millisatoshis); /* Raw: low-level helper */
}

void json_add_amount_sat_msat(struct json_stream *result,
			      const char *msatfieldname,
			      struct amount_sat sat)
{
	struct amount_msat msat;
	assert(strends(msatfieldname, "_msat"));
	if (amount_sat_to_msat(&msat, sat))
		json_add_amount_msat(result, msatfieldname, msat);
}

void json_add_sats(struct json_stream *result,
		   const char *fieldname,
		   struct amount_sat sat)
{
	json_add_string(result, fieldname, take(fmt_amount_sat(NULL, sat)));
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

void json_add_lease_rates(struct json_stream *result,
			  const struct lease_rates *rates)
{
	json_add_amount_sat_msat(result, "lease_fee_base_msat",
				 amount_sat(rates->lease_fee_base_sat));
	json_add_num(result, "lease_fee_basis", rates->lease_fee_basis);
	json_add_num(result, "funding_weight", rates->funding_weight);
	json_add_amount_msat(result,
			     "channel_fee_max_base_msat",
			     amount_msat(rates->channel_fee_max_base_msat));
	json_add_num(result, "channel_fee_max_proportional_thousandths",
		     rates->channel_fee_max_proportional_thousandths);
}

void json_add_id(struct json_stream *result, const char *id)
{
	char *p;

	/* Bypass escape-required assertion in json_out_add */
	p = json_member_direct(result, "id", strlen(id));
	memcpy(p, id, strlen(id));
}
