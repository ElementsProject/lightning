#include "config.h"
#include <arpa/inet.h>
#include <bitcoin/psbt.h>
#include <ccan/ccan/str/hex/hex.h>
#include <common/json_helpers.h>
#include <common/json_stream.h>
#include <common/type_to_string.h>
#include <common/wireaddr.h>
#include <errno.h>
#include <wire/onion_wire.h>
#include <wire/peer_wire.h>

bool json_to_bitcoin_amount(const char *buffer, const jsmntok_t *tok,
			    uint64_t *satoshi)
{
	char *end;
	unsigned long btc, sat;

	btc = strtoul(buffer + tok->start, &end, 10);
	if (btc == ULONG_MAX && errno == ERANGE)
		return false;
	if (end != buffer + tok->end) {
		/* Expect always 8 decimal places. */
		if (*end != '.' || buffer + tok->end - end != 9)
			return false;
		sat = strtoul(end+1, &end, 10);
		if (sat == ULONG_MAX && errno == ERANGE)
			return false;
		if (end != buffer + tok->end)
			return false;
	} else
		sat = 0;

	*satoshi = btc * (uint64_t)100000000 + sat;
	if (*satoshi != btc * (uint64_t)100000000 + sat)
		return false;

	return true;
}

bool json_to_node_id(const char *buffer, const jsmntok_t *tok,
		     struct node_id *id)
{
	return node_id_from_hexstr(buffer + tok->start,
				   tok->end - tok->start, id);
}

bool json_to_pubkey(const char *buffer, const jsmntok_t *tok,
		    struct pubkey *pubkey)
{
	return pubkey_from_hexstr(buffer + tok->start,
				  tok->end - tok->start, pubkey);
}

bool json_to_msat(const char *buffer, const jsmntok_t *tok,
		  struct amount_msat *msat)
{
	return parse_amount_msat(msat,
				 buffer + tok->start, tok->end - tok->start);
}

bool json_to_sat(const char *buffer, const jsmntok_t *tok,
		 struct amount_sat *sat)
{
	return parse_amount_sat(sat, buffer + tok->start, tok->end - tok->start);
}

bool json_to_sat_or_all(const char *buffer, const jsmntok_t *tok,
			struct amount_sat *sat)
{
	if (json_tok_streq(buffer, tok, "all")) {
		*sat = AMOUNT_SAT(-1ULL);
		return true;
	}
	return json_to_sat(buffer, tok, sat);
}

bool json_to_short_channel_id(const char *buffer, const jsmntok_t *tok,
			      struct short_channel_id *scid)
{
	return (short_channel_id_from_str(buffer + tok->start,
					  tok->end - tok->start, scid));
}

bool json_to_txid(const char *buffer, const jsmntok_t *tok,
		  struct bitcoin_txid *txid)
{
	return bitcoin_txid_from_hex(buffer + tok->start,
				     tok->end - tok->start, txid);
}

bool json_to_outpoint(const char *buffer, const jsmntok_t *tok,
		      struct bitcoin_outpoint *op)
{
	jsmntok_t t1, t2;

	if (!split_tok(buffer, tok, ':', &t1, &t2))
		return false;

	return json_to_txid(buffer, &t1, &op->txid)
		&& json_to_u32(buffer, &t2, &op->n);
}

bool json_to_channel_id(const char *buffer, const jsmntok_t *tok,
			struct channel_id *cid)
{
	return hex_decode(buffer + tok->start, tok->end - tok->start,
			  cid, sizeof(*cid));
}

bool split_tok(const char *buffer, const jsmntok_t *tok,
				char split,
				jsmntok_t *a,
				jsmntok_t *b)
{
	const char *p = memchr(buffer + tok->start, split, tok->end - tok->start);
	if (!p)
		return false;

	*a = *b = *tok;
	a->end = p - buffer;
	b->start = p + 1 - buffer;

	return true;
}

bool json_to_secret(const char *buffer, const jsmntok_t *tok, struct secret *dest)
{
	return hex_decode(buffer + tok->start, tok->end - tok->start,
			  dest->data, sizeof(struct secret));
}

bool json_to_preimage(const char *buffer, const jsmntok_t *tok, struct preimage *preimage)
{
	size_t hexlen = tok->end - tok->start;
	return hex_decode(buffer + tok->start, hexlen, preimage->r, sizeof(preimage->r));
}

struct wally_psbt *json_to_psbt(const tal_t *ctx, const char *buffer,
				const jsmntok_t *tok)
{
	return psbt_from_b64(ctx, buffer + tok->start, tok->end - tok->start);
}

struct tlv_obs2_onionmsg_payload_reply_path *
json_to_obs2_reply_path(const tal_t *ctx, const char *buffer, const jsmntok_t *tok)
{
	struct tlv_obs2_onionmsg_payload_reply_path *rpath;
	const jsmntok_t *hops, *t;
	size_t i;
	const char *err;

	rpath = tal(ctx, struct tlv_obs2_onionmsg_payload_reply_path);
	err = json_scan(tmpctx, buffer, tok, "{blinding:%,first_node_id:%}",
			JSON_SCAN(json_to_pubkey, &rpath->blinding),
			JSON_SCAN(json_to_pubkey, &rpath->first_node_id),
			NULL);
	if (err)
		return tal_free(rpath);

	hops = json_get_member(buffer, tok, "hops");
	if (!hops || hops->size < 1)
		return tal_free(rpath);

	rpath->path = tal_arr(rpath, struct onionmsg_path *, hops->size);
	json_for_each_arr(i, t, hops) {
		rpath->path[i] = tal(rpath->path, struct onionmsg_path);
		err = json_scan(tmpctx, buffer, t, "{id:%,encrypted_recipient_data:%}",
				JSON_SCAN(json_to_pubkey,
					  &rpath->path[i]->node_id),
				JSON_SCAN_TAL(rpath->path[i],
					      json_tok_bin_from_hex,
					      &rpath->path[i]->encrypted_recipient_data));
		if (err)
			return tal_free(rpath);
	}

	return rpath;
}

struct tlv_onionmsg_payload_reply_path *
json_to_reply_path(const tal_t *ctx, const char *buffer, const jsmntok_t *tok)
{
	struct tlv_onionmsg_payload_reply_path *rpath;
	const jsmntok_t *hops, *t;
	size_t i;
	const char *err;

	rpath = tal(ctx, struct tlv_onionmsg_payload_reply_path);
	err = json_scan(tmpctx, buffer, tok, "{blinding:%,first_node_id:%}",
			JSON_SCAN(json_to_pubkey, &rpath->blinding),
			JSON_SCAN(json_to_pubkey, &rpath->first_node_id),
			NULL);
	if (err)
		return tal_free(rpath);

	hops = json_get_member(buffer, tok, "hops");
	if (!hops || hops->size < 1)
		return tal_free(rpath);

	rpath->path = tal_arr(rpath, struct onionmsg_path *, hops->size);
	json_for_each_arr(i, t, hops) {
		rpath->path[i] = tal(rpath->path, struct onionmsg_path);
		err = json_scan(tmpctx, buffer, t, "{id:%,encrypted_recipient_data:%}",
				JSON_SCAN(json_to_pubkey,
					  &rpath->path[i]->node_id),
				JSON_SCAN_TAL(rpath->path[i],
					      json_tok_bin_from_hex,
					      &rpath->path[i]->encrypted_recipient_data));
		if (err)
			return tal_free(rpath);
	}

	return rpath;
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

void json_add_point32(struct json_stream *response,
		      const char *fieldname,
		      const struct point32 *key)
{
	u8 output[32];

	secp256k1_xonly_pubkey_serialize(secp256k1_ctx, output, &key->pubkey);
	json_add_hex(response, fieldname, output, sizeof(output));
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
	json_add_member(result, fieldname, true, "%s:%d", hex, out->n);
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
	if (addr->type == ADDR_TYPE_IPV4) {
		char addrstr[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, addr->addr, addrstr, INET_ADDRSTRLEN);
		json_add_string(response, "type", "ipv4");
		json_add_string(response, "address", addrstr);
		json_add_num(response, "port", addr->port);
	} else if (addr->type == ADDR_TYPE_IPV6) {
		char addrstr[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, addr->addr, addrstr, INET6_ADDRSTRLEN);
		json_add_string(response, "type", "ipv6");
		json_add_string(response, "address", addrstr);
		json_add_num(response, "port", addr->port);
	} else if (addr->type == ADDR_TYPE_TOR_V2_REMOVED) {
		json_add_string(response, "type", "torv2");
		json_add_string(response, "address", fmt_wireaddr_without_port(tmpctx, addr));
		json_add_num(response, "port", addr->port);
	} else if (addr->type == ADDR_TYPE_TOR_V3) {
		json_add_string(response, "type", "torv3");
		json_add_string(response, "address", fmt_wireaddr_without_port(tmpctx, addr));
		json_add_num(response, "port", addr->port);
	} else if (addr->type == ADDR_TYPE_DNS) {
		json_add_string(response, "type", "dns");
		json_add_string(response, "address", fmt_wireaddr_without_port(tmpctx, addr));
		json_add_num(response, "port", addr->port);
	} else if (addr->type == ADDR_TYPE_WEBSOCKET) {
		json_add_string(response, "type", "websocket");
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
	psbt_b64 = psbt_to_b64(NULL, psbt);
	json_add_string(stream, fieldname, take(psbt_b64));
	if (taken(psbt))
		tal_free(psbt);
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
	json_add_amount_sat_only(result, "lease_fee_base_msat",
				 amount_sat(rates->lease_fee_base_sat));
	json_add_num(result, "lease_fee_basis", rates->lease_fee_basis);
	json_add_num(result, "funding_weight", rates->funding_weight);
	json_add_amount_msat_only(result,
				  "channel_fee_max_base_msat",
				  amount_msat(rates->channel_fee_max_base_msat));
	json_add_num(result, "channel_fee_max_proportional_thousandths",
		     rates->channel_fee_max_proportional_thousandths);
}
