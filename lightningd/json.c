#include "json.h"
#include <arpa/inet.h>
#include <ccan/str/hex/hex.h>
#include <ccan/tal/str/str.h>
#include <common/json.h>
#include <common/type_to_string.h>
#include <common/wireaddr.h>
#include <gossipd/routing.h>
#include <lightningd/options.h>
#include <sys/socket.h>
#include <wallet/wallet.h>
#include <wire/wire.h>

/* Output a route hop */
static void
json_add_route_hop(struct json_result *r, char const *n,
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
json_add_route(struct json_result *r, char const *n,
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
json_add_payment_fields(struct json_result *response,
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

void json_add_pubkey(struct json_result *response,
		     const char *fieldname,
		     const struct pubkey *key)
{
	u8 der[PUBKEY_DER_LEN];

	pubkey_to_der(der, key);
	json_add_hex(response, fieldname, der, sizeof(der));
}

void json_add_txid(struct json_result *result, const char *fieldname,
		   const struct bitcoin_txid *txid)
{
	char hex[hex_str_size(sizeof(*txid))];

	bitcoin_txid_to_hex(txid, hex, sizeof(hex));
	json_add_string(result, fieldname, hex);
}

bool json_tok_pubkey(const char *buffer, const jsmntok_t *tok,
		     struct pubkey *pubkey)
{
	return pubkey_from_hexstr(buffer + tok->start,
				  tok->end - tok->start, pubkey);
}

void json_add_short_channel_id(struct json_result *response,
			       const char *fieldname,
			       const struct short_channel_id *id)
{
	json_add_string(response, fieldname,
			type_to_string(response, struct short_channel_id, id));
}

bool json_tok_short_channel_id(const char *buffer, const jsmntok_t *tok,
			       struct short_channel_id *scid)
{
	return short_channel_id_from_str(buffer + tok->start,
					 tok->end - tok->start,
					 scid);
}

bool
json_tok_channel_id(const char *buffer, const jsmntok_t *tok,
		    struct channel_id *cid)
{
	return hex_decode(buffer + tok->start, tok->end - tok->start,
			  cid, sizeof(*cid));
}

void json_add_address(struct json_result *response, const char *fieldname,
		      const struct wireaddr *addr)
{
	/* No need to print padding */
	if (addr->type == ADDR_TYPE_PADDING)
		return;

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

void json_add_address_internal(struct json_result *response,
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
