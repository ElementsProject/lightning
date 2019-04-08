#include <bitcoin/pubkey.h>
#include <bitcoin/short_channel_id.h>
#include <common/amount.h>
#include <common/json_helpers.h>
#include <common/node_id.h>
#include <errno.h>

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

bool json_to_short_channel_id(const char *buffer, const jsmntok_t *tok,
			      struct short_channel_id *scid,
			      bool may_be_deprecated_form)
{
	return (short_channel_id_from_str(buffer + tok->start,
					  tok->end - tok->start, scid,
					  may_be_deprecated_form));
}
