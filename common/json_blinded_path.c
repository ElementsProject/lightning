#include "config.h"
#include <common/json_blinded_path.h>
#include <common/json_parse.h>
#include <wire/onion_wire.h>

struct blinded_path *
json_to_blinded_path(const tal_t *ctx, const char *buffer, const jsmntok_t *tok)
{
	struct blinded_path *rpath;
	const jsmntok_t *hops, *t;
	size_t i;
	const char *err;

	rpath = tal(ctx, struct blinded_path);
	err = json_scan(tmpctx, buffer, tok, "{blinding:%,first_node_id:%}",
			JSON_SCAN(json_to_pubkey, &rpath->blinding),
			JSON_SCAN(json_to_pubkey, &rpath->first_node_id),
			NULL);
	if (err)
		return tal_free(rpath);

	hops = json_get_member(buffer, tok, "hops");
	if (!hops || hops->size < 1)
		return tal_free(rpath);

	rpath->path = tal_arr(rpath, struct onionmsg_hop *, hops->size);
	json_for_each_arr(i, t, hops) {
		rpath->path[i] = tal(rpath->path, struct onionmsg_hop);
		err = json_scan(tmpctx, buffer, t, "{blinded_node_id:%,encrypted_recipient_data:%}",
				JSON_SCAN(json_to_pubkey,
					  &rpath->path[i]->blinded_node_id),
				JSON_SCAN_TAL(rpath->path[i],
					      json_tok_bin_from_hex,
					      &rpath->path[i]->encrypted_recipient_data));
		if (err)
			return tal_free(rpath);
	}

	return rpath;
}

