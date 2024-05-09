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
	struct pubkey first_node_id;
	struct short_channel_id_dir first_scidd;

	rpath = tal(ctx, struct blinded_path);

	/* It will give us either scid or node_id */
	memset(&first_scidd, 0, sizeof(first_scidd));
	err = json_scan(tmpctx, buffer, tok,
			"{blinding:%,"
			"first_node_id?:%,"
			"first_scid?:%,"
			"first_scid_dir?:%}",
			JSON_SCAN(json_to_pubkey, &rpath->blinding),
			JSON_SCAN(json_to_pubkey, &first_node_id),
			JSON_SCAN(json_to_short_channel_id, &first_scidd.scid),
			JSON_SCAN(json_to_int, &first_scidd.dir),
			NULL);
	if (err)
		return tal_free(rpath);

	if (first_scidd.scid.u64 != 0)
		sciddir_or_pubkey_from_scidd(&rpath->first_node_id, &first_scidd);
	else
		sciddir_or_pubkey_from_pubkey(&rpath->first_node_id, &first_node_id);

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

