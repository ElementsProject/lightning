#include "config.h"
#include <common/json_blinded_path.h>
#include <common/json_parse.h>
#include <common/utils.h>
#include <wire/onion_wiregen.h>

struct blinded_path *
json_to_blinded_path(const tal_t *ctx, const char *buffer, const jsmntok_t *tok)
{
	struct blinded_path *rpath;
	const jsmntok_t *hops, *t, *node_id_tok, *scid_tok;
	size_t i;
	const char *err;
	struct pubkey first_node_id;
	struct short_channel_id_dir first_scidd;

	rpath = tal(ctx, struct blinded_path);

	/* It will give us either scid or node_id */
	memset(&first_node_id, 0, sizeof(first_node_id));
	memset(&first_scidd, 0, sizeof(first_scidd));
	err = json_scan(tmpctx, buffer, tok,
			"{first_path_key:%,"
			"first_node_id?:%,"
			"first_scid?:%,"
			"first_scid_dir?:%}",
			JSON_SCAN(json_to_pubkey, &rpath->first_path_key),
			JSON_SCAN(json_to_pubkey, &first_node_id),
			JSON_SCAN(json_to_short_channel_id, &first_scidd.scid),
			JSON_SCAN(json_to_int, &first_scidd.dir),
			NULL);
	if (err)
		return tal_free(rpath);

	/* A zero scid is valid on the wire, so don't use it as a sentinel:
	 * require exactly one of the two forms. */
	node_id_tok = json_get_member(buffer, tok, "first_node_id");
	scid_tok = json_get_member(buffer, tok, "first_scid");
	if (!node_id_tok == !scid_tok)
		return tal_free(rpath);

	if (scid_tok)
		sciddir_or_pubkey_from_scidd(&rpath->first_node_id, &first_scidd);
	else
		sciddir_or_pubkey_from_pubkey(&rpath->first_node_id, &first_node_id);

	hops = json_get_member(buffer, tok, "hops");
	if (!hops || hops->size < 1)
		return tal_free(rpath);

	rpath->path = tal_arr(rpath, struct blinded_path_hop *, hops->size);
	json_for_each_arr(i, t, hops) {
		rpath->path[i] = tal(rpath->path, struct blinded_path_hop);
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

