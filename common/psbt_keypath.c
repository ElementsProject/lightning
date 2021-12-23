#include "config.h"
#include <bitcoin/tx.h>
#include <common/psbt_keypath.h>
#include <common/utils.h>
#include <wally_bip32.h>
#include <wally_psbt.h>

void psbt_set_keypath(u32 index, const struct ext_key *ext, struct wally_map *map_in) {
	u8 fingerprint[BIP32_KEY_FINGERPRINT_LEN];
	if (bip32_key_get_fingerprint(
		    (struct ext_key *) ext, fingerprint, sizeof(fingerprint)) != WALLY_OK)
		abort();

	u32 path[1];
	path[0] = index;

	if (wally_map_add_keypath_item(map_in,
				       ext->pub_key, sizeof(ext->pub_key),
				       fingerprint, sizeof(fingerprint),
				       path, 1) != WALLY_OK)
		abort();
}

void psbt_add_keypath_to_last_output(struct bitcoin_tx *tx,
				     u32 key_index,
				     const struct ext_key *ext) {
	size_t outndx = tx->psbt->num_outputs - 1;
	struct wally_map *map_in = &tx->psbt->outputs[outndx].keypaths;

	tal_wally_start();
	psbt_set_keypath(key_index, ext, map_in);
	tal_wally_end(tx->psbt);
}
