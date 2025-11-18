#include "config.h"
#include <bitcoin/tx.h>
#include <common/psbt_keypath.h>
#include <common/utils.h>

bool psbt_output_set_keypath(u32 index,
			     const struct ext_key *ext,
			     bool is_taproot,
			     struct wally_psbt_output *output)
{
	u8 fingerprint[BIP32_KEY_FINGERPRINT_LEN];
	if (bip32_key_get_fingerprint(
		    (struct ext_key *) ext, fingerprint, sizeof(fingerprint)) != WALLY_OK)
		abort();

	u32 path[1];
	path[0] = index;

	if (is_taproot) {
		if (wally_psbt_output_taproot_keypath_add(output,
							  ext->pub_key + 1, sizeof(ext->pub_key) - 1,
							  NULL, 0,
							  fingerprint, sizeof(fingerprint),
							  path, 1) != WALLY_OK)
			return false;
	} else {
		if (wally_psbt_output_keypath_add(output,
						  ext->pub_key, sizeof(ext->pub_key),
						  fingerprint, sizeof(fingerprint),
						  path, 1) != WALLY_OK)
			return false;
	}

	return true;
}

bool psbt_add_keypath_to_last_output(struct bitcoin_tx *tx,
				     u32 key_index,
				     const struct ext_key *ext,
				     bool is_taproot)
{
	size_t outndx = tx->psbt->num_outputs - 1;
	bool ok;

	tal_wally_start();
	ok = psbt_output_set_keypath(key_index, ext, is_taproot, &tx->psbt->outputs[outndx]);
	tal_wally_end(tx->psbt);

	return ok;
}
