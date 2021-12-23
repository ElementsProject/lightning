#ifndef LIGHTNING_COMMON_PSBT_KEYPATH_H
#define LIGHTNING_COMMON_PSBT_KEYPATH_H

#include "config.h"
#include <ccan/short_types/short_types.h>

struct bitcoin_tx;
struct ext_key;
struct wally_map;

/* psbt_set_keypath - Set the keypath of a PSBT output.
 *
 * @index - child index of the wallet key
 * @ext - extended public key of the immediate parent of the wallet key
 * @map_in - wally keypaths map
 */
void psbt_set_keypath(u32 index,
		      const struct ext_key *ext,
		      struct wally_map *map_in);

/* psbt_add_keypath_to_last_output - augment the last output with the
 * given wallet keypath
 *
 * @tx - transaction to modify
 * @index - child index of the wallet key
 * @ext - extended public key of the immediate parent of the wallet key
 */
void psbt_add_keypath_to_last_output(struct bitcoin_tx *tx,
				     u32 index,
				     const struct ext_key *ext);

#endif /* LIGHTNING_COMMON_PSBT_KEYPATH_H */
