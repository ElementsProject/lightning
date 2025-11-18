#ifndef LIGHTNING_COMMON_PSBT_KEYPATH_H
#define LIGHTNING_COMMON_PSBT_KEYPATH_H

#include "config.h"
#include <ccan/compiler/compiler.h>
#include <ccan/short_types/short_types.h>
#include <wally_psbt.h>

struct bitcoin_tx;
struct ext_key;
struct wally_map;

/* psbt_output_set_keypath - Set the keypath of a PSBT output.
 *
 * @index - child index of the wallet key
 * @ext - extended public key of the immediate parent of the wallet key
 * @is_taproot - PSBT output has taproot script
 * @output - PSBT output to set
 *
 * This can fail, if it's adding the same thing twice (taproot only)
 */
WARN_UNUSED_RESULT
bool psbt_output_set_keypath(u32 index,
			     const struct ext_key *ext,
			     bool is_taproot,
			     struct wally_psbt_output *output);

/* psbt_add_keypath_to_last_output - augment the last output with the
 * given wallet keypath
 *
 * @tx - transaction to modify
 * @index - child index of the wallet key
 * @ext - extended public key of the immediate parent of the wallet key
 * @is_taproot - if the output is taproot
 */
WARN_UNUSED_RESULT
bool psbt_add_keypath_to_last_output(struct bitcoin_tx *tx,
				     u32 index,
				     const struct ext_key *ext,
				     bool is_taproot);

#endif /* LIGHTNING_COMMON_PSBT_KEYPATH_H */
