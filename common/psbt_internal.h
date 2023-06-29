#ifndef LIGHTNING_COMMON_PSBT_INTERNAL_H
#define LIGHTNING_COMMON_PSBT_INTERNAL_H

#include "config.h"
#include <ccan/tal/tal.h>
#include <common/tx_roles.h>

struct wally_psbt;
struct wally_psbt_input;
struct witness;

/* psbt_finalize_input - Finalize an input with a given witness stack
 *
 * Sets the given witness elements onto the PSBT. Also finalizes
 * the redeem_script, if any.
 * @ctx - the context to allocate onto
 * @in - input to set final_witness for
 * @witness - witness data to add to witness stack
 */
void psbt_finalize_input(const tal_t *ctx,
			 struct wally_psbt_input *in,
			 const struct witness *witness);

/* psbt_to_witness_stacks - Take a side's sigs from a PSBT and copy to a
 * 			    wire witness
 *
 * @ctx - allocation context
 * @psbt - PSBT to copy sigs from
 * @side_to_stack - which side to stack witnesses of
 */
const struct witness **
psbt_to_witnesses(const tal_t *ctx,
		  const struct wally_psbt *psbt,
		  enum tx_role side_to_stack);

#endif /* LIGHTNING_COMMON_PSBT_INTERNAL_H */
