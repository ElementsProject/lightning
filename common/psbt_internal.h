#ifndef LIGHTNING_COMMON_PSBT_INTERNAL_H
#define LIGHTNING_COMMON_PSBT_INTERNAL_H

#include "config.h"
#include <ccan/tal/tal.h>
#include <common/tx_roles.h>

struct wally_psbt;
struct wally_psbt_input;
struct witness_element;

/* psbt_finalize_input - Finalize an input with a given witness stack
 *
 * Sets the given witness elements onto the PSBT. Also finalizes
 * the redeem_script, if any.
 * @psbt - the PSBT containing the input to set final_witness for
 * @in - index of the input in the PSBT
 * @witness_element - elements to add to witness stack
 */
void psbt_finalize_input(struct wally_psbt *psbt,
			 size_t in,
			 const struct witness_element **elements);

/* psbt_to_witness_stacks - Take all sigs on a PSBT and copy to a
 * 			    witness_stack
 *
 * @ctx - allocation context
 * @psbt - PSBT to copy sigs from
 * @opener - which side initiated this tx
 */
const struct witness_stack **
psbt_to_witness_stacks(const tal_t *ctx,
		       const struct wally_psbt *psbt,
		       enum tx_role side_to_stack);
#endif /* LIGHTNING_COMMON_PSBT_INTERNAL_H */
