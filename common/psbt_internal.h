#ifndef LIGHTNING_COMMON_PSBT_INTERNAL_H
#define LIGHTNING_COMMON_PSBT_INTERNAL_H

#include "config.h"
#include <ccan/tal/tal.h>
#include <common/tx_roles.h>

struct wally_psbt;
struct wally_psbt_input;
#if EXPERIMENTAL_FEATURES
struct witness_element;
#endif /* EXPERIMENTAL_FEATURES */

#if EXPERIMENTAL_FEATURES
/* psbt_input_set_final_witness_stack - Set the witness stack for PSBT input
 *
 * @ctx - the context to allocate onto
 * @in - input to set final_witness for
 * @witness_element - elements to add to witness stack
 */
void psbt_input_set_final_witness_stack(const tal_t *ctx,
					struct wally_psbt_input *in,
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
#endif /* EXPERIMENTAL_FEATURES */
#endif /* LIGHTNING_COMMON_PSBT_INTERNAL_H */
