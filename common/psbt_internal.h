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
 * @ctx - the context to allocate onto
 * @in - input to set final_witness for
 * @witness_element - elements to add to witness stack
 */
void psbt_finalize_input(const tal_t *ctx,
			 struct wally_psbt_input *in,
			 const struct witness_element **elements);
/* psbt_finalize_multisig_signatures - Takes signatures from the
 * "partial signatures" section and adds them to the witness stack
 * in the order their corresponding public keys appear in the witness
 * script. If the signature is already present, it is not added.
 *
 * If the stack is empty, the witness_script is appended and a zero
 * size signature is prepended.
 *
 * The signatures are DER encoded if not already.
 *
 * @ctx - the context to allocate onto
 * @in - input to set final_witness for
 *
 * Returns the number of signatures that were recognized as correct
 * for the witness script (whether they were already present or not).
 */
int psbt_finalize_multisig_signatures(const tal_t *ctx,
				       struct wally_psbt_input *in);
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
