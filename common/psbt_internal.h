#ifndef LIGHTNING_COMMON_PSBT_INTERNAL_H
#define LIGHTNING_COMMON_PSBT_INTERNAL_H

#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <common/tx_roles.h>

struct wally_psbt;
struct wally_psbt_input;
struct witness;

/* One element of a witness stack. @data points into the witness blob. */
struct witness_element {
	const u8 *data;
	size_t len;
};

/* True iff witness is a complete witness stack: item count, that many
 * items, no trailing bytes. @num_items is set only on success. */
bool witness_stack_items(const u8 *witness, size_t *num_items);

/* Elements of a complete witness stack, pointing into @witness.
 * NULL if truncated or trailing bytes remain. An empty stack is a
 * zero-length array, not NULL. */
const struct witness_element *witness_stack_elements(const tal_t *ctx,
						     const u8 *witness);

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

/* Minimal tx_signatures witness check, shared by dual open and splice.
 * NULL if acceptable. */
const char *check_tx_signatures_witness(const tal_t *ctx,
					const struct wally_psbt_input *in,
					const struct witness *witness);

/* The number of witnesses must equal the inputs added by the sending
 * node. @input_index_to_ignore is not counted (the splice funding
 * input, whose signature is not in the witness array). Pass -1 to
 * count every input of @their_role. */
const char *check_tx_signatures_witness_count(const tal_t *ctx,
					     const struct wally_psbt *psbt,
					     enum tx_role their_role,
					     size_t num_witnesses,
					     int input_index_to_ignore);

/* psbt_to_witnesses - Take a side's sigs from a PSBT and copy to a
 * 			    wire witness
 *
 * @ctx - allocation context
 * @psbt - PSBT to copy sigs from
 * @side_to_stack - which side to stack witnesses of
 * @input_index_to_ignore - which input to not include. Pass -1 to include all.
 */
const struct witness **
psbt_to_witnesses(const tal_t *ctx,
		  const struct wally_psbt *psbt,
		  enum tx_role side_to_stack,
                  int input_index_to_ignore);

#endif /* LIGHTNING_COMMON_PSBT_INTERNAL_H */
