#include "common/psbt_internal.h"
#include <common/psbt_open.h>
#include <wally_psbt.h>
#include <wire/peer_wire.h>

#if EXPERIMENTAL_FEATURES
void psbt_input_set_final_witness_stack(const tal_t *ctx,
					struct wally_psbt_input *in,
					const struct witness_element **elements)
{
	tal_wally_start();
	wally_tx_witness_stack_init_alloc(tal_count(elements),
					  &in->final_witness);

	for (size_t i = 0; i < tal_count(elements); i++)
		wally_tx_witness_stack_add(in->final_witness,
					   elements[i]->witness,
					   tal_bytelen(elements[i]->witness));
	tal_wally_end(ctx);
}

const struct witness_stack **
psbt_to_witness_stacks(const tal_t *ctx,
		       const struct wally_psbt *psbt,
		       enum tx_role side_to_stack)
{
	size_t stack_index;
	u64 serial_id;
	const struct witness_stack **stacks
		= tal_arr(ctx, const struct witness_stack *, psbt->num_inputs);

	stack_index = 0;
	for (size_t i = 0; i < psbt->num_inputs; i++) {
		if (!psbt_get_serial_id(&psbt->inputs[i].unknowns,
					&serial_id))
			/* FIXME: throw an error ? */
			return NULL;

		/* BOLT-78de9a79b491ae9fb84b1fdb4546bacf642dce87 #2:
		 * - if is the `initiator`:
		 *   - MUST send even `serial_id`s
		 */
		if (serial_id % 2 == side_to_stack) {
			struct wally_tx_witness_stack *wtx_s =
				psbt->inputs[i].final_witness;
			struct witness_stack *stack =
				tal(stacks, struct witness_stack);
			/* Convert the wally_tx_witness_stack to
			 * a witness_stack entry */
			stack->witness_element =
				tal_arr(stack, struct witness_element *,
					wtx_s->num_items);
			for (size_t j = 0; j < tal_count(stack->witness_element); j++) {
				stack->witness_element[j] = tal(stack,
								struct witness_element);
				stack->witness_element[j]->witness =
					tal_dup_arr(stack, u8,
						    wtx_s->items[j].witness,
						    wtx_s->items[j].witness_len,
						    0);

			}

			stacks[stack_index++] = stack;
		}

	}

	if (stack_index == 0)
		return tal_free(stacks);

	tal_resize(&stacks, stack_index);
	return stacks;
}

#endif /* EXPERIMENTAL_FEATURES */
