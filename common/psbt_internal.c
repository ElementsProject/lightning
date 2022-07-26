#include "config.h"
#include <bitcoin/psbt.h>
#include <bitcoin/script.h>
#include <common/psbt_internal.h>
#include <common/psbt_open.h>
#include <wally_psbt_members.h>
#include <wire/peer_wire.h>

static void
psbt_input_set_final_witness_stack(const tal_t *ctx,
				   struct wally_psbt_input *in,
				   const struct witness_element **elements)
{
	wally_tx_witness_stack_free(in->final_witness);

	tal_wally_start();
	wally_tx_witness_stack_init_alloc(tal_count(elements),
					  &in->final_witness);

	for (size_t i = 0; i < tal_count(elements); i++)
		wally_tx_witness_stack_add(in->final_witness,
					   elements[i]->witness,
					   tal_bytelen(elements[i]->witness));
	tal_wally_end(ctx);
}

void psbt_finalize_input(const struct wally_psbt *psbt,
			 size_t input_num,
			 const struct witness_element **elements)
{
    struct wally_psbt_input *in = &psbt->inputs[input_num];
    u8 *input_redeem_script;
    size_t input_redeem_script_len;

    wally_psbt_get_input_redeem_script_len(psbt, input_num, &input_redeem_script_len);
    input_redeem_script = tal_arr(tmpctx, u8, input_redeem_script_len);

	psbt_input_set_final_witness_stack(psbt, in, elements);

	/* There's this horrible edgecase where we set the final_witnesses
	 * directly onto the PSBT, but the input is a P2SH-wrapped input
	 * (which has redeemscripts that belong in the scriptsig). Because
	 * of how the internal libwally stuff works calling 'finalize'
	 * on these just .. ignores it!? Murder. Anyway, here we do a final
	 * scriptsig check -- if there's a redeemscript field still around we
	 * just go ahead and mush it into the final_scriptsig field. */
	if (input_redeem_script) {
		u8 *redeemscript = tal_dup_arr(NULL, u8,
					       input_redeem_script,
					       input_redeem_script_len, 0);
        u8 *final_scriptsig = bitcoin_scriptsig_redeem(NULL,
                         take(redeemscript));
        wally_psbt_input_set_final_scriptsig(in, final_scriptsig, tal_count(final_scriptsig));

        /* FIXME need to check behavior
		in->redeem_script = tal_free(in->redeem_script);
		in->redeem_script_len = 0; */
	}
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

		/* BOLT-f53ca2301232db780843e894f55d95d512f297f9 #2:
		 * - if is the *initiator*:
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
