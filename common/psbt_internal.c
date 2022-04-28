#include "common/psbt_internal.h"
#include <bitcoin/script.h>
#include <ccan/ccan/tal/tal.h>
#include <common/psbt_open.h>
#include <wally_psbt.h>
#include <wire/peer_wire.h>

static void
psbt_input_set_final_witness_stack(const tal_t *ctx,
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

void psbt_finalize_input(const tal_t *ctx,
			 struct wally_psbt_input *in,
			 const struct witness_element **elements)
{
	psbt_input_set_final_witness_stack(ctx, in, elements);

	/* There's this horrible edgecase where we set the final_witnesses
	 * directly onto the PSBT, but the input is a P2SH-wrapped input
	 * (which has redeemscripts that belong in the scriptsig). Because
	 * of how the internal libwally stuff works calling 'finalize'
	 * on these just .. ignores it!? Murder. Anyway, here we do a final
	 * scriptsig check -- if there's a redeemscript field still around we
	 * just go ahead and mush it into the final_scriptsig field. */
	if (in->redeem_script) {
		u8 *redeemscript = tal_dup_arr(NULL, u8,
					       in->redeem_script,
					       in->redeem_script_len, 0);
		in->final_scriptsig =
			bitcoin_scriptsig_redeem(NULL,
						 take(redeemscript));
		in->final_scriptsig_len =
			tal_bytelen(in->final_scriptsig);

		in->redeem_script = tal_free(in->redeem_script);
		in->redeem_script_len = 0;
	}
}

static size_t index_of_pubkey_in_multisig(const unsigned char *pubkey,
					  size_t pubkey_len,
					  const unsigned char *witness_script,
					  size_t witness_script_len)
{
	if(!witness_script_len)
		return SIZE_MAX;

	/* Currently only support 1-16 required signatures
	 *
	 * 0x51: OP_1
	 * 0x60: OP_16 */
	if(*witness_script < 0x51 || *witness_script > 0x60)
		return SIZE_MAX;

	size_t pubkey_index = 0;

	for(int i = 1; i < witness_script_len; ) {

		unsigned char item_size = witness_script[i];

		 /* item_size must be a raw push data */
		if(item_size < 0x01 || item_size > 0x4b)
			break;

		if(++i + item_size >= witness_script_len)
			break;

		/* Check for pubkey binary match */
		if(item_size == pubkey_len)
			if(0 == memcmp(witness_script + i,
				       pubkey,
				       item_size))
				return pubkey_index;

		pubkey_index++;
		i += item_size;
	}

	return SIZE_MAX;
}

int psbt_finalize_multisig_signatures(const tal_t *ctx,
				      struct wally_psbt_input *in)
{
	int result = 0;

	tal_wally_start();

	if(!in->final_witness)
		wally_tx_witness_stack_init_alloc(1,
						  &in->final_witness);

	/* If this is our first pass, add the empty first signature and
	 * the witness script
	 */

	if(!in->final_witness->num_items) {

		wally_tx_witness_stack_add(in->final_witness,
					   NULL,
					   0);

		wally_tx_witness_stack_add(in->final_witness,
					   in->witness_script,
					   in->witness_script_len);
	}

	/* Add signatures to the witness stack */

	for(int i = 0; i < in->signatures.num_items; i++) {

		u8 der[EC_SIGNATURE_DER_MAX_LEN + 1];
		struct wally_map_item *item = &in->signatures.items[i];
		unsigned char *value = item->value;
		size_t value_len = item->value_len;

		size_t pubkey_index =
			index_of_pubkey_in_multisig(item->key,
						    item->key_len,
						    in->witness_script,
						    in->witness_script_len);

		/* If the public key is not found in the witness script, skip */
		if(pubkey_index == SIZE_MAX)
			continue;

		/* Because the first signature is always an empty one, we move
		 * the real signatures over by one */

		pubkey_index++;

		/* We want to return the number of signatures that would have
		 * been added, regardless of if its already present. This makes
		 * the result value more useful as a success/failure mechanism.
		 */

		result++;

		/* If the signature is not DER encoded, let's encode it */
		if(item->value_len == sizeof(secp256k1_ecdsa_signature)) {

			secp256k1_ecdsa_signature *sig;

			sig = (secp256k1_ecdsa_signature *)item->value;

			size_t der_len = sizeof(der);

			secp256k1_ecdsa_signature_serialize_der(secp256k1_ctx,
								der, &der_len, sig);

			/* Append sighash type */
			der[der_len++] = SIGHASH_ALL;

			value = der;
			value_len = der_len;
		}

		/* Search through witness stack to see if the signature is
		 * already present */

		bool is_already_present = false;

		for(int j = 0; j < in->final_witness->num_items; j++) {

			struct wally_tx_witness_item *cmp_item =
				&in->final_witness->items[j];

			if(value_len != cmp_item->witness_len)
				continue;

			if(0 == memcmp(value,
				       cmp_item->witness,
				       value_len))
				is_already_present = true;
		}

		if(is_already_present)
			continue;

		/* wally current has no witness stack insert, so we must
		 * hobble one together with the available methods.
		 *
		 * We'll add a second witness script on the end and then
		 * copy each item to the stack item above it until we
		 * have the correct spot to insert the new signature.
		 */

		wally_tx_witness_stack_add(in->final_witness,
					   in->witness_script,
					   in->witness_script_len);

		int index = in->final_witness->num_items - 1;

		do {

			struct wally_tx_witness_item *lower_item =
				&in->final_witness->items[index - 1];

			wally_tx_witness_stack_set(in->final_witness,
						   index,
						   lower_item->witness,
						   lower_item->witness_len);

			index--;

		} while(index > pubkey_index);

		/* index is now the appropriate spot in the stack to add the
		 * sig, so let's add it there */

		wally_tx_witness_stack_set(in->final_witness,
					   index,
					   value,
					   value_len);
	}

	tal_wally_end(ctx);

	return result;
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
