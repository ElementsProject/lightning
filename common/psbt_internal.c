#include "config.h"
#include <assert.h>
#include <bitcoin/psbt.h>
#include <bitcoin/script.h>
#include <bitcoin/varint.h>
#include <common/psbt_internal.h>
#include <common/psbt_open.h>
#include <wire/peer_wire.h>


static bool next_size(const u8 **cursor, size_t *max, size_t *size)
{
	size_t len;
	varint_t varint;

	if (*max < 1)
		return false;

	len = varint_get(*cursor, *max, &varint);

	if (len < 1)
		return false;

	if (*max < len) {
		*max = 0;
		return false;
	}

	*cursor += len;
	*max -= len;
	*size = varint;
	return true;
}

static u8 *next_script(const tal_t *ctx, const u8 **cursor, size_t *max)
{
	const u8 *p;
	size_t size;
	u8 *ret;

	if (!next_size(cursor, max, &size))
		return NULL;

	if (*max < size) {
		*max = 0;
		return NULL;
	}

	p = *cursor;
	*max -= size;
	*cursor += size;

	ret = tal_arr(ctx, u8, size);
	memcpy(ret, p, size);
	return ret;
}

static void
psbt_input_set_final_witness_stack(const tal_t *ctx,
				   struct wally_psbt_input *in,
				   const struct witness *witness)
{
	u8 *script, *sctx;
	const u8 *data = witness->witness_data;
	size_t size, max = tal_count(data);
	bool ok;

	wally_psbt_input_set_final_witness(in, NULL);

	/* FIXME: return an error?? */
	if (!next_size(&data, &max, &size))
		return;

	tal_wally_start();
	sctx = tal(NULL, u8);

	wally_tx_witness_stack_init_alloc(size, &in->final_witness);

	while ((script = next_script(sctx, &data, &max)) && script != NULL) {
		ok = (wally_tx_witness_stack_add(in->final_witness,
					   script, tal_count(script)) == WALLY_OK);
		assert(ok);
	}

	tal_wally_end(ctx);
	tal_free(sctx);
}

void psbt_finalize_input(const tal_t *ctx,
			 struct wally_psbt_input *in,
			 const struct witness *witness)
{
	const struct wally_map_item *redeem_script;
	psbt_input_set_final_witness_stack(ctx, in, witness);

	/* There's this horrible edgecase where we set the final_witnesses
	 * directly onto the PSBT, but the input is a P2SH-wrapped input
	 * (which has redeemscripts that belong in the scriptsig). Because
	 * of how the internal libwally stuff works calling 'finalize'
	 * on these just .. ignores it!? Murder. Anyway, here we do a final
	 * scriptsig check -- if there's a redeemscript field still around we
	 * just go ahead and mush it into the final_scriptsig field. */
	redeem_script = wally_map_get_integer(&in->psbt_fields, /* PSBT_IN_REDEEM_SCRIPT */ 0x04);
	if (redeem_script) {
		u8 *redeemscript = tal_dup_arr(NULL, u8,
					       redeem_script->value,
					       redeem_script->value_len, 0);
		u8 *final_scriptsig =
			bitcoin_scriptsig_redeem(NULL,
						 take(redeemscript));
		wally_psbt_input_set_final_scriptsig(in, final_scriptsig, tal_bytelen(final_scriptsig));
		wally_psbt_input_set_redeem_script(in, tal_arr(NULL, u8, 0), 0);
	}
}

const struct witness **
psbt_to_witnesses(const tal_t *ctx,
		  const struct wally_psbt *psbt,
		  enum tx_role side_to_stack,
		  int input_index_to_ignore)
{
	u64 serial_id;
	const struct witness **witnesses =
		tal_arr(ctx, const struct witness *, 0);

	for (size_t i = 0; i < psbt->num_inputs; i++) {
		struct wally_tx_witness_stack *wtx_s =
			psbt->inputs[i].final_witness;
		if (!psbt_get_serial_id(&psbt->inputs[i].unknowns,
					&serial_id))
			/* FIXME: throw an error ? */
			return tal_free(witnesses);

		if (input_index_to_ignore == i)
			continue;

		/* BOLT #2:
		 * - if is the *initiator*:
		 *   - MUST send even `serial_id`s
		 */
		if (wtx_s && serial_id % 2 == side_to_stack) {

			/* BOLT #2:
			 *
			 * The `witness_data` is encoded as per bitcoin's
			 * wire protocol (a CompactSize number of elements,
			 * with each element a CompactSize length and that
			 * many bytes following).
			 */
			struct witness *wit = tal(witnesses, struct witness);
			wit->witness_data = tal_arr(wit, u8, 0);
			add_varint(&wit->witness_data, wtx_s->num_items);
			for (size_t j = 0; j < wtx_s->num_items; j++) {
				add_varint(&wit->witness_data, wtx_s->items[j].witness_len);
				tal_expand(&wit->witness_data, wtx_s->items[j].witness,
					   wtx_s->items[j].witness_len);
			}

			tal_arr_expand(&witnesses, wit);
		}

	}

	return witnesses;
}
