#include <assert.h>
#include <bitcoin/psbt.h>
#include <ccan/cast/cast.h>
#include <string.h>
#include <wally_psbt.h>
#include <wally_transaction.h>
#include <wire/wire.h>

#define MAKE_ROOM(arr, pos, num)				\
	memmove((arr) + (pos) + 1, (arr) + (pos),		\
		sizeof(*(arr)) * ((num) - ((pos) + 1)))

#define REMOVE_ELEM(arr, pos, num)				\
	memmove((arr) + (pos), (arr) + (pos) + 1,		\
		sizeof(*(arr)) * ((num) - ((pos) + 1)))

void psbt_destroy(struct wally_psbt *psbt)
{
	wally_psbt_free(psbt);
}

struct wally_psbt *new_psbt(const tal_t *ctx, const struct wally_tx *wtx)
{
	struct wally_psbt *psbt;
	int wally_err;
	u8 **scripts;
	size_t *script_lens;
	struct wally_tx_witness_stack **witnesses;

	wally_err = wally_psbt_init_alloc(wtx->num_inputs, wtx->num_outputs, 0, &psbt);
	assert(wally_err == WALLY_OK);
	tal_add_destructor(psbt, psbt_destroy);

	/* we can't have scripts on the psbt's global tx,
	 * so we erase them/stash them until after it's been populated */
	scripts = tal_arr(NULL, u8 *, wtx->num_inputs);
	script_lens = tal_arr(NULL, size_t, wtx->num_inputs);
	witnesses = tal_arr(NULL, struct wally_tx_witness_stack *, wtx->num_inputs);
	for (size_t i = 0; i < wtx->num_inputs; i++) {
		scripts[i] = (u8 *)wtx->inputs[i].script;
		wtx->inputs[i].script = NULL;
		script_lens[i] = wtx->inputs[i].script_len;
		wtx->inputs[i].script_len = 0;
		witnesses[i] = wtx->inputs[i].witness;
		wtx->inputs[i].witness = NULL;
	}

	wally_err = wally_psbt_set_global_tx(psbt, cast_const(struct wally_tx *, wtx));
	assert(wally_err == WALLY_OK);

	/* set the scripts + witnesses back */
	for (size_t i = 0; i < wtx->num_inputs; i++) {
		wtx->inputs[i].script = (unsigned char *)scripts[i];
		wtx->inputs[i].script_len = script_lens[i];
		wtx->inputs[i].witness = witnesses[i];
	}

	tal_free(witnesses);
	tal_free(scripts);
	tal_free(script_lens);

	return tal_steal(ctx, psbt);
}

struct wally_psbt_input *psbt_add_input(struct wally_psbt *psbt,
					struct wally_tx_input *input,
				       	size_t insert_at)
{
	struct wally_tx *tx;
	struct wally_tx_input tmp_in;

	tx = psbt->tx;
	assert(insert_at <= tx->num_inputs);
	wally_tx_add_input(tx, input);
	tmp_in = tx->inputs[tx->num_inputs - 1];
	MAKE_ROOM(tx->inputs, insert_at, tx->num_inputs);
	tx->inputs[insert_at] = tmp_in;

    	if (psbt->inputs_allocation_len < tx->num_inputs) {
		struct wally_psbt_input *p = tal_arr(psbt, struct wally_psbt_input, tx->num_inputs);
		memcpy(p, psbt->inputs, sizeof(*psbt->inputs) * psbt->inputs_allocation_len);
		tal_free(psbt->inputs);

		psbt->inputs = p;
		psbt->inputs_allocation_len = tx->num_inputs;
	}

	psbt->num_inputs += 1;
	MAKE_ROOM(psbt->inputs, insert_at, psbt->num_inputs);
	memset(&psbt->inputs[insert_at], 0, sizeof(psbt->inputs[insert_at]));
	return &psbt->inputs[insert_at];
}

void psbt_rm_input(struct wally_psbt *psbt,
		   size_t remove_at)
{
	assert(remove_at < psbt->tx->num_inputs);
	wally_tx_remove_input(psbt->tx, remove_at);
	REMOVE_ELEM(psbt->inputs, remove_at, psbt->num_inputs);
	psbt->num_inputs -= 1;
}

struct wally_psbt_output *psbt_add_output(struct wally_psbt *psbt,
					  struct wally_tx_output *output,
					  size_t insert_at)
{
	struct wally_tx *tx;
	struct wally_tx_output tmp_out;

	tx = psbt->tx;
	assert(insert_at <= tx->num_outputs);
	wally_tx_add_output(tx, output);
	tmp_out = tx->outputs[tx->num_outputs - 1];
	MAKE_ROOM(tx->outputs, insert_at, tx->num_outputs);
	tx->outputs[insert_at] = tmp_out;

    	if (psbt->outputs_allocation_len < tx->num_outputs) {
		struct wally_psbt_output *p = tal_arr(psbt, struct wally_psbt_output, tx->num_outputs);
		memcpy(p, psbt->outputs, sizeof(*psbt->outputs) * psbt->outputs_allocation_len);
		tal_free(psbt->outputs);

		psbt->outputs = p;
		psbt->outputs_allocation_len = tx->num_outputs;
	}

	psbt->num_outputs += 1;
	MAKE_ROOM(psbt->outputs, insert_at, psbt->num_outputs);
	memset(&psbt->outputs[insert_at], 0, sizeof(psbt->outputs[insert_at]));
	return &psbt->outputs[insert_at];
}

void psbt_rm_output(struct wally_psbt *psbt,
		    size_t remove_at)
{
	assert(remove_at < psbt->tx->num_outputs);
	wally_tx_remove_output(psbt->tx, remove_at);
	REMOVE_ELEM(psbt->outputs, remove_at, psbt->num_outputs);
	psbt->num_outputs -= 1;
}

void towire_psbt(u8 **pptr, const struct wally_psbt *psbt)
{
	/* Let's include the PSBT bytes */
	for (size_t room = 1024; room < 1024 * 1000; room *= 2) {
		u8 *pbt_bytes = tal_arr(NULL, u8, room);
		size_t bytes_written;
		if (wally_psbt_to_bytes(psbt, pbt_bytes, room, &bytes_written) == WALLY_OK) {
			towire_u32(pptr, bytes_written);
			towire_u8_array(pptr, pbt_bytes, bytes_written);
			tal_free(pbt_bytes);
			return;
		}
		tal_free(pbt_bytes);
	}
	/* PSBT is too big */
	abort();
}

struct wally_psbt *fromwire_psbt(const tal_t *ctx,
				 const u8 **cursor, size_t *max)
{
	struct wally_psbt *psbt;
	u32 psbt_byte_len;
	const u8 *psbt_buf;

	psbt_byte_len = fromwire_u32(cursor, max);
	psbt_buf = fromwire(cursor, max, NULL, psbt_byte_len);
	if (!psbt_buf)
		return NULL;

	if (wally_psbt_from_bytes(psbt_buf, psbt_byte_len, &psbt) != WALLY_OK)
		return fromwire_fail(cursor, max);

	/* We promised it would be owned by ctx: libwally uses a dummy owner */
	tal_steal(ctx, psbt);
	tal_add_destructor(psbt, psbt_destroy);

#if DEVELOPER
	/* Re-marshall for sanity check! */
	u8 *tmpbuf = tal_arr(NULL, u8, psbt_byte_len);
	size_t written;
	if (wally_psbt_to_bytes(psbt, tmpbuf, psbt_byte_len, &written) != WALLY_OK) {
		tal_free(tmpbuf);
		tal_free(psbt);
		return fromwire_fail(cursor, max);
	}
	tal_free(tmpbuf);
#endif

	return psbt;
}

