#include "config.h"
#include <assert.h>
#include <bitcoin/psbt.h>
#include <bitcoin/pubkey.h>
#include <bitcoin/script.h>
#include <ccan/tal/str/str.h>
#include <common/psbt_internal.h>
#include <common/psbt_open.h>
#include <common/utils.h>
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

/* If @elements is non-NULL it must hold at least as many slots as the
 * stack claims. A failure may have written a prefix; ignore it. */
static bool parse_witness_stack(const u8 *witness, size_t *num_items,
				struct witness_element *elements)
{
	const u8 *cursor = witness;
	size_t max = tal_bytelen(witness);
	size_t n, item_len;

	if (!next_size(&cursor, &max, &n))
		return false;

	for (size_t i = 0; i < n; i++) {
		if (!next_size(&cursor, &max, &item_len))
			return false;
		if (max < item_len)
			return false;
		if (elements) {
			elements[i].data = cursor;
			elements[i].len = item_len;
		}
		cursor += item_len;
		max -= item_len;
	}

	/* Encoding ends here; anything left is not a witness. */
	if (max != 0)
		return false;

	*num_items = n;
	return true;
}

bool witness_stack_items(const u8 *witness, size_t *num_items)
{
	return parse_witness_stack(witness, num_items, NULL);
}

const struct witness_element *witness_stack_elements(const tal_t *ctx,
						     const u8 *witness)
{
	size_t n;
	struct witness_element *elements;

	if (!parse_witness_stack(witness, &n, NULL))
		return NULL;

	/* Each item costs at least its length byte, so n fits the blob. */
	elements = tal_arr(ctx, struct witness_element, n);
	if (!parse_witness_stack(witness, &n, elements))
		return tal_free(elements);
	return elements;
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
			bitcoin_scriptsig_redeem(ctx,
						 take(redeemscript));
		tal_wally_start();
		wally_psbt_input_set_final_scriptsig(in, final_scriptsig, tal_bytelen(final_scriptsig));
		wally_psbt_input_set_redeem_script(in, tal_arr(in, u8, 0), 0);
		tal_wally_end(ctx);
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
				if (wtx_s->items[j].witness_len) {
					assert(wtx_s->items[j].witness);
					tal_expand(&wit->witness_data,
						   wtx_s->items[j].witness,
						   wtx_s->items[j].witness_len);
				}
			}

			tal_arr_expand(&witnesses, wit);
		}

	}

	return witnesses;
}

/* Bitcoin Core src/policy/policy.h. Applied only to the type they belong to. */
#define MAX_STANDARD_P2WSH_STACK_ITEMS 100
#define MAX_STANDARD_P2WSH_STACK_ITEM_SIZE 80
#define MAX_STANDARD_P2WSH_SCRIPT_SIZE 3600
#define MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE 80

/* BIP341 annex tag. BIP342 leaf version is the low 7 bits of 0xc0. */
#define WITNESS_ANNEX_TAG 0x50
#define TAPROOT_LEAF_MASK 0xfe
#define TAPROOT_LEAF_TAPSCRIPT 0xc0

/* A P2WPKH witness is always a signature and a compressed pubkey.
 * No byte cap: the shape is fixed. */
static const char *check_p2wpkh_witness(const tal_t *ctx,
					const struct witness_element *elems)
{
	size_t n = tal_count(elems);

	if (n != 2)
		return tal_fmt(ctx,
			       "witness is non-standard: "
			       "P2WPKH witness has %zu items, "
			       "expected a signature and a public key",
			       n);
	if (elems[1].len != PUBKEY_CMPR_LEN)
		return tal_fmt(ctx,
			       "witness is non-standard: "
			       "P2WPKH public key is %zu bytes",
			       elems[1].len);
	/* Sighash byte sits after the DER signature. No interpreter. */
	if (elems[0].len == 0 || elems[0].data[elems[0].len - 1] != SIGHASH_ALL)
		return tal_fmt(ctx,
			       "witness is non-standard: "
			       "P2WPKH signature is not SIGHASH_ALL");
	return NULL;
}

/* Items below the witness script, not the script itself. */
static const char *check_p2wsh_witness(const tal_t *ctx,
				       const struct witness_element *elems)
{
	size_t n = tal_count(elems);
	size_t stack_items = n - 1;

	if (elems[n - 1].len > MAX_STANDARD_P2WSH_SCRIPT_SIZE)
		return tal_fmt(ctx,
			       "witness is non-standard: "
			       "witness script is %zu bytes",
			       elems[n - 1].len);

	if (stack_items > MAX_STANDARD_P2WSH_STACK_ITEMS)
		return tal_fmt(ctx,
			       "witness is non-standard: "
			       "%zu stack items",
			       stack_items);

	for (size_t i = 0; i < stack_items; i++) {
		if (elems[i].len > MAX_STANDARD_P2WSH_STACK_ITEM_SIZE)
			return tal_fmt(ctx,
				       "witness is non-standard: "
				       "stack item %zu is %zu bytes",
				       i, elems[i].len);
	}
	/* FIXME: no SIGHASH_ALL check. Which stack items are signatures
	 * depends on the witness script, so this needs an interpreter. */
	return NULL;
}

/* Key path has no size policy. Tapscript limits the items under the
 * script; an annex is non-standard. */
static const char *check_p2tr_witness(const tal_t *ctx,
				      const struct witness_element *elems)
{
	size_t n = tal_count(elems);
	const struct witness_element *control;

	if (n >= 2 && elems[n - 1].len > 0
	    && elems[n - 1].data[0] == WITNESS_ANNEX_TAG)
		return tal_fmt(ctx, "witness is non-standard: taproot annex");

	/* Key path. 64 bytes omits the sighash: that is SIGHASH_DEFAULT,
	 * which is SIGHASH_ALL. 65 bytes must end in SIGHASH_ALL. */
	if (n == 1) {
		const struct witness_element *sig = &elems[0];

		if (sig->len == 64
		    || (sig->len == 65 && sig->data[64] == SIGHASH_ALL))
			return NULL;
		return tal_fmt(ctx,
			       "witness is non-standard: "
			       "P2TR key path signature is not SIGHASH_ALL");
	}

	if (n < 2)
		return NULL;

	/* FIXME: no SIGHASH_ALL check on a script-path spend. Which stack
	 * items are signatures depends on the leaf script. */

	control = &elems[n - 1];
	if (control->len == 0)
		return tal_fmt(ctx,
			       "witness is non-standard: "
			       "empty taproot control block");
	if ((control->data[0] & TAPROOT_LEAF_MASK) != TAPROOT_LEAF_TAPSCRIPT)
		return NULL;

	for (size_t i = 0; i + 2 < n; i++) {
		if (elems[i].len > MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE)
			return tal_fmt(ctx,
				       "witness is non-standard: "
				       "tapscript stack item %zu is %zu bytes",
				       i, elems[i].len);
	}
	return NULL;
}

/* Our inputs carry witness_utxo. Peer inputs carry the prevtx in utxo. */
static const u8 *spent_scriptpubkey(const struct wally_psbt_input *in,
				    size_t *script_len)
{
	if (in->witness_utxo && in->witness_utxo->script) {
		*script_len = in->witness_utxo->script_len;
		return in->witness_utxo->script;
	}
	if (in->utxo && in->index < in->utxo->num_outputs
	    && in->utxo->outputs[in->index].script) {
		*script_len = in->utxo->outputs[in->index].script_len;
		return in->utxo->outputs[in->index].script;
	}
	*script_len = 0;
	return NULL;
}

const char *check_tx_signatures_witness(const tal_t *ctx,
					const struct wally_psbt_input *in,
					const struct witness *witness)
{
	const struct witness_element *elems;
	const u8 *script;
	size_t script_len;

	if (!witness || !witness->witness_data ||
	    tal_count(witness->witness_data) == 0)
		return tal_fmt(ctx, "witness is empty");

	elems = witness_stack_elements(ctx, witness->witness_data);
	if (!elems)
		return tal_fmt(ctx, "witness is truncated or has trailing bytes");

	if (tal_count(elems) == 0)
		return tal_fmt(ctx, "witness is empty");

	script = spent_scriptpubkey(in, &script_len);
	if (script && is_p2wpkh(script, script_len, NULL))
		return check_p2wpkh_witness(ctx, elems);
	if (script && is_p2wsh(script, script_len, NULL))
		return check_p2wsh_witness(ctx, elems);
	if (script && is_p2tr(script, script_len, NULL))
		return check_p2tr_witness(ctx, elems);

	return tal_fmt(ctx,
		       "witness is non-standard: "
		       "input is not P2WPKH, P2WSH or P2TR");
}

const char *check_tx_signatures_witness_count(const tal_t *ctx,
					     const struct wally_psbt *psbt,
					     enum tx_role their_role,
					     size_t num_witnesses,
					     int input_index_to_ignore)
{
	size_t peer_inputs = 0;

	for (size_t i = 0; i < psbt->num_inputs; i++) {
		u64 in_serial;

		if (input_index_to_ignore >= 0
		    && i == (size_t)input_index_to_ignore)
			continue;
		if (!psbt_get_serial_id(&psbt->inputs[i].unknowns, &in_serial))
			continue;
		if (in_serial % 2 != their_role)
			continue;
		peer_inputs++;
	}

	if (peer_inputs != num_witnesses)
		return tal_fmt(ctx,
			       "Mismatched witness stack count, expecting %zu, "
			       "got %zu",
			       peer_inputs, num_witnesses);
	return NULL;
}
