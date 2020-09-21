#ifndef LIGHTNING_BITCOIN_PSBT_H
#define LIGHTNING_BITCOIN_PSBT_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <stddef.h>

struct wally_psbt;
struct wally_psbt_input;
struct wally_tx;
struct wally_tx_input;
struct wally_tx_output;
struct wally_map;
struct amount_asset;
struct amount_sat;
struct bitcoin_signature;
struct bitcoin_txid;
struct pubkey;

/** psbt_destroy - Destroy a PSBT that is not tal-allocated
 *
 * @psbt - the PSBT to destroy
 *
 * WARNING Do NOT call this function directly if you got the
 * PSBT from create_psbt, new_psbt, psbt_from_bytes,
 * psbt_from_b64, or fromwire_wally_psbt.
 * Those functions register this function as a `tal_destructor`
 * automatically.
 */
void psbt_destroy(struct wally_psbt *psbt);

/**
 * create_psbt - Create a new psbt object
 *
 * @ctx - allocation context
 * @num_inputs - number of inputs to allocate
 * @num_outputs - number of outputs to allocate
 * @locktime - locktime for the transaction
 */
struct wally_psbt *create_psbt(const tal_t *ctx, size_t num_inputs, size_t num_outputs, u32 locktime);

/*
 * new_psbt - Create a PSBT, using the passed in tx
 * 	      as the global_tx
 *
 * @ctx - allocation context
 * @wtx - global_tx starter kit
 */
struct wally_psbt *new_psbt(const tal_t *ctx,
			    const struct wally_tx *wtx);

/**
 * psbt_is_finalized - Check if tx is ready to be extracted
 *
 * The libwally library requires a transaction be *ready* for
 * extraction before it will add/append all of the sigs/witnesses
 * onto the global transaction. This check returns true if
 * a psbt has the finalized script sig and/or witness data populated
 * for such a call
 */
bool psbt_is_finalized(const struct wally_psbt *psbt);

/**
 * psbt_txid - get the txid of the psbt (what it would be after finalization)
 * @ctx: the context to allocate wtx off, if *@wtx isn't NULL.
 * @psbt: the psbt.
 * @txid: the transaction id (output)
 * @wtx: if non-NULL, returns a copy of the transaction (caller must wally_tx_free).
 */
void psbt_txid(const tal_t *ctx,
	       const struct wally_psbt *psbt, struct bitcoin_txid *txid,
	       struct wally_tx **wtx);

/* psbt_elements_normalize_fees - Figure out the fee output for a PSET
 *
 * Adds a fee output if not present, or updates it to include the diff
 * between inputs - outputs. Unlike bitcoin, elements requires every
 * satoshi to be accounted for in an output.
 */
void psbt_elements_normalize_fees(struct wally_psbt *psbt);

struct wally_tx *psbt_finalize(struct wally_psbt *psbt, bool finalize_in_place);

/* psbt_make_key - Create a new, proprietary c-lightning key
 *
 * @ctx - allocation context
 * @key_subtype - type for this key
 * @key_data - any extra data to append to the key
 *
 * Returns a proprietary-prefixed key.
 */
u8 *psbt_make_key(const tal_t *ctx, u8 key_subtype, const u8 *key_data);

struct wally_psbt_input *psbt_add_input(struct wally_psbt *psbt,
					struct wally_tx_input *input,
					size_t insert_at);

/* One stop shop for adding an input + metadata to a PSBT */
struct wally_psbt_input *psbt_append_input(struct wally_psbt *psbt,
					   const struct bitcoin_txid *txid,
					   u32 outnum, u32 sequence,
					   const u8 *scriptSig,
					   const u8 *input_wscript,
					   const u8 *redeemscript);

/* psbt_input_set_wit_utxo - Set the witness_utxo field for this PSBT */
void psbt_input_set_wit_utxo(struct wally_psbt *psbt, size_t in,
			     const u8 *scriptPubkey, struct amount_sat amt);

/* psbt_elements_input_set_asset - Set the asset/value fields for an
 * 				   Elements PSBT (PSET, technically */
void psbt_elements_input_set_asset(struct wally_psbt *psbt, size_t in,
				   struct amount_asset *asset);

void psbt_rm_input(struct wally_psbt *psbt,
		   size_t remove_at);

struct wally_psbt_output *psbt_add_output(struct wally_psbt *psbt,
					  struct wally_tx_output *output,
					  size_t insert_at);

/**
 * wally_psbt_output - Append a new output to the PSBT
 *
 * @psbt - PSBT to append output to
 * @script - scriptPubKey of the output
 * @amount - value of the output
 */
struct wally_psbt_output *psbt_append_output(struct wally_psbt *psbt,
					     const u8 *script,
					     struct amount_sat amount);
struct wally_psbt_output *psbt_insert_output(struct wally_psbt *psbt,
					     const u8 *script,
					     struct amount_sat amount,
					     size_t insert_at);

void psbt_rm_output(struct wally_psbt *psbt,
		    size_t remove_at);

void psbt_input_add_pubkey(struct wally_psbt *psbt, size_t in,
			   const struct pubkey *pubkey);

WARN_UNUSED_RESULT bool psbt_input_set_signature(struct wally_psbt *psbt, size_t in,
						 const struct pubkey *pubkey,
						 const struct bitcoin_signature *sig);

void psbt_input_set_witscript(struct wally_psbt *psbt, size_t in, const u8 *wscript);
void psbt_elements_input_init(struct wally_psbt *psbt, size_t in,
			      const u8 *scriptPubkey,
			      struct amount_asset *asset,
			      const u8 *nonce);
void psbt_elements_input_init_witness(struct wally_psbt *psbt, size_t in,
				      const u8 *witscript,
				      struct amount_asset *asset,
				      const u8 *nonce);
bool psbt_input_set_redeemscript(struct wally_psbt *psbt, size_t in,
				 const u8 *redeemscript);
/* psbt_input_add_unknown - Add the given Key-Value to the psbt's input keymap
 * @in - psbt input to add key-value to
 * @key - key for key-value pair
 * @value - value to add
 * @value_len - length of {@value}
 */
void psbt_input_add_unknown(struct wally_psbt_input *in,
			    const u8 *key,
			    const void *value,
			    size_t value_len);
/* psbt_get_unknown - Fetch the value from the given map at key
 *
 * @map - map of unknowns to search for key
 * @key - key of key-value pair to return value for
 * @value_len - (out) length of value (if found)
 *
 * Returns: value at @key, or NULL if not found */
void *psbt_get_unknown(const struct wally_map *map,
		       const u8 *key,
		       size_t *val_len);

/* psbt_get_lightning - Fetch a proprietary lightning value from the given map
 *
 * @map - map of unknowns to search for key
 * @proprietary_type - type no. to look for
 * @val_len - (out) length of value (if found)
 *
 * Returns: value of type {proprietary_type}, or NULL if not found */
void *psbt_get_lightning(const struct wally_map *map,
			 const u8 proprietary_type,
			 size_t *val_len);

/* psbt_output_add_unknown - Add the given Key-Value to the psbt's output keymap
 *
 * @out - psbt output to add key-value to
 * @key - key for key-value pair
 * @value - value to add
 * @value_len - length of {@value}
 */
void psbt_output_add_unknown(struct wally_psbt_output *out,
			     const u8 *key, const void *value,
			     size_t value_len);

/* psbt_input_get_amount - Returns the value of this input
 *
 * @psbt - psbt
 * @in - index of input whose value you're returning
 * */
struct amount_sat psbt_input_get_amount(const struct wally_psbt *psbt,
					size_t in);

/* psbt_output_get_amount - Returns the value of this output
 *
 * @psbt - psbt
 * @out -index of output whose value you're returning
 */
struct amount_sat psbt_output_get_amount(const struct wally_psbt *psbt,
					 size_t out);

/* psbt_has_input - Is this input present on this psbt
 *
 * @psbt - psbt
 * @txid - txid of input
 * @outnum - output index of input
 */
bool psbt_has_input(const struct wally_psbt *psbt,
		    const struct bitcoin_txid *txid,
		    u32 outnum);

struct wally_psbt *psbt_from_b64(const tal_t *ctx,
				 const char *b64,
				 size_t b64len);
char *psbt_to_b64(const tal_t *ctx, const struct wally_psbt *psbt);
const u8 *psbt_get_bytes(const tal_t *ctx, const struct wally_psbt *psbt,
			 size_t *bytes_written);
struct wally_psbt *psbt_from_bytes(const tal_t *ctx, const u8 *bytes,
				   size_t byte_len);
void towire_wally_psbt(u8 **pptr, const struct wally_psbt *psbt);
struct wally_psbt *fromwire_wally_psbt(const tal_t *ctx,
				       const u8 **cursor, size_t *max);
#endif /* LIGHTNING_BITCOIN_PSBT_H */
