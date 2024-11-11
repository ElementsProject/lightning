#ifndef LIGHTNING_BITCOIN_PSBT_H
#define LIGHTNING_BITCOIN_PSBT_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

struct wally_psbt;
struct wally_psbt_input;
struct wally_tx;
struct wally_tx_input;
struct wally_tx_output;
struct wally_map;
struct amount_asset;
struct amount_sat;
struct bitcoin_outpoint;
struct bitcoin_signature;
struct bitcoin_txid;
struct pubkey;


/* Utility we need for psbt stuffs;
 * add the varint onto the given array */
void add_varint(u8 **arr, size_t val);

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
 * 	      as the locktime/inputs/output psbt fields
 *
 * @ctx - allocation context
 * @wtx - global_tx starter kit
 */
struct wally_psbt *new_psbt(const tal_t *ctx,
			    const struct wally_tx *wtx);

/**
 * clone_psbt - Clone a PSBT onto passed in context
 *
 * @ctx - allocation context
 * @psbt - psbt to be cloned
 */
struct wally_psbt *clone_psbt(const tal_t *ctx, const struct wally_psbt *psbt);

/**
 * combine_psbt - Combine two PSBT into a cloned copy
 *
 * @ctx - allocation context
 * @psbt0 - one psbt
 * @psbt1 - other psbt
 */
struct wally_psbt *combine_psbt(const tal_t *ctx,
				const struct wally_psbt *psbt0,
				const struct wally_psbt *psbt1);

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

/**
 * psbt_finalize - finalize this psbt.
 *
 * Returns false if we can't, otherwise returns true and psbt_is_finalized()
 * is true.
 */
bool psbt_finalize(struct wally_psbt *psbt);

/**
 * psbt_final_tx - extract transaction from finalized psbt.
 * @ctx: context to tallocate return
 * @psbt: psbt to extract.
 *
 * If @psbt isn't final, or we can't extract tx, returns NULL.
 */
struct wally_tx *psbt_final_tx(const tal_t *ctx, const struct wally_psbt *psbt);

/* psbt_make_key - Create a new, proprietary Core Lightning key
 *
 * @ctx - allocation context
 * @key_subtype - type for this key
 * @key_data - any extra data to append to the key
 *
 * Returns a proprietary-prefixed key.
 */
u8 *psbt_make_key(const tal_t *ctx, u8 key_subtype, const u8 *key_data);

struct wally_psbt_input *psbt_add_input(struct wally_psbt *psbt,
					const struct wally_tx_input *input,
					size_t insert_at);

/* One stop shop for adding an input + metadata to a PSBT */
struct wally_psbt_input *psbt_append_input(struct wally_psbt *psbt,
					   const struct bitcoin_outpoint *outpoint,
					   u32 sequence,
					   const u8 *scriptSig,
					   const u8 *input_wscript,
					   const u8 *redeemscript);

/* psbt_input_set_wit_utxo - Set the witness_utxo field for this PSBT */
void psbt_input_set_wit_utxo(struct wally_psbt *psbt, size_t in,
			     const u8 *scriptPubkey, struct amount_sat amt);

/* psbt_input_set_utxo - Set the non-witness utxo field for this PSBT input */
void psbt_input_set_utxo(struct wally_psbt *psbt, size_t in,
			 const struct wally_tx *prev_tx);

void psbt_input_set_outpoint(struct wally_psbt *psbt, size_t in,
			     struct bitcoin_outpoint outpoint);

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
			   const struct pubkey *pubkey, bool is_taproot);

WARN_UNUSED_RESULT bool psbt_input_set_signature(struct wally_psbt *psbt, size_t in,
						 const struct pubkey *pubkey,
						 const struct bitcoin_signature *sig);

/* Returns false on error. On success, *signature_found is set to true if the
 * input has a signature present for `pubkey` and false if if one was not found.
 * Only ignature presence is checked, is not validated. */
WARN_UNUSED_RESULT bool psbt_input_have_signature(const struct wally_psbt *psbt,
						  size_t in,
						  const struct pubkey *pubkey,
						  bool *signature_found);

/* Returns false on error. On success *sig is set to the signature otherwise
 * *sig is set to NULL. */
WARN_UNUSED_RESULT bool psbt_input_get_signature(const tal_t *ctx,
						 const struct wally_psbt *psbt,
						 size_t in,
						 const struct pubkey *pubkey,
						 struct bitcoin_signature **sig);

void psbt_input_set_witscript(struct wally_psbt *psbt, size_t in, const u8 *wscript);

/* psbt_input_set_unknown - Set the given Key-Value in the psbt's input keymap
 * @ctx - tal context for allocations
 * @in - psbt input to set key-value on
 * @key - key for key-value pair
 * @value - value to set
 * @value_len - length of {@value}
 */
void psbt_input_set_unknown(const tal_t *ctx,
			    struct wally_psbt_input *in,
			    const u8 *key,
			    const void *value,
			    size_t value_len);

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

/* psbt_set_lightning - Set a propreitary lightning value on the given map
 *
 * @map - map of unknowns to set the value
 * @proprietary_type - type no. to set
 * @value - the value to be set
 * @val_len - length of value
 */
void psbt_set_lightning(const tal_t *ctx,
			struct wally_map *map,
			const u8 proprietary_type,
			const void *value,
			size_t val_len);

/* psbt_output_set_unknown - Set the given Key-Value in the psbt's output keymap
 *
 * @ctx - tal context for allocations
 * @out - psbt output to set key-value on
 * @key - key for key-value pair
 * @value - value to set
 * @value_len - length of {@value}
 */
void psbt_output_set_unknown(const tal_t *ctx,
			     struct wally_psbt_output *out,
			     const u8 *key, const void *value,
			     size_t value_len);

/* psbt_input_get_amount - Returns the value of this input
 *
 * @psbt - psbt
 * @in - index of input whose value you're returning
 * */
struct amount_sat psbt_input_get_amount(const struct wally_psbt *psbt,
					size_t in);

/* psbt_input_get_weight - Calculate the tx weight for input index `in` */
size_t psbt_input_get_weight(const struct wally_psbt *psbt,
			     size_t in);

/* psbt_output_get_amount - Returns the value of this output
 *
 * @psbt - psbt
 * @out -index of output whose value you're returning
 */
struct amount_sat psbt_output_get_amount(const struct wally_psbt *psbt,
					 size_t out);

/* psbt_output_get_weight - Calculate the tx weight for output index `outnum` */
size_t psbt_output_get_weight(const struct wally_psbt *psbt,
			      size_t outnum);

/* psbt_compute_fee - Returns value of fee for PSBT
 *
 * @psbt -psbt
 */
struct amount_sat psbt_compute_fee(const struct wally_psbt *psbt);

/* psbt_has_input - Is this input present on this psbt
 *
 * @psbt - psbt
 * @outpoint - txid/index spent by input
 */
bool psbt_has_input(const struct wally_psbt *psbt,
		    const struct bitcoin_outpoint *outpoint);

/* wally_psbt_input_spends - Returns true if PSBT input spends given outpoint
 *
 * @input - psbt input
 * @outpoint - outpoint
 */
bool wally_psbt_input_spends(const struct wally_psbt_input *input,
               const struct bitcoin_outpoint *outpoint);

void wally_psbt_input_get_outpoint(const struct wally_psbt_input *in,
                 struct bitcoin_outpoint *outpoint);

const u8 *wally_psbt_output_get_script(const tal_t *ctx,
                     const struct wally_psbt_output *output);

void wally_psbt_input_get_txid(const struct wally_psbt_input *in,
                 struct bitcoin_txid *txid);

struct amount_asset
wally_psbt_output_get_amount(const struct wally_psbt_output *output);

/* psbt_set_version - Returns false if there was any issue with the PSBT.
 * Returns true if it was a well-formed PSET and treats it as a no-op
 */
bool psbt_set_version(struct wally_psbt *psbt, u32 version);

bool elements_psbt_output_is_fee(const struct wally_psbt *psbt, size_t outnum);

struct wally_psbt *psbt_from_b64(const tal_t *ctx,
				 const char *b64,
				 size_t b64len);
char *fmt_wally_psbt(const tal_t *ctx, const struct wally_psbt *psbt);
const u8 *psbt_get_bytes(const tal_t *ctx, const struct wally_psbt *psbt,
			 size_t *bytes_written);
bool validate_psbt(const struct wally_psbt *psbt);
struct wally_psbt *psbt_from_bytes(const tal_t *ctx, const u8 *bytes,
				   size_t byte_len);
void towire_wally_psbt(u8 **pptr, const struct wally_psbt *psbt);
struct wally_psbt *fromwire_wally_psbt(const tal_t *ctx,
				       const u8 **cursor, size_t *max);
#endif /* LIGHTNING_BITCOIN_PSBT_H */
