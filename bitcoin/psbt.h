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
struct wally_unknowns_map;
struct amount_asset;
struct amount_sat;
struct bitcoin_signature;
struct bitcoin_txid;
struct pubkey;

int wally_psbt_clone(const struct wally_psbt *psbt, struct wally_psbt **output);

void psbt_destroy(struct wally_psbt *psbt);

/**
 * create_psbt - Create a new psbt object
 *
 * @ctx - allocation context
 *
 * Returns NULL if there's a failure.
 */
struct wally_psbt *create_psbt(const tal_t *ctx);

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
bool psbt_is_finalized(struct wally_psbt *psbt);

/**
 * psbt_txid - get the txid of the psbt (what it would be after finalization)
 * @psbt: the psbt.
 * @txid: the transaction id (output)
 * @wtx: if non-NULL, returns a copy of the transaction (caller must wally_tx_free).
 */
void psbt_txid(const struct wally_psbt *psbt, struct bitcoin_txid *txid,
	       struct wally_tx **wtx);

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

struct wally_psbt_input *psbt_append_input(struct wally_psbt *psbt,
					   const struct bitcoin_txid *txid,
					   u32 outnum, u32 sequence);

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
struct wally_psbt_output *psbt_append_out(struct wally_psbt *psbt,
					  const u8 *script,
					  struct amount_sat amount);

void psbt_rm_output(struct wally_psbt *psbt,
		    size_t remove_at);

void psbt_input_add_pubkey(struct wally_psbt *psbt, size_t in,
			   const struct pubkey *pubkey);

WARN_UNUSED_RESULT bool psbt_input_set_partial_sig(struct wally_psbt *psbt, size_t in,
						   const struct pubkey *pubkey,
						   const struct bitcoin_signature *sig);

void psbt_input_set_prev_utxo(struct wally_psbt *psbt,
			      size_t in,
			      const u8 *wscript,
			      struct amount_sat amt);
void psbt_input_set_prev_utxo_wscript(struct wally_psbt *psbt, size_t in,
			              const u8 *wscript,
				      struct amount_sat amt);
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
bool psbt_input_add_unknown(struct wally_psbt_input *in,
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
void *psbt_get_unknown(struct wally_unknowns_map *map, const u8 *key, size_t *value_len);

/* psbt_output_add_unknown - Add the given Key-Value to the psbt's output keymap
 *
 * @out - psbt output to add key-value to
 * @key - key for key-value pair
 * @value - value to add
 * @value_len - length of {@value}
 */
bool psbt_output_add_unknown(struct wally_psbt_output *out,
			     const u8 *key, const void *value,
			     size_t value_len);

/* psbt_input_get_amount - Returns the value of this input
 *
 * @psbt - psbt
 * @in - index of input whose value you're returning
 * */
struct amount_sat psbt_input_get_amount(struct wally_psbt *psbt,
					size_t in);

/* psbt_output_get_amount - Returns the value of this output
 *
 * @psbt - psbt
 * @out -index of output whose value you're returning
 */
struct amount_sat psbt_output_get_amount(struct wally_psbt *psbt,
					 size_t out);

/* psbt_has_input - Is this input present on this psbt
 *
 * @psbt - psbt
 * @txid - txid of input
 * @outnum - output index of input
 */
bool psbt_has_input(struct wally_psbt *psbt,
		    struct bitcoin_txid *txid,
		    u32 outnum);

bool psbt_from_b64(const char *b64str, struct wally_psbt **psbt);
char *psbt_to_b64(const tal_t *ctx, const struct wally_psbt *psbt);
const u8 *psbt_get_bytes(const tal_t *ctx, const struct wally_psbt *psbt,
			 size_t *bytes_written);
struct wally_psbt *psbt_from_bytes(const tal_t *ctx, const u8 *bytes,
				   size_t byte_len);
void towire_wally_psbt(u8 **pptr, const struct wally_psbt *psbt);
struct wally_psbt *fromwire_wally_psbt(const tal_t *ctx,
				       const u8 **cursor, size_t *max);
#endif /* LIGHTNING_BITCOIN_PSBT_H */
