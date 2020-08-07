#ifndef LIGHTNING_BITCOIN_PSBT_H
#define LIGHTNING_BITCOIN_PSBT_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <stddef.h>

struct wally_tx_input;
struct wally_tx_output;
struct wally_psbt;
struct wally_psbt_input;
struct wally_tx;
struct amount_asset;
struct amount_sat;
struct bitcoin_signature;
struct bitcoin_txid;
struct pubkey;

void psbt_destroy(struct wally_psbt *psbt);

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
 * @psbt: the psbt.
 * @txid: the transaction id (output)
 * @wtx: if non-NULL, returns a copy of the transaction (caller must wally_tx_free).
 */
void psbt_txid(const struct wally_psbt *psbt, struct bitcoin_txid *txid,
	       struct wally_tx **wtx);

struct wally_tx *psbt_finalize(struct wally_psbt *psbt, bool finalize_in_place);

struct wally_psbt_input *psbt_add_input(struct wally_psbt *psbt,
					struct wally_tx_input *input,
					size_t insert_at);

void psbt_rm_input(struct wally_psbt *psbt,
		   size_t remove_at);

struct wally_psbt_output *psbt_add_output(struct wally_psbt *psbt,
					  struct wally_tx_output *output,
					  size_t insert_at);

void psbt_rm_output(struct wally_psbt *psbt,
		    size_t remove_at);

void psbt_input_add_pubkey(struct wally_psbt *psbt, size_t in,
			   const struct pubkey *pubkey);

WARN_UNUSED_RESULT bool psbt_input_set_signature(struct wally_psbt *psbt, size_t in,
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
struct amount_sat psbt_input_get_amount(struct wally_psbt *psbt,
					size_t in);

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
