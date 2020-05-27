#ifndef LIGHTNING_BITCOIN_TX_H
#define LIGHTNING_BITCOIN_TX_H
#include "config.h"
#include "shadouble.h"
#include "signature.h"
#include "varint.h"
#include <ccan/short_types/short_types.h>
#include <ccan/structeq/structeq.h>
#include <ccan/tal/tal.h>
#include <common/amount.h>
#include <wally_psbt.h>
#include <wally_transaction.h>

#define BITCOIN_TX_DEFAULT_SEQUENCE 0xFFFFFFFF
struct wally_psbt;

struct bitcoin_txid {
	struct sha256_double shad;
};
/* Define bitcoin_txid_eq */
STRUCTEQ_DEF(bitcoin_txid, 0, shad.sha.u);

struct bitcoin_tx {
	/* Keep track of input amounts, this is needed for signatures (NULL if
	 * unknown) */
	struct amount_sat **input_amounts;
	struct wally_tx *wtx;

	/* Keep a reference to the ruleset we have to abide by */
	const struct chainparams *chainparams;

	/* psbt struct */
	struct wally_psbt *psbt;
};

struct bitcoin_tx_output {
	struct amount_sat amount;
	u8 *script;
};

/* SHA256^2 the tx in legacy format. */
void bitcoin_txid(const struct bitcoin_tx *tx, struct bitcoin_txid *txid);
void wally_txid(const struct wally_tx *wtx, struct bitcoin_txid *txid);

/* Linear bytes of tx. */
u8 *linearize_tx(const tal_t *ctx, const struct bitcoin_tx *tx);
u8 *linearize_wtx(const tal_t *ctx, const struct wally_tx *wtx);

/* Get weight of tx in Sipa. */
size_t bitcoin_tx_weight(const struct bitcoin_tx *tx);

/* Allocate a tx: you just need to fill in inputs and outputs (they're
 * zeroed with inputs' sequence_number set to FFFFFFFF) */
struct bitcoin_tx *bitcoin_tx(const tal_t *ctx,
			      const struct chainparams *chainparams,
			      varint_t input_count, varint_t output_count,
			      u32 nlocktime);

/* This takes a raw bitcoin tx in hex. */
struct bitcoin_tx *bitcoin_tx_from_hex(const tal_t *ctx, const char *hex,
				       size_t hexlen);

/* Parse hex string to get txid (reversed, a-la bitcoind). */
bool bitcoin_txid_from_hex(const char *hexstr, size_t hexstr_len,
			   struct bitcoin_txid *txid);

/* Get hex string of txid (reversed, a-la bitcoind). */
bool bitcoin_txid_to_hex(const struct bitcoin_txid *txid,
			 char *hexstr, size_t hexstr_len);

/* Internal de-linearization functions. */
struct bitcoin_tx *pull_bitcoin_tx(const tal_t *ctx,
				   const u8 **cursor, size_t *max);
/* Add one output to tx. */
int bitcoin_tx_add_output(struct bitcoin_tx *tx, const u8 *script,
			  u8 *wscript,
			  struct amount_sat amount);

/* Add mutiple output to tx. */
int bitcoin_tx_add_multi_outputs(struct bitcoin_tx *tx,
				 struct bitcoin_tx_output **outputs);

int bitcoin_tx_add_input(struct bitcoin_tx *tx, const struct bitcoin_txid *txid,
			 u32 outnum, u32 sequence,
			 struct amount_sat amount, u8 *script);

/* This helps is useful because wally uses a raw byte array for txids */
bool wally_tx_input_spends(const struct wally_tx_input *input,
			   const struct bitcoin_txid *txid,
			   int outnum);

struct amount_asset
wally_tx_output_get_amount(const struct wally_tx_output *output);

/**
 * Set the output amount on the transaction.
 *
 * Allows changing the amount on the transaction output after it was set on
 * creation. This is useful to grind a feerate or subtract the fee from an
 * existing output.
 */
void bitcoin_tx_output_set_amount(struct bitcoin_tx *tx, int outnum,
				  struct amount_sat amount);

/**
 * Helper to get the script of a script's output as a tal_arr
 *
 * Internally we use a `wally_tx` to represent the transaction. The script
 * attached to a `wally_tx_output` is not a `tal_arr`, so in order to keep the
 * comfort of being able to call `tal_bytelen` and similar on a script we just
 * return a `tal_arr` clone of the original script.
 */
const u8 *bitcoin_tx_output_get_script(const tal_t *ctx, const struct bitcoin_tx *tx, int outnum);

/**
 * Helper to get a witness script for an output.
 */
u8 *bitcoin_tx_output_get_witscript(const tal_t *ctx, const struct bitcoin_tx *tx, int outnum);

/** bitcoin_tx_output_get_amount_sat - Helper to get transaction output's amount
 *
 * Internally we use a `wally_tx` to represent the transaction. The
 * satoshi amount isn't a struct amount_sat, so we need a conversion
 */
void bitcoin_tx_output_get_amount_sat(struct bitcoin_tx *tx, int outnum,
				      struct amount_sat *amount);
/**
 * Helper to just get an amount_sat for the output amount.
 */
struct amount_asset bitcoin_tx_output_get_amount(const struct bitcoin_tx *tx,
						 int outnum);

/**
 * Set the input witness.
 *
 * Given that we generate the witness after constructing the transaction
 * itself, we need a way to attach a witness to an existing input.
 */
void bitcoin_tx_input_set_witness(struct bitcoin_tx *tx, int innum,
				  u8 **witness TAKES);

/**
 * Set the input script on the given input.
 */
void bitcoin_tx_input_set_script(struct bitcoin_tx *tx, int innum, u8 *script);

/**
 * Helper to get a witness as a tal_arr array.
 */
const u8 *bitcoin_tx_input_get_witness(const tal_t *ctx,
				       const struct bitcoin_tx *tx, int innum,
				       int witnum);

/**
 * Wrap the raw txhash in the wally_tx_input into a bitcoin_txid
 */
void bitcoin_tx_input_get_txid(const struct bitcoin_tx *tx, int innum,
			       struct bitcoin_txid *out);
void wally_tx_input_get_txid(const struct wally_tx_input *in,
			     struct bitcoin_txid *txid);

/**
 * Check a transaction for consistency.
 *
 * Mainly for the transition from `bitcoin_tx` to the `wally_tx`. Checks that
 * both transactions serialize to two identical representations.
 */
bool bitcoin_tx_check(const struct bitcoin_tx *tx);


/**
 * Finalize a transaction by truncating overallocated and temporary
 * fields. This includes adding a fee output for elements transactions or
 * adjusting an existing fee output, and resizing metadata arrays for inputs
 * and outputs.
 */
void bitcoin_tx_finalize(struct bitcoin_tx *tx);

/**
 * Returns true if the given outnum is a fee output
 */
bool elements_tx_output_is_fee(const struct bitcoin_tx *tx, int outnum);

/**
 * Calculate the fees for this transaction
 */
struct amount_sat bitcoin_tx_compute_fee(const struct bitcoin_tx *tx);

/*
 * Calculate the fees for this transaction, given a pre-computed input balance.
 *
 * This is needed for cases where the input_amounts aren't properly initialized,
 * typically due to being passed across the wire.
 */
struct amount_sat bitcoin_tx_compute_fee_w_inputs(const struct bitcoin_tx *tx,
						  struct amount_sat input_val);

/* Wire marshalling and unmarshalling */
void fromwire_bitcoin_txid(const u8 **cursor, size_t *max,
			   struct bitcoin_txid *txid);
struct bitcoin_tx *fromwire_bitcoin_tx(const tal_t *ctx,
				       const u8 **cursor, size_t *max);
struct bitcoin_tx_output *fromwire_bitcoin_tx_output(const tal_t *ctx,
						     const u8 **cursor, size_t *max);
void towire_bitcoin_txid(u8 **pptr, const struct bitcoin_txid *txid);
void towire_bitcoin_tx(u8 **pptr, const struct bitcoin_tx *tx);
void towire_bitcoin_tx_output(u8 **pptr, const struct bitcoin_tx_output *output);

/*
 * Get the base64 string encoded PSBT of a bitcoin transaction.
 */
char *bitcoin_tx_to_psbt_base64(const tal_t *ctx, struct bitcoin_tx *tx);
#endif /* LIGHTNING_BITCOIN_TX_H */
