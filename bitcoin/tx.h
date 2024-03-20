#ifndef LIGHTNING_BITCOIN_TX_H
#define LIGHTNING_BITCOIN_TX_H
#include "config.h"
#include <bitcoin/chainparams.h>
#include <bitcoin/shadouble.h>
#include <bitcoin/signature.h>
#include <bitcoin/varint.h>
#include <ccan/structeq/structeq.h>
#include <common/amount.h>
#include <wally_transaction.h>

#define BITCOIN_TX_DEFAULT_SEQUENCE 0xFFFFFFFF

/* BIP 125: Any nsequence < 0xFFFFFFFE is replacable.
 * And bitcoind uses this value. */
#define BITCOIN_TX_RBF_SEQUENCE 0xFFFFFFFD
struct wally_psbt;

struct bitcoin_txid {
	struct sha256_double shad;
};

struct bitcoin_outpoint {
	struct bitcoin_txid txid;
	u32 n;
};

/* Define bitcoin_txid_eq */
STRUCTEQ_DEF(bitcoin_txid, 0, shad.sha.u);

/* Define bitcoin_outpoint_eq */
STRUCTEQ_DEF(bitcoin_outpoint, 0, txid.shad.sha.u, n);

struct bitcoin_tx {
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

struct bitcoin_tx_output *new_tx_output(const tal_t *ctx,
					struct amount_sat amount,
					const u8 *script);

/* SHA256^2 the tx in legacy format. */
void bitcoin_txid(const struct bitcoin_tx *tx, struct bitcoin_txid *txid);
void wally_txid(const struct wally_tx *wtx, struct bitcoin_txid *txid);

/* Linear bytes of tx. */
u8 *linearize_tx(const tal_t *ctx, const struct bitcoin_tx *tx);
u8 *linearize_wtx(const tal_t *ctx, const struct wally_tx *wtx);

/* Get weight of tx in Sipa; assumes it will have witnesses! */
size_t bitcoin_tx_weight(const struct bitcoin_tx *tx);
size_t wally_tx_weight(const struct wally_tx *wtx);

/* Allocate a tx: you just need to fill in inputs and outputs (they're
 * zeroed with inputs' sequence_number set to FFFFFFFF) */
struct bitcoin_tx *bitcoin_tx(const tal_t *ctx,
			      const struct chainparams *chainparams,
			      varint_t input_count, varint_t output_count,
			      u32 nlocktime);

/* Make a (deep) copy */
struct bitcoin_tx *clone_bitcoin_tx(const tal_t *ctx,
				    const struct bitcoin_tx *tx TAKES);

/* This takes a raw bitcoin tx in hex. */
struct bitcoin_tx *bitcoin_tx_from_hex(const tal_t *ctx, const char *hex,
				       size_t hexlen);

/* Parse hex string to get txid (reversed, a-la bitcoind). */
bool bitcoin_txid_from_hex(const char *hexstr, size_t hexstr_len,
			   struct bitcoin_txid *txid);

/* Get hex string of txid (reversed, a-la bitcoind). */
bool bitcoin_txid_to_hex(const struct bitcoin_txid *txid,
			 char *hexstr, size_t hexstr_len);

/* Create a bitcoin_tx from a psbt */
struct bitcoin_tx *bitcoin_tx_with_psbt(const tal_t *ctx, struct wally_psbt *psbt);

/* Internal de-linearization functions. */
/* Pull a bitcoin tx, and create a PSBT wrapper for it */
struct bitcoin_tx *pull_bitcoin_tx(const tal_t *ctx,
				   const u8 **cursor, size_t *max);

/* Pull a bitcoin tx without creating a PSBT wrapper for it */
struct bitcoin_tx *pull_bitcoin_tx_only(const tal_t *ctx,
					const u8 **cursor, size_t *max);

/* Helper to create a wally_tx_output: make sure to wally_tx_output_free!
 * Returns NULL if amount is extreme (wally doesn't like).
 */
struct wally_tx_output *wally_tx_output(const tal_t *ctx,
					const u8 *script,
					struct amount_sat amount);

/* Add one output to tx. */
int bitcoin_tx_add_output(struct bitcoin_tx *tx, const u8 *script,
			  const u8 *wscript,
			  struct amount_sat amount);

/* Remove one output. */
void bitcoin_tx_remove_output(struct bitcoin_tx *tx, size_t outnum);

/* Set the locktime for a transaction */
void bitcoin_tx_set_locktime(struct bitcoin_tx *tx, u32 locktime);

/* Add a new input to a bitcoin tx.
 *
 * For P2WSH inputs, we'll also store the wscript and/or scriptPubkey
 * Passing in just the {input_wscript}, we'll generate the scriptPubkey for you.
 * In some cases we may not have the wscript, in which case the scriptPubkey
 * should be provided. We'll check that it's P2WSH before saving it */
int bitcoin_tx_add_input(struct bitcoin_tx *tx,
			 const struct bitcoin_outpoint *outpoint,
			 u32 sequence, const u8 *scriptSig,
			 struct amount_sat amount, const u8 *scriptPubkey,
			 const u8 *input_wscript);

/* This is useful because wally uses a raw byte array for txids */
bool wally_tx_input_spends(const struct wally_tx_input *input,
			   const struct bitcoin_outpoint *outpoint);

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
 * Helper to get a witness script for an output.
 */
u8 *bitcoin_tx_output_get_witscript(const tal_t *ctx, const struct bitcoin_tx *tx, int outnum);

/** bitcoin_tx_output_get_amount_sat - Helper to get transaction output's amount
 *
 * Internally we use a `wally_tx` to represent the transaction. The
 * satoshi amount isn't a struct amount_sat, so we need a conversion
 */
void bitcoin_tx_output_get_amount_sat(const struct bitcoin_tx *tx, int outnum,
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
 * Wrap the raw txhash in the wally_tx_input into a bitcoin_txid
 */
void bitcoin_tx_input_get_outpoint(const struct bitcoin_tx *tx,
				   int innum,
				   struct bitcoin_outpoint *outpoint);

void bitcoin_tx_input_get_txid(const struct bitcoin_tx *tx, int innum,
			       struct bitcoin_txid *out);
void wally_tx_input_get_txid(const struct wally_tx_input *in,
			     struct bitcoin_txid *txid);

void wally_tx_input_get_outpoint(const struct wally_tx_input *in,
				 struct bitcoin_outpoint *outpoint);

/**
 * Overwrite the txhash and index in the wally_tx_input
 */
void bitcoin_tx_input_set_outpoint(struct bitcoin_tx *tx, int innum,
				   const struct bitcoin_outpoint *outpoint);

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
bool elements_wtx_output_is_fee(const struct wally_tx *tx, int outnum);

/**
 * Returns true if the given outnum is a fee output
 */
bool elements_tx_output_is_fee(const struct bitcoin_tx *tx, int outnum);

/** Attempt to compute the elements overhead given a base bitcoin size.
 *
 * The overhead consists of 2 empty proofs for the transaction, 6 bytes of
 * proofs per input and 35 bytes per output. In addition the explicit fee
 * output will add 9 bytes and the per output overhead as well.
 */
static inline size_t elements_tx_overhead(const struct chainparams *chainparams,
					  size_t incount, size_t outcount)
{
	size_t overhead;

	if (!chainparams->is_elements)
		return 0;

	/* Each transaction has surjection and rangeproof (both empty
	 * for us as long as we use unblinded L-BTC transactions). */
	overhead = 2 * 4;
	/* For elements we also need to add the fee output and the
	 * overhead for rangeproofs into the mix. */
	overhead += (8 + 1) * 4; /* Bitcoin style output */

	/* All outputs have a bit of elements overhead (incl fee) */
	overhead += (32 + 1 + 1 + 1) * 4 * (outcount + 1); /* Elements added fields */

	/* Inputs have 6 bytes of blank proofs attached. */
	overhead += 6 * incount;

	return overhead;
}

/**
 * Calculate the fees for this transaction
 */
struct amount_sat bitcoin_tx_compute_fee(const struct bitcoin_tx *tx);

/**
 * Calculate the feerate for this transaction (in perkw)
*/
u32 tx_feerate(const struct bitcoin_tx *tx);


/*
 * Calculate the fees for this transaction, given a pre-computed input balance.
 *
 * This is needed for cases where the transaction's psbt metadata isn't properly filled
 * in typically due to being instantiated from a tx hex (i.e. from a block scan)
 */
struct amount_sat bitcoin_tx_compute_fee_w_inputs(const struct bitcoin_tx *tx,
						  struct amount_sat input_val);

/* Wire marshalling and unmarshalling */
void fromwire_bitcoin_txid(const u8 **cursor, size_t *max,
			   struct bitcoin_txid *txid);
struct bitcoin_tx *fromwire_bitcoin_tx(const tal_t *ctx,
				       const u8 **cursor, size_t *max);
void towire_bitcoin_txid(u8 **pptr, const struct bitcoin_txid *txid);
void towire_bitcoin_tx(u8 **pptr, const struct bitcoin_tx *tx);
void towire_bitcoin_outpoint(u8 **pptr, const struct bitcoin_outpoint *outp);
void fromwire_bitcoin_outpoint(const u8 **cursor, size_t *max,
			       struct bitcoin_outpoint *outp);
char *fmt_bitcoin_tx(const tal_t *ctx, const struct bitcoin_tx *tx);
char *fmt_bitcoin_txid(const tal_t *ctx, const struct bitcoin_txid *txid);
char *fmt_bitcoin_outpoint(const tal_t *ctx,
			   const struct bitcoin_outpoint *outpoint);
char *fmt_wally_tx(const tal_t *ctx, const struct wally_tx *tx);


/* Various weights of transaction parts. */
size_t bitcoin_tx_core_weight(size_t num_inputs, size_t num_outputs);
size_t bitcoin_tx_output_weight(size_t outscript_len);

/* Weight to push sig on stack. */
size_t bitcoin_tx_input_sig_weight(void);

/* Segwit input, but with parameter for witness weight (size) */
size_t bitcoin_tx_input_weight(bool p2sh, size_t witness_weight);

/* The witness weight for a simple (sig + key) input */
size_t bitcoin_tx_simple_input_witness_weight(void);

/* We only do segwit inputs, and we assume witness is sig + key  */
size_t bitcoin_tx_simple_input_weight(bool p2sh);

/* The witness for our 2of2 input (closing or commitment tx). */
size_t bitcoin_tx_2of2_input_witness_weight(void);

/**
 * change_weight - what's the weight of a change output?
 */
size_t change_weight(void);

/**
 * change_fee - what's the cost to add a change output to this tx?
 * @feerate_perkw: feerate.
 * @total_weight: current weight of tx.
 *
 * We pass in the total_weight of the tx (up until this point) so as
 * to avoid any off-by-one errors with rounding the change fee (down)
 */
struct amount_sat change_fee(u32 feerate_perkw,	size_t total_weight);

/**
 * change_amount - Is it worth making a change output at this feerate?
 * @excess: input amount we have above the tx fee and other outputs.
 * @feerate_perkw: feerate.
 * @total_weight: current weight of tx.
 *
 * Change script is P2TR for Bitcoin, P2WPKH for Elements
 *
 * If it's not worth (or possible) to make change, returns AMOUNT_SAT(0).
 * Otherwise returns the amount of the change output to add (@excess minus
 * the change_fee()).
 */
struct amount_sat change_amount(struct amount_sat excess, u32 feerate_perkw,
				size_t total_weight);

#endif /* LIGHTNING_BITCOIN_TX_H */
