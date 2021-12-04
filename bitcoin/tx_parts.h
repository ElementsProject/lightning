/* This represents a specific part of a transaction, without including
 * all the metadata (which we might not know, if we didn't make the
 * transction ourselves). */
#ifndef LIGHTNING_BITCOIN_TX_PARTS_H
#define LIGHTNING_BITCOIN_TX_PARTS_H
#include "config.h"
#include <bitcoin/tx.h>

struct tx_parts {
	/* The txid of this transacation */
	struct bitcoin_txid txid;
	/* A subset of inputs: NULL means it's not included. */
	struct wally_tx_input **inputs;
	/* A subset of outputs: NULL means it's not included. */
	struct wally_tx_output **outputs;
};

/* Initialize this from a wally_tx: input/output == -1 for all,
 * otherwise the input/output number to include.  */
struct tx_parts *tx_parts_from_wally_tx(const tal_t *ctx,
					const struct wally_tx *wtx,
					int input, int output);

/* Wire marshalling and unmarshalling */
struct tx_parts *fromwire_tx_parts(const tal_t *ctx,
				   const u8 **cursor, size_t *max);
void towire_tx_parts(u8 **pptr, const struct tx_parts *tx_parts);
#endif /* LIGHTNING_BITCOIN_TX_PARTS_H */
