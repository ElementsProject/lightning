#ifndef LIGHTNING_BITCOIN_TX_H
#define LIGHTNING_BITCOIN_TX_H
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include "shadouble.h"

#define BITCOIN_TX_VERSION 1

/* We unpack varints for our in-memory representation */
#define varint_t u64

struct bitcoin_tx {
	u32 version;
	varint_t input_count;
	struct bitcoin_tx_input *input;
	varint_t output_count;
	struct bitcoin_tx_output *output;
	u32 lock_time;
};

struct bitcoin_tx_output {
	u64 amount;
	varint_t script_length;
	u8 *script;
};

struct bitcoin_tx_input {
	struct sha256_double txid;
	u32 index; /* output number referred to by above */
	varint_t script_length;
	u8 *script;
	u32 sequence_number;
};


/* SHA256^2 the tx: simpler than sha256_tx */
void bitcoin_txid(const struct bitcoin_tx *tx, struct sha256_double *txid);

/* Useful for signature code. */
void sha256_tx(struct sha256_ctx *ctx, const struct bitcoin_tx *tx);

/* Linear bytes of tx. */
u8 *linearize_tx(const tal_t *ctx, const struct bitcoin_tx *tx);

/* Allocate a tx: you just need to fill in inputs and outputs (they're
 * zeroed with inputs' sequence_number set to FFFFFFFF) */
struct bitcoin_tx *bitcoin_tx(const tal_t *ctx, varint_t input_count,
			      varint_t output_count);

struct bitcoin_tx *bitcoin_tx_from_file(const tal_t *ctx,
					const char *filename);

#endif /* LIGHTNING_BITCOIN_TX_H */
