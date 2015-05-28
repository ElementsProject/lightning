#ifndef LIGHTNING_BITCOIN_TX_H
#define LIGHTNING_BITCOIN_TX_H
#include <ccan/short_types/short_types.h>
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

/* Linearize the tx.  This is good for deriving the txid, as well as the
 * signature. */
void sha256_tx(struct sha256_ctx *shactx, const struct bitcoin_tx *tx);

#endif /* LIGHTNING_BITCOIN_TX_H */
