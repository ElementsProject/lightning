#ifndef LIGHTNING_BITCOIN_TX_H
#define LIGHTNING_BITCOIN_TX_H
#include "config.h"
#include "shadouble.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

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

	/* Value of the output we're spending (NULL if unknown). */
	u64 *amount;

	/* Only if BIP141 used. */
	u8 **witness;
};


/* SHA256^2 the tx: simpler than sha256_tx */
void bitcoin_txid(const struct bitcoin_tx *tx, struct sha256_double *txid);

/* Useful for signature code. */
void sha256_tx_for_sig(struct sha256_ctx *ctx, const struct bitcoin_tx *tx,
		       unsigned int input_num);

/* Linear bytes of tx. */
u8 *linearize_tx(const tal_t *ctx, const struct bitcoin_tx *tx);

/* Force linearization in extended form; useful if 0 inputs. */
u8 *linearize_tx_force_extended(const tal_t *ctx,
				const struct bitcoin_tx *tx);

/* Allocate a tx: you just need to fill in inputs and outputs (they're
 * zeroed with inputs' sequence_number set to FFFFFFFF) */
struct bitcoin_tx *bitcoin_tx(const tal_t *ctx, varint_t input_count,
			      varint_t output_count);

/* This takes a raw bitcoin tx in hex. */
struct bitcoin_tx *bitcoin_tx_from_hex(const tal_t *ctx, const char *hex,
				       size_t hexlen);

/* Parse hex string to get txid (reversed, a-la bitcoind). */
bool bitcoin_txid_from_hex(const char *hexstr, size_t hexstr_len,
			   struct sha256_double *txid);

/* Get hex string of txid (reversed, a-la bitcoind). */
bool bitcoin_txid_to_hex(const struct sha256_double *txid,
			 char *hexstr, size_t hexstr_len);

#endif /* LIGHTNING_BITCOIN_TX_H */
