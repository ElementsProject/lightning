#include "bitcoin_tx.h"
#include <ccan/crypto/sha256/sha256.h>
#include <assert.h>

static void sha256_varint(struct sha256_ctx *ctx, varint_t v)
{
	u8 buf[9], *p = buf;

	if (v < 0xfd) {
		*(p++) = v;
	} else if (v <= 0xffff) {
		(*p++) = 0xfd;
		(*p++) = v >> 8;
		(*p++) = v;
	} else if (v <= 0xffffffff) {
		(*p++) = 0xfe;
		(*p++) = v >> 24;
		(*p++) = v >> 16;
		(*p++) = v >> 8;
		(*p++) = v;
	} else {
		(*p++) = 0xff;
		(*p++) = v >> 56;
		(*p++) = v >> 48;
		(*p++) = v >> 40;
		(*p++) = v >> 32;
		(*p++) = v >> 24;
		(*p++) = v >> 16;
		(*p++) = v >> 8;
		(*p++) = v;
	}
	sha256_update(ctx, buf, p - buf);
}

static void sha256_tx_input(struct sha256_ctx *ctx,
			    const struct bitcoin_tx_input *input)
{
	sha256_update(ctx, &input->txid, sizeof(input->txid));
	sha256_le32(ctx, input->index);
	sha256_varint(ctx, input->script_length);
	sha256_update(ctx, input->script, input->script_length);
	sha256_le32(ctx, input->sequence_number);
}

static void sha256_tx_output(struct sha256_ctx *ctx,
			     const struct bitcoin_tx_output *output)
{
	sha256_le64(ctx, output->amount);
	sha256_varint(ctx, output->script_length);
	sha256_update(ctx, output->script, output->script_length);
}

void sha256_tx(struct sha256_ctx *ctx, const struct bitcoin_tx *tx)
{
	varint_t i;

	sha256_le32(ctx, tx->version);
	sha256_varint(ctx, tx->input_count);
	for (i = 0; i < tx->input_count; i++)
		sha256_tx_input(ctx, &tx->input[i]);
	sha256_varint(ctx, tx->output_count);
	for (i = 0; i < tx->output_count; i++)
		sha256_tx_output(ctx, &tx->output[i]);
	sha256_le32(ctx, tx->lock_time);
}

void bitcoin_txid(const struct bitcoin_tx *tx, struct sha256_double *txid)
{
	struct sha256_ctx ctx = SHA256_INIT;

	sha256_tx(&ctx, tx);
	sha256_double_done(&ctx, txid);
}

struct bitcoin_tx *bitcoin_tx(const tal_t *ctx, varint_t input_count,
			      varint_t output_count)
{
	struct bitcoin_tx *tx = tal(ctx, struct bitcoin_tx);
	size_t i;

	tx->version = BITCOIN_TX_VERSION;
	tx->output_count = output_count;
	tx->output = tal_arrz(tx, struct bitcoin_tx_output, output_count);
	tx->input_count = input_count;
	tx->input = tal_arrz(tx, struct bitcoin_tx_input, input_count);
	for (i = 0; i < tx->input_count; i++) {
		/* We assume NULL is a zero bitmap */
		assert(tx->input[i].script == NULL);
		tx->input[i].sequence_number = 0xFFFFFFFF;
	}
	tx->lock_time = 0xFFFFFFFF;

	return tx;
}
