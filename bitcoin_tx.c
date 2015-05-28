#include "bitcoin_tx.h"
#include <ccan/crypto/sha256/sha256.h>

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
