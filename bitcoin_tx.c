#include "bitcoin_tx.h"
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/endian/endian.h>
#include <assert.h>

static void add_varint(varint_t v,
		       void (*add)(const void *, size_t, void *), void *addp)
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
	add(buf, p - buf, addp);
}

static void add_le32(u32 v,
		     void (*add)(const void *, size_t, void *), void *addp)
{
	le32 l = cpu_to_le32(v);
	add(&l, sizeof(l), addp);
}

static void add_le64(u64 v,
		     void (*add)(const void *, size_t, void *), void *addp)
{
	le64 l = cpu_to_le64(v);
	add(&l, sizeof(l), addp);
}

static void add_tx_input(const struct bitcoin_tx_input *input,
			 void (*add)(const void *, size_t, void *), void *addp)
{
	add(&input->txid, sizeof(input->txid), addp);
	add_le32(input->index, add, addp);
	add_varint(input->script_length, add, addp);
	add(input->script, input->script_length, addp);
	add_le32(input->sequence_number, add, addp);
}

static void add_tx_output(const struct bitcoin_tx_output *output,
			  void (*add)(const void *, size_t, void *), void *addp)
{
	add_le64(output->amount, add, addp);
	add_varint(output->script_length, add, addp);
	add(output->script, output->script_length, addp);
}

static void add_tx(const struct bitcoin_tx *tx,
		   void (*add)(const void *, size_t, void *), void *addp)
{
	varint_t i;

	add_le32(tx->version, add, addp);
	add_varint(tx->input_count, add, addp);
	for (i = 0; i < tx->input_count; i++)
		add_tx_input(&tx->input[i], add, addp);
	add_varint(tx->output_count, add, addp);
	for (i = 0; i < tx->output_count; i++)
		add_tx_output(&tx->output[i], add, addp);
	add_le32(tx->lock_time, add, addp);
}

static void add_sha(const void *data, size_t len, void *shactx_)
{
	struct sha256_ctx *ctx = shactx_;
	sha256_update(ctx, data, len);
}

void sha256_tx(struct sha256_ctx *ctx, const struct bitcoin_tx *tx)
{
	add_tx(tx, add_sha, ctx);
}

static void add_linearize(const void *data, size_t len, void *pptr_)
{
	u8 **pptr = pptr_;
	size_t oldsize = tal_count(*pptr);

	tal_resize(pptr, oldsize + len);
	memcpy(*pptr + oldsize, data, len);
}

u8 *linearize_tx(const tal_t *ctx, const struct bitcoin_tx *tx)
{
	u8 *arr = tal_arr(ctx, u8, 0);
	add_tx(tx, add_linearize, &arr);
	return arr;
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
