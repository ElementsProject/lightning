#include "bitcoin_tx.h"
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/err/err.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/str/hex/hex.h>
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

/* Sets *cursor to NULL and returns NULL when a pull fails. */
static const u8 *pull(const u8 **cursor, size_t *max, void *copy, size_t n)
{
	const u8 *p = *cursor;

	if (*max < n) {
		*cursor = NULL;
		*max = 0;
		/* Just make sure we don't leak uninitialized mem! */
		if (copy)
			memset(copy, 0, n);
		return NULL;
	}
	*cursor += n;
	*max -= n;
	if (copy)
		memcpy(copy, p, n);
	return p;
}

static u64 pull_varint(const u8 **cursor, size_t *max)
{
	u64 ret;
	const u8 *p;

	p = pull(cursor, max, NULL, 1);
	if (!p)
		return 0;

	if (*p < 0xfd) {
		ret = *p;
	} else if (*p == 0xfd) {
		p = pull(cursor, max, NULL, 2);
		if (!p)
			return 0;
		ret = ((u64)p[2] << 8) + p[1];
	} else if (*p == 0xfe) {
		p = pull(cursor, max, NULL, 4);
		if (!p)
			return 0;
		ret = ((u64)p[4] << 24) + ((u64)p[3] << 16)
			+ ((u64)p[2] << 8) + p[1];
	} else {
		p = pull(cursor, max, NULL, 8);
		if (!p)
			return 0;
		ret = ((u64)p[8] << 56) + ((u64)p[7] << 48)
			+ ((u64)p[6] << 40) + ((u64)p[5] << 32)
			+ ((u64)p[4] << 24) + ((u64)p[3] << 16)
			+ ((u64)p[2] << 8) + p[1];
	}
	return ret;
}

static u32 pull_le32(const u8 **cursor, size_t *max)
{
	le32 ret;

	if (!pull(cursor, max, &ret, sizeof(ret)))
		return 0;
	return le32_to_cpu(ret);
}

static u64 pull_le64(const u8 **cursor, size_t *max)
{
	le64 ret;

	if (!pull(cursor, max, &ret, sizeof(ret)))
		return 0;
	return le64_to_cpu(ret);
}

static bool pull_sha256_double(const u8 **cursor, size_t *max,
			       struct sha256_double *h)
{
	return pull(cursor, max, h, sizeof(*h));
}

static void pull_input(const tal_t *ctx, const u8 **cursor, size_t *max,
		       struct bitcoin_tx_input *input)
{
	pull_sha256_double(cursor, max, &input->txid);
	input->index = pull_le32(cursor, max);
	input->script_length = pull_varint(cursor, max);
	input->script = tal_arr(ctx, u8, input->script_length);
	pull(cursor, max, input->script, input->script_length);
	input->sequence_number = pull_le32(cursor, max);
}

static void pull_output(const tal_t *ctx, const u8 **cursor, size_t *max,
			struct bitcoin_tx_output *output)
{
	output->amount = pull_le64(cursor, max);
	output->script_length = pull_varint(cursor, max);
	output->script = tal_arr(ctx, u8, output->script_length);
	pull(cursor, max, output->script, output->script_length);
}

static struct bitcoin_tx *pull_bitcoin_tx(const tal_t *ctx,
					  const u8 **cursor, size_t *max)
{
	struct bitcoin_tx *tx = tal(ctx, struct bitcoin_tx);
	size_t i;

	tx->version = pull_le32(cursor, max);
	tx->input_count = pull_varint(cursor, max);
	tx->input = tal_arr(tx, struct bitcoin_tx_input, tx->input_count);
	for (i = 0; i < tx->input_count; i++)
		pull_input(tx, cursor, max, tx->input + i);
	tx->output_count = pull_varint(cursor, max);
	tx->output = tal_arr(ctx, struct bitcoin_tx_output, tx->output_count);
	for (i = 0; i < tx->output_count; i++)
		pull_output(tx, cursor, max, tx->output + i);
	tx->lock_time = pull_le32(cursor, max);

	/* If we ran short, or have bytes left over, fail. */
	if (!*cursor || *max != 0)
		tx = tal_free(tx);
	return tx;
}

struct bitcoin_tx *bitcoin_tx_from_file(const tal_t *ctx,
					const char *filename)
{
	char *hex;
	u8 *linear_tx;
	const u8 *p;
	struct bitcoin_tx *tx;
	size_t len;

	/* Grabs file, add nul at end. */
	hex = grab_file(ctx, filename);
	if (!hex)
		err(1, "Opening %s", filename);

	len = hex_data_size(tal_count(hex)-1);
	p = linear_tx = tal_arr(hex, u8, len);
	if (!hex_decode(hex, tal_count(hex)-1, linear_tx, len))
		errx(1, "Bad hex string in %s", filename);

	tx = pull_bitcoin_tx(ctx, &p, &len);
	if (!tx)
		errx(1, "Bad transaction in %s", filename);
	tal_free(hex);

	return tx;
}

/* <sigh>.  Bitcoind represents hashes as little-endian for RPC.  This didn't
 * stick for blockids (everyone else uses big-endian, eg. block explorers),
 * but it did stick for txids. */
static void reverse_bytes(u8 *arr, size_t len)
{
	unsigned int i;

	for (i = 0; i < len / 2; i++) {
		unsigned char tmp = arr[i];
		arr[i] = arr[len - 1 - i];
		arr[len - 1 - i] = tmp;
	}
}

bool bitcoin_txid_from_hex(const char *hexstr, size_t hexstr_len,
			   struct sha256_double *txid)
{
	if (!hex_decode(hexstr, hexstr_len, txid, sizeof(*txid)))
		return false;
	reverse_bytes(txid->sha.u.u8, sizeof(txid->sha.u.u8));
	return true;
}
	
