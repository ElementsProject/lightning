#include "tx.h"
#include <assert.h>
#include <ccan/cast/cast.h>
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/endian/endian.h>
#include <ccan/mem/mem.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/str/hex/hex.h>
#include <stdio.h>

#define SEGREGATED_WITNESS_FLAG 0x1

static void add_varint(varint_t v,
		       void (*add)(const void *, size_t, void *), void *addp)
{
	u8 buf[9], *p = buf;

	if (v < 0xfd) {
		*(p++) = v;
	} else if (v <= 0xffff) {
		(*p++) = 0xfd;
		(*p++) = v;
		(*p++) = v >> 8;
	} else if (v <= 0xffffffff) {
		(*p++) = 0xfe;
		(*p++) = v;
		(*p++) = v >> 8;
		(*p++) = v >> 16;
		(*p++) = v >> 24;
	} else {
		(*p++) = 0xff;
		(*p++) = v;
		(*p++) = v >> 8;
		(*p++) = v >> 16;
		(*p++) = v >> 24;
		(*p++) = v >> 32;
		(*p++) = v >> 40;
		(*p++) = v >> 48;
		(*p++) = v >> 56;
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

/* BIP 141:
 * It is followed by stack items, with each item starts with a var_int
 * to indicate the length. */
static void add_witness(const u8 *witness, 
			void (*add)(const void *, size_t, void *), void *addp)
{
	add_varint(tal_count(witness), add, addp);
	add(witness, tal_count(witness), addp);
}

/* BIP144:
 * If the witness is empty, the old serialization format should be used. */
static bool uses_witness(const struct bitcoin_tx *tx)
{
	size_t i;

	for (i = 0; i < tx->input_count; i++) {
		if (tx->input[i].witness)
			return true;
	}
	return false;
}

static void add_tx(const struct bitcoin_tx *tx,
		   void (*add)(const void *, size_t, void *), void *addp,
		   bool extended)
{
	varint_t i;
	u8 flag = 0;

	add_le32(tx->version, add, addp);

	if (extended) {
		u8 marker;
		/* BIP 144 */
		/* marker 	char 	Must be zero */
		/* flag 	char 	Must be nonzero */
		marker = 0;
		add(&marker, 1, addp);
		/* BIP 141: The flag MUST be a 1-byte non-zero
		 * value. Currently, 0x01 MUST be used.
		 *
		 * BUT: Current segwit4 branch breaks fundrawtransaction;
		 * it sees 0 inputs and thinks it's extended format.
		 * Make it really an extended format, but without
		 * witness. */
		if (uses_witness(tx))
			flag = SEGREGATED_WITNESS_FLAG;
		add(&flag, 1, addp);
	}

	add_varint(tx->input_count, add, addp);
	for (i = 0; i < tx->input_count; i++)
		add_tx_input(&tx->input[i], add, addp);

	add_varint(tx->output_count, add, addp);
	for (i = 0; i < tx->output_count; i++)
		add_tx_output(&tx->output[i], add, addp);

	if (flag & SEGREGATED_WITNESS_FLAG) {
		/* BIP 141:
		 * The witness is a serialization of all witness data
		 * of the transaction. Each txin is associated with a
		 * witness field. A witness field starts with a
		 * var_int to indicate the number of stack items for
		 * the txin.  */
		for (i = 0; i < tx->input_count; i++) {
			size_t j, elements;

			/* Not every input needs a witness. */
			if (!tx->input[i].witness) {
				add_varint(0, add, addp);
				continue;
			}
			elements = tal_count(tx->input[i].witness);
			add_varint(elements, add, addp);
			for (j = 0;
			     j < tal_count(tx->input[i].witness);
			     j++) {
				add_witness(tx->input[i].witness[j],
					    add, addp);
			}
		}
	}
	add_le32(tx->lock_time, add, addp);
}

static void add_sha(const void *data, size_t len, void *shactx_)
{
	struct sha256_ctx *ctx = shactx_;
	sha256_update(ctx, memcheck(data, len), len);
}

void sha256_tx_for_sig(struct sha256_ctx *ctx, const struct bitcoin_tx *tx,
		       unsigned int input_num)
{
	size_t i;

	/* Caller should zero-out other scripts for signing! */
	assert(input_num < tx->input_count);
	for (i = 0; i < tx->input_count; i++)
		if (i != input_num)
			assert(tx->input[i].script_length == 0);
	add_tx(tx, add_sha, ctx, false);
}

static void add_linearize(const void *data, size_t len, void *pptr_)
{
	u8 **pptr = pptr_;
	size_t oldsize = tal_count(*pptr);

	tal_resize(pptr, oldsize + len);
	memcpy(*pptr + oldsize, memcheck(data, len), len);
}

u8 *linearize_tx(const tal_t *ctx, const struct bitcoin_tx *tx)
{
	u8 *arr = tal_arr(ctx, u8, 0);
	add_tx(tx, add_linearize, &arr, uses_witness(tx));
	return arr;
}

u8 *linearize_tx_force_extended(const tal_t *ctx,
				const struct bitcoin_tx *tx)
{
	u8 *arr = tal_arr(ctx, u8, 0);
	add_tx(tx, add_linearize, &arr, true);
	return arr;
}

void bitcoin_txid(const struct bitcoin_tx *tx, struct sha256_double *txid)
{
	struct sha256_ctx ctx = SHA256_INIT;

	/* For TXID, we never use extended form. */
	add_tx(tx, add_sha, &ctx, false);
	sha256_double_done(&ctx, txid);
}

struct bitcoin_tx *bitcoin_tx(const tal_t *ctx, varint_t input_count,
			      varint_t output_count)
{
	struct bitcoin_tx *tx = tal(ctx, struct bitcoin_tx);
	size_t i;

	tx->output_count = output_count;
	tx->output = tal_arrz(tx, struct bitcoin_tx_output, output_count);
	tx->input_count = input_count;
	tx->input = tal_arrz(tx, struct bitcoin_tx_input, input_count);
	for (i = 0; i < tx->input_count; i++) {
		/* We assume NULL is a zero bitmap */
		assert(tx->input[i].script == NULL);
		tx->input[i].sequence_number = 0xFFFFFFFF;
		tx->input[i].amount = NULL;
		tx->input[i].witness = NULL;
	}
	tx->lock_time = 0;
#if HAS_BIP68
	tx->version = 2;
#else
	tx->version = 1;
#endif
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
	return memcheck(p, n);
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
		ret = ((u64)p[1] << 8) + p[0];
	} else if (*p == 0xfe) {
		p = pull(cursor, max, NULL, 4);
		if (!p)
			return 0;
		ret = ((u64)p[3] << 24) + ((u64)p[2] << 16)
			+ ((u64)p[1] << 8) + p[0];
	} else {
		p = pull(cursor, max, NULL, 8);
		if (!p)
			return 0;
		ret = ((u64)p[7] << 56) + ((u64)p[6] << 48)
			+ ((u64)p[5] << 40) + ((u64)p[4] << 32)
			+ ((u64)p[3] << 24) + ((u64)p[2] << 16)
			+ ((u64)p[1] << 8) + p[0];
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

static u64 pull_value(const u8 **cursor, size_t *max)
{
	u64 amount;

	amount = pull_le64(cursor, max);
	return amount;
}

/* Pulls a varint which specifies a data length: ensures basic sanity to
 * avoid trivial OOM */
static u64 pull_length(const u8 **cursor, size_t *max)
{
	u64 v = pull_varint(cursor, max);
	if (v > *max) {
		*cursor = NULL;
		*max = 0;
		return 0;
	}
	return v;
}
	
static void pull_input(const tal_t *ctx, const u8 **cursor, size_t *max,
		       struct bitcoin_tx_input *input)
{
	pull_sha256_double(cursor, max, &input->txid);
	input->index = pull_le32(cursor, max);
	input->script_length = pull_length(cursor, max);
	input->script = tal_arr(ctx, u8, input->script_length);
	pull(cursor, max, input->script, input->script_length);
	input->sequence_number = pull_le32(cursor, max);
}

static void pull_output(const tal_t *ctx, const u8 **cursor, size_t *max,
			struct bitcoin_tx_output *output)
{
	output->amount = pull_value(cursor, max);
	output->script_length = pull_length(cursor, max);
	output->script = tal_arr(ctx, u8, output->script_length);
	pull(cursor, max, output->script, output->script_length);
}

static u8 *pull_witness_item(const tal_t *ctx, const u8 **cursor, size_t *max)
{
	uint64_t len = pull_length(cursor, max);
	u8 *item;

	item = tal_arr(ctx, u8, len);
	pull(cursor, max, item, len);
	return item;
}

static void pull_witness(struct bitcoin_tx_input *inputs, size_t i,
			 const u8 **cursor, size_t *max)
{
	uint64_t j, num = pull_length(cursor, max);

	/* 0 means not using witness. */
	if (num == 0) {
		inputs[i].witness = NULL;
		return;
	}

	inputs[i].witness = tal_arr(inputs, u8 *, num);
	for (j = 0; j < num; j++) {
		inputs[i].witness[j] = pull_witness_item(inputs[i].witness, 
							 cursor, max);
	}
}

static struct bitcoin_tx *pull_bitcoin_tx(const tal_t *ctx,
					  const u8 **cursor, size_t *max)
{
	struct bitcoin_tx *tx = tal(ctx, struct bitcoin_tx);
	size_t i;
	u8 flag = 0;

	tx->version = pull_le32(cursor, max);
	tx->input_count = pull_length(cursor, max);
	/* BIP 144 marker is 0 (impossible to have tx with 0 inputs) */
	if (tx->input_count == 0) {
		pull(cursor, max, &flag, 1);
		if (flag != SEGREGATED_WITNESS_FLAG)
			return tal_free(tx);
		tx->input_count = pull_length(cursor, max);
	}

	tx->input = tal_arr(tx, struct bitcoin_tx_input, tx->input_count);
	for (i = 0; i < tx->input_count; i++)
		pull_input(tx, cursor, max, tx->input + i);

	tx->output_count = pull_length(cursor, max);
	tx->output = tal_arr(tx, struct bitcoin_tx_output, tx->output_count);
	for (i = 0; i < tx->output_count; i++)
		pull_output(tx, cursor, max, tx->output + i);

	if (flag & SEGREGATED_WITNESS_FLAG) {
		for (i = 0; i < tx->input_count; i++)
			pull_witness(tx->input, i, cursor, max);
	} else {
		for (i = 0; i < tx->input_count; i++)
			tx->input[i].witness = NULL;
	}
	tx->lock_time = pull_le32(cursor, max);

	/* If we ran short, or have bytes left over, fail. */
	if (!*cursor || *max != 0)
		tx = tal_free(tx);
	return tx;
}

struct bitcoin_tx *bitcoin_tx_from_hex(const tal_t *ctx, const char *hex,
				       size_t hexlen)
{
	char *end;
	u8 *linear_tx;
	const u8 *p;
	struct bitcoin_tx *tx;
	size_t len;

	end = memchr(hex, '\n', hexlen);
	if (!end)
		end = cast_const(char *, hex) + hexlen;

	len = hex_data_size(end - hex);
	p = linear_tx = tal_arr(ctx, u8, len);
	if (!hex_decode(hex, end - hex, linear_tx, len))
		goto fail;

	tx = pull_bitcoin_tx(ctx, &p, &len);
	if (!tx)
		goto fail;

	if (end != hex + hexlen && *end != '\n')
		goto fail_free_tx;

	tal_free(linear_tx);
	return tx;

fail_free_tx:
	tal_free(tx);
fail:
	tal_free(linear_tx);
	return NULL;
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

bool bitcoin_txid_to_hex(const struct sha256_double *txid,
			 char *hexstr, size_t hexstr_len)
{
	struct sha256_double rev = *txid;
	reverse_bytes(rev.sha.u.u8, sizeof(rev.sha.u.u8));
	return hex_encode(&rev, sizeof(rev), hexstr, hexstr_len);
}
