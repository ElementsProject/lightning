#include <assert.h>
#include <bitcoin/block.h>
#include <bitcoin/pullpush.h>
#include <bitcoin/tx.h>
#include <ccan/cast/cast.h>
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/endian/endian.h>
#include <ccan/mem/mem.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/str/hex/hex.h>
#include <common/type_to_string.h>
#include <stdio.h>

#define SEGREGATED_WITNESS_FLAG 0x1

static void push_tx_input(const struct bitcoin_tx_input *input,
			 void (*push)(const void *, size_t, void *), void *pushp)
{
	push(&input->txid, sizeof(input->txid), pushp);
	push_le32(input->index, push, pushp);
	push_varint_blob(input->script, push, pushp);
	push_le32(input->sequence_number, push, pushp);
}

static void push_tx_output(const struct bitcoin_tx_output *output,
			  void (*push)(const void *, size_t, void *), void *pushp)
{
	push_le64(output->amount, push, pushp);
	push_varint_blob(output->script, push, pushp);
}

/* BIP 141:
 * It is followed by stack items, with each item starts with a var_int
 * to indicate the length. */
static void push_witness(const u8 *witness,
			void (*push)(const void *, size_t, void *), void *pushp)
{
	push_varint_blob(witness, push, pushp);
}

/* BIP144:
 * If the witness is empty, the old serialization format should be used. */
static bool uses_witness(const struct bitcoin_tx *tx)
{
	size_t i;

	for (i = 0; i < tal_count(tx->input); i++) {
		if (tx->input[i].witness)
			return true;
	}
	return false;
}

/* BIP 141: The witness is a serialization of all witness data of the
 * transaction. Each txin is associated with a witness field. A
 * witness field starts with a var_int to indicate the number of stack
 * items for the txin.  */
static void push_witnesses(const struct bitcoin_tx *tx,
			  void (*push)(const void *, size_t, void *), void *pushp)
{
	size_t i;
	for (i = 0; i < tal_count(tx->input); i++) {
		size_t j, elements;

		/* Not every input needs a witness. */
		if (!tx->input[i].witness) {
			push_varint(0, push, pushp);
			continue;
		}
		elements = tal_count(tx->input[i].witness);
		push_varint(elements, push, pushp);
		for (j = 0;
		     j < tal_count(tx->input[i].witness);
		     j++) {
			push_witness(tx->input[i].witness[j],
				    push, pushp);
		}
	}
}

static void push_tx(const struct bitcoin_tx *tx,
		   void (*push)(const void *, size_t, void *), void *pushp,
		   bool bip144)
{
	varint_t i;
	u8 flag = 0;

	push_le32(tx->version, push, pushp);

        if (bip144 && uses_witness(tx))
		flag |= SEGREGATED_WITNESS_FLAG;

	/* BIP 141: The flag MUST be a 1-byte non-zero value. */
	/* ie. if no flags set, we fallback to pre-BIP144-style */
	if (flag) {
		u8 marker = 0;
		/* BIP 144 */
		/* marker 	char 	Must be zero */
		/* flag 	char 	Must be nonzero */
		push(&marker, 1, pushp);
		push(&flag, 1, pushp);
	}

	push_varint(tal_count(tx->input), push, pushp);
	for (i = 0; i < tal_count(tx->input); i++)
		push_tx_input(&tx->input[i], push, pushp);

	push_varint(tal_count(tx->output), push, pushp);
	for (i = 0; i < tal_count(tx->output); i++)
		push_tx_output(&tx->output[i], push, pushp);

	if (flag & SEGREGATED_WITNESS_FLAG)
		push_witnesses(tx, push, pushp);

	push_le32(tx->lock_time, push, pushp);
}

static void push_sha(const void *data, size_t len, void *shactx_)
{
	struct sha256_ctx *ctx = shactx_;
	sha256_update(ctx, memcheck(data, len), len);
}

static void hash_prevouts(struct sha256_double *h, const struct bitcoin_tx *tx)
{
	struct sha256_ctx ctx;
	size_t i;

	/* BIP143: If the ANYONECANPAY flag is not set, hashPrevouts is the
	 * double SHA256 of the serialization of all input
	 * outpoints */
	sha256_init(&ctx);
	for (i = 0; i < tal_count(tx->input); i++) {
		push_sha(&tx->input[i].txid, sizeof(tx->input[i].txid), &ctx);
		push_le32(tx->input[i].index, push_sha, &ctx);
	}
	sha256_double_done(&ctx, h);
}

static void hash_sequence(struct sha256_double *h, const struct bitcoin_tx *tx)
{
	struct sha256_ctx ctx;
	size_t i;

	/* BIP143: If none of the ANYONECANPAY, SINGLE, NONE sighash type
	 * is set, hashSequence is the double SHA256 of the serialization
	 * of nSequence of all inputs */
	sha256_init(&ctx);
	for (i = 0; i < tal_count(tx->input); i++)
		push_le32(tx->input[i].sequence_number, push_sha, &ctx);

	sha256_double_done(&ctx, h);
}

/* If the sighash type is neither SINGLE nor NONE, hashOutputs is the
 * double SHA256 of the serialization of all output value (8-byte
 * little endian) with scriptPubKey (varInt for the length +
 * script); */
static void hash_outputs(struct sha256_double *h, const struct bitcoin_tx *tx)
{
	struct sha256_ctx ctx;
	size_t i;

	sha256_init(&ctx);
	for (i = 0; i < tal_count(tx->output); i++) {
		push_le64(tx->output[i].amount, push_sha, &ctx);
		push_varint_blob(tx->output[i].script, push_sha, &ctx);
	}

	sha256_double_done(&ctx, h);
}

static void hash_for_segwit(struct sha256_ctx *ctx,
			    const struct bitcoin_tx *tx,
			    unsigned int input_num,
			    const u8 *witness_script)
{
	struct sha256_double h;

	/* BIP143:
	 *
	 * Double SHA256 of the serialization of:
	 *     1. nVersion of the transaction (4-byte little endian)
	 */
	push_le32(tx->version, push_sha, ctx);

	/*     2. hashPrevouts (32-byte hash) */
	hash_prevouts(&h, tx);
	push_sha(&h, sizeof(h), ctx);

	/*     3. hashSequence (32-byte hash) */
	hash_sequence(&h, tx);
	push_sha(&h, sizeof(h), ctx);

	/*     4. outpoint (32-byte hash + 4-byte little endian)  */
	push_sha(&tx->input[input_num].txid, sizeof(tx->input[input_num].txid),
		ctx);
	push_le32(tx->input[input_num].index, push_sha, ctx);

	/*     5. scriptCode of the input (varInt for the length + script) */
	push_varint_blob(witness_script, push_sha, ctx);

	/*     6. value of the output spent by this input (8-byte little end) */
	push_le64(*tx->input[input_num].amount, push_sha, ctx);

	/*     7. nSequence of the input (4-byte little endian) */
	push_le32(tx->input[input_num].sequence_number, push_sha, ctx);

	/*     8. hashOutputs (32-byte hash) */
	hash_outputs(&h, tx);
	push_sha(&h, sizeof(h), ctx);

	/*     9. nLocktime of the transaction (4-byte little endian) */
	push_le32(tx->lock_time, push_sha, ctx);
}

void sha256_tx_for_sig(struct sha256_double *h, const struct bitcoin_tx *tx,
		       unsigned int input_num,
		       const u8 *witness_script)
{
	size_t i;
	struct sha256_ctx ctx = SHA256_INIT;

	/* Caller should zero-out other scripts for signing! */
	assert(input_num < tal_count(tx->input));
	for (i = 0; i < tal_count(tx->input); i++)
		if (i != input_num)
			assert(!tx->input[i].script);

	if (witness_script) {
		/* BIP143 hashing if OP_CHECKSIG is inside witness. */
		hash_for_segwit(&ctx, tx, input_num, witness_script);
	} else {
		/* Otherwise signature hashing never includes witness. */
		push_tx(tx, push_sha, &ctx, false);
	}

	sha256_le32(&ctx, SIGHASH_ALL);
	sha256_double_done(&ctx, h);
}

static void push_linearize(const void *data, size_t len, void *pptr_)
{
	u8 **pptr = pptr_;
	size_t oldsize = tal_count(*pptr);

	tal_resize(pptr, oldsize + len);
	memcpy(*pptr + oldsize, memcheck(data, len), len);
}

u8 *linearize_tx(const tal_t *ctx, const struct bitcoin_tx *tx)
{
	u8 *arr = tal_arr(ctx, u8, 0);
	push_tx(tx, push_linearize, &arr, true);
	return arr;
}

static void push_measure(const void *data UNUSED, size_t len, void *lenp)
{
	*(size_t *)lenp += len;
}

size_t measure_tx_weight(const struct bitcoin_tx *tx)
{
	size_t non_witness_len = 0, witness_len = 0;
	push_tx(tx, push_measure, &non_witness_len, false);
	if (uses_witness(tx)) {
		push_witnesses(tx, push_measure, &witness_len);
		/* Include BIP 144 marker and flag bytes in witness length */
		witness_len += 2;
	}

	/* Normal bytes weigh 4 times more than Witness bytes */
	return non_witness_len * 4 + witness_len;
}

void bitcoin_txid(const struct bitcoin_tx *tx, struct bitcoin_txid *txid)
{
	struct sha256_ctx ctx = SHA256_INIT;

	/* For TXID, we never use extended form. */
	push_tx(tx, push_sha, &ctx, false);
	sha256_double_done(&ctx, &txid->shad);
}

struct bitcoin_tx *bitcoin_tx(const tal_t *ctx, varint_t input_count,
			      varint_t output_count)
{
	struct bitcoin_tx *tx = tal(ctx, struct bitcoin_tx);
	size_t i;

	tx->output = tal_arrz(tx, struct bitcoin_tx_output, output_count);
	tx->input = tal_arrz(tx, struct bitcoin_tx_input, input_count);
	for (i = 0; i < tal_count(tx->input); i++) {
		/* We assume NULL is a zero bitmap */
		assert(tx->input[i].script == NULL);
		tx->input[i].sequence_number = 0xFFFFFFFF;
		tx->input[i].amount = NULL;
		tx->input[i].witness = NULL;
	}
	tx->lock_time = 0;
	tx->version = 2;
	return tx;
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

/* Pulls a varint which specifies n items of mult size: ensures basic
 * sanity to avoid trivial OOM */
static u64 pull_length(const u8 **cursor, size_t *max, size_t mult)
{
	u64 v = pull_varint(cursor, max);
	if (v * mult > *max) {
		*cursor = NULL;
		*max = 0;
		return 0;
	}
	return v;
}

static void pull_input(const tal_t *ctx, const u8 **cursor, size_t *max,
		       struct bitcoin_tx_input *input)
{
	u64 script_len;
	pull_sha256_double(cursor, max, &input->txid.shad);
	input->index = pull_le32(cursor, max);
	script_len = pull_length(cursor, max, 1);
	if (script_len)
		input->script = tal_arr(ctx, u8, script_len);
	else
		input->script = NULL;
	pull(cursor, max, input->script, tal_count(input->script));
	input->sequence_number = pull_le32(cursor, max);
}

static void pull_output(const tal_t *ctx, const u8 **cursor, size_t *max,
			struct bitcoin_tx_output *output)
{
	output->amount = pull_value(cursor, max);
	output->script = tal_arr(ctx, u8, pull_length(cursor, max, 1));
	pull(cursor, max, output->script, tal_count(output->script));
}

static u8 *pull_witness_item(const tal_t *ctx, const u8 **cursor, size_t *max)
{
	uint64_t len = pull_length(cursor, max, 1);
	u8 *item;

	item = tal_arr(ctx, u8, len);
	pull(cursor, max, item, len);
	return item;
}

static void pull_witness(struct bitcoin_tx_input *inputs, size_t i,
			 const u8 **cursor, size_t *max)
{
	uint64_t j, num = pull_length(cursor, max, 1);

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

struct bitcoin_tx *pull_bitcoin_tx(const tal_t *ctx, const u8 **cursor,
				   size_t *max)
{
	size_t i;
	u64 count;
	u8 flag = 0;
	struct bitcoin_tx *tx = tal(ctx, struct bitcoin_tx);

	tx->version = pull_le32(cursor, max);
	count = pull_length(cursor, max, 32 + 4 + 4 + 1);
	/* BIP 144 marker is 0 (impossible to have tx with 0 inputs) */
	if (count == 0) {
		pull(cursor, max, &flag, 1);
		if (flag != SEGREGATED_WITNESS_FLAG)
			return tal_free(tx);
		count = pull_length(cursor, max, 32 + 4 + 4 + 1);
	}

	tx->input = tal_arr(tx, struct bitcoin_tx_input, count);
	for (i = 0; i < tal_count(tx->input); i++)
		pull_input(tx, cursor, max, tx->input + i);

	count = pull_length(cursor, max, 8 + 1);
	tx->output = tal_arr(tx, struct bitcoin_tx_output, count);
	for (i = 0; i < tal_count(tx->output); i++)
		pull_output(tx, cursor, max, tx->output + i);

	if (flag & SEGREGATED_WITNESS_FLAG) {
		for (i = 0; i < tal_count(tx->input); i++)
			pull_witness(tx->input, i, cursor, max);
	} else {
		for (i = 0; i < tal_count(tx->input); i++)
			tx->input[i].witness = NULL;
	}
	tx->lock_time = pull_le32(cursor, max);

	/* If we ran short, fail. */
	if (!*cursor)
		tx = tal_free(tx);
	return tx;
}

struct bitcoin_tx *bitcoin_tx_from_hex(const tal_t *ctx, const char *hex,
				       size_t hexlen)
{
	const char *end;
	u8 *linear_tx;
	const u8 *p;
	struct bitcoin_tx *tx;
	size_t len;

	end = memchr(hex, '\n', hexlen);
	if (!end)
		end = hex + hexlen;

	len = hex_data_size(end - hex);
	p = linear_tx = tal_arr(ctx, u8, len);
	if (!hex_decode(hex, end - hex, linear_tx, len))
		goto fail;

	tx = pull_bitcoin_tx(ctx, &p, &len);
	if (!tx)
		goto fail;

	if (len)
		goto fail_free_tx;

	tal_free(linear_tx);
	return tx;

fail_free_tx:
	tal_free(tx);
fail:
	tal_free(linear_tx);
	return NULL;
}

/* <sigh>.  Bitcoind represents hashes as little-endian for RPC. */
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
			   struct bitcoin_txid *txid)
{
	if (!hex_decode(hexstr, hexstr_len, txid, sizeof(*txid)))
		return false;
	reverse_bytes(txid->shad.sha.u.u8, sizeof(txid->shad.sha.u.u8));
	return true;
}

bool bitcoin_txid_to_hex(const struct bitcoin_txid *txid,
			 char *hexstr, size_t hexstr_len)
{
	struct sha256_double rev = txid->shad;
	reverse_bytes(rev.sha.u.u8, sizeof(rev.sha.u.u8));
	return hex_encode(&rev, sizeof(rev), hexstr, hexstr_len);
}

static char *fmt_bitcoin_tx(const tal_t *ctx, const struct bitcoin_tx *tx)
{
	u8 *lin = linearize_tx(ctx, tx);
	char *s = tal_hex(ctx, lin);
	tal_free(lin);
	return s;
}

static char *fmt_bitcoin_txid(const tal_t *ctx, const struct bitcoin_txid *txid)
{
	char *hexstr = tal_arr(ctx, char, hex_str_size(sizeof(*txid)));

	bitcoin_txid_to_hex(txid, hexstr, hex_str_size(sizeof(*txid)));
	return hexstr;
}

REGISTER_TYPE_TO_STRING(bitcoin_tx, fmt_bitcoin_tx);
REGISTER_TYPE_TO_STRING(bitcoin_txid, fmt_bitcoin_txid);
