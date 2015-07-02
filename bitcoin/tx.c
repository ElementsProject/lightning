#include <ccan/crypto/sha256/sha256.h>
#include <ccan/endian/endian.h>
#include <ccan/err/err.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/str/hex/hex.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <assert.h>
#include "tx.h"
#include "valgrind.h"

enum styles {
	/* Add the CT padding stuff to amount. */
	TX_AMOUNT_CT_STYLE = 1,
	/* Whether to process CT rangeproof and noncecommitment. */
	TX_AMOUNT_INCLUDE_CT = 2,
	/* Process the txfee field. */
	TX_FEE = 4,
	/* Process the input script sig. */
	TX_INPUT_SCRIPTSIG = 8,
	/* Process the amounts for each input. */
	TX_INPUT_AMOUNT = 16,
	/* Process hash of rangeproof and noncecommitment in *output* amount,
	 * instead of rangeproof and noncecommitment themselves. */
	TX_OUTPUT_AMOUNT_HASHPROOF = 32
};

#ifdef ALPHA_TXSTYLE
/* Linearizing has everything, except input amount (which is implied) */
#define LINEARIZE_STYLE (TX_AMOUNT_CT_STYLE | TX_AMOUNT_INCLUDE_CT | TX_FEE | TX_INPUT_SCRIPTSIG)

/* Alpha txids don't include input scripts, or rangeproof/txcommit in output */
#define TXID_STYLE (TX_AMOUNT_CT_STYLE | TX_FEE)

/* Alpha signatures sign the input script (assuming others are set to
 * 0-len), as well as the input fee.

 * They sign a hash of the rangeproof and noncecommitment for inputs,
 * rather than the non rangeproof and noncecommitment themselves.
 *
 * For some reason they skip the txfee. */
#define SIG_STYLE (TX_AMOUNT_CT_STYLE | TX_AMOUNT_INCLUDE_CT | TX_INPUT_SCRIPTSIG | TX_INPUT_AMOUNT | TX_OUTPUT_AMOUNT_HASHPROOF)

#else /* BITCOIN */

/* Process all the bitcoin fields.  Works for txid, serialization and signing */
#define LINEARIZE_STYLE (TX_INPUT_SCRIPTSIG)
#define TXID_STYLE (TX_INPUT_SCRIPTSIG)
#define SIG_STYLE (TX_INPUT_SCRIPTSIG)

#endif

static void add_varint(varint_t v,
		       void (*add)(const void *, size_t, void *), void *addp,
		       enum styles style)
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
		     void (*add)(const void *, size_t, void *), void *addp,
		     enum styles style)
{
	le32 l = cpu_to_le32(v);
	add(&l, sizeof(l), addp);
}

static void add_le64(u64 v,
		     void (*add)(const void *, size_t, void *), void *addp,
		     enum styles style)
{
	le64 l = cpu_to_le64(v);
	add(&l, sizeof(l), addp);
}

static void add_value(u64 amount,
		      void (*add)(const void *, size_t, void *),
		      void *addp,
		      bool output,
		      enum styles style)
{
	if (style & TX_AMOUNT_CT_STYLE) {
		/* The input is hashed as a 33 byte value (for CT); 25 0, then
		 * the big-endian value. */
		static u8 zeroes[25];
		be64 b = cpu_to_be64(amount);
		add(zeroes, sizeof(zeroes), addp);
		add(&b, sizeof(b), addp);
		if (style & TX_AMOUNT_INCLUDE_CT) {
			/* Two more zeroes: Rangeproof and Noncecommitment */
			if (output && (style & TX_OUTPUT_AMOUNT_HASHPROOF)) {
				struct sha256_double h;
				sha256_double(&h, zeroes, 2);
				add(&h, sizeof(h), addp);
			} else {
				add_varint(0, add, addp, style);
				add_varint(0, add, addp, style);
			}
		}
	} else {
		add_le64(amount, add, addp, style);
	}
}

static void add_input_value(u64 amount,
			    void (*add)(const void *, size_t, void *),
			    void *addp,
			    enum styles style)
{
	return add_value(amount, add, addp, false, style);
}

static void add_output_value(u64 amount,
			     void (*add)(const void *, size_t, void *),
			     void *addp,
			     enum styles style)
{
	return add_value(amount, add, addp, true, style);
}

static void add_tx_input(const struct bitcoin_tx_input *input,
			 void (*add)(const void *, size_t, void *), void *addp,
			 enum styles style)
{
	add(&input->txid, sizeof(input->txid), addp);
	add_le32(input->index, add, addp, style);
	if (style & TX_INPUT_AMOUNT) {
		add_input_value(input->input_amount, add, addp, style);
	}
	if (style & TX_INPUT_SCRIPTSIG) {
		add_varint(input->script_length, add, addp, style);
		add(input->script, input->script_length, addp);
	}
	add_le32(input->sequence_number, add, addp, style);
}

static void add_tx_output(const struct bitcoin_tx_output *output,
			  void (*add)(const void *, size_t, void *), void *addp,
			  enum styles style)
{
	add_output_value(output->amount, add, addp, style);
	add_varint(output->script_length, add, addp, style);
	add(output->script, output->script_length, addp);
}

static void add_tx(const struct bitcoin_tx *tx,
		   void (*add)(const void *, size_t, void *), void *addp,
		   enum styles style)
{
	varint_t i;

	add_le32(tx->version, add, addp, style);
	add_varint(tx->input_count, add, addp, style);
	for (i = 0; i < tx->input_count; i++)
		add_tx_input(&tx->input[i], add, addp, style);

	if (style & TX_FEE)
		add_le64(tx->fee, add, addp, style);

	add_varint(tx->output_count, add, addp, style);
	for (i = 0; i < tx->output_count; i++)
		add_tx_output(&tx->output[i], add, addp, style);
	add_le32(tx->lock_time, add, addp, style);
}

static void add_sha(const void *data, size_t len, void *shactx_)
{
	struct sha256_ctx *ctx = shactx_;
	sha256_update(ctx, check_mem(data, len), len);
}

void sha256_tx_for_sig(struct sha256_ctx *ctx, const struct bitcoin_tx *tx)
{
	add_tx(tx, add_sha, ctx, SIG_STYLE);
}

static void add_linearize(const void *data, size_t len, void *pptr_)
{
	u8 **pptr = pptr_;
	size_t oldsize = tal_count(*pptr);

	tal_resize(pptr, oldsize + len);
	memcpy(*pptr + oldsize, check_mem(data, len), len);
}

u8 *linearize_tx(const tal_t *ctx, const struct bitcoin_tx *tx)
{
	u8 *arr = tal_arr(ctx, u8, 0);
	add_tx(tx, add_linearize, &arr, LINEARIZE_STYLE);
	return arr;
}

void bitcoin_txid(const struct bitcoin_tx *tx, struct sha256_double *txid)
{
	struct sha256_ctx ctx = SHA256_INIT;

	add_tx(tx, add_sha, &ctx, TXID_STYLE);
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
	tx->lock_time = 0;

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
	return check_mem(p, n);
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

	if (LINEARIZE_STYLE & TX_AMOUNT_CT_STYLE) {
		/* The input is hashed as a 33 byte value (for CT); 25 0, then
		 * the big-endian value. */
		u8 zeroes[25];
		be64 b;

		if (!pull(cursor, max, zeroes, sizeof(zeroes)))
			return 0;

		/* We don't handle CT amounts. */
		if (zeroes[0] != 0)
			goto fail;

		if (!pull(cursor, max, &b, sizeof(b)))
			return 0;

		amount = be64_to_cpu(b);
		if (LINEARIZE_STYLE & TX_AMOUNT_INCLUDE_CT) {
			varint_t rp, nc;

			rp = pull_varint(cursor, max);
			nc = pull_varint(cursor, max);
			if (rp != 0 || nc != 0)
				goto fail;
		}
	} else {
		amount = pull_le64(cursor, max);
	}
	return amount;

fail:
	/* Simulate EOF */
	*cursor = NULL;
	*max = 0;
	return 0;
}

static void pull_input(const tal_t *ctx, const u8 **cursor, size_t *max,
		       struct bitcoin_tx_input *input)
{
	pull_sha256_double(cursor, max, &input->txid);
	input->index = pull_le32(cursor, max);
	if (LINEARIZE_STYLE & TX_INPUT_AMOUNT) {
		input->input_amount = pull_value(cursor, max);
	}
	if (LINEARIZE_STYLE & TX_INPUT_SCRIPTSIG) {
		input->script_length = pull_varint(cursor, max);
		input->script = tal_arr(ctx, u8, input->script_length);
		pull(cursor, max, input->script, input->script_length);
	}
	input->sequence_number = pull_le32(cursor, max);
}

static void pull_output(const tal_t *ctx, const u8 **cursor, size_t *max,
			struct bitcoin_tx_output *output)
{
	output->amount = pull_value(cursor, max);
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

	if (LINEARIZE_STYLE & TX_FEE)
		tx->fee = pull_le64(cursor, max);

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
	char *hex, *end;
	u8 *linear_tx;
	const u8 *p;
	struct bitcoin_tx *tx;
	size_t len;

	/* Grabs file, add nul at end. */
	hex = grab_file(ctx, filename);
	if (!hex)
		err(1, "Opening %s", filename);

	if (strends(hex, "\n"))
		hex[strlen(hex)-1] = '\0';

	end = strchr(hex, ':');
	if (!end)
		end = hex + strlen(hex);
		
	len = hex_data_size(end - hex);
	p = linear_tx = tal_arr(hex, u8, len);
	if (!hex_decode(hex, end - hex, linear_tx, len))
		errx(1, "Bad hex string in %s", filename);

	tx = pull_bitcoin_tx(ctx, &p, &len);
	if (!tx)
		errx(1, "Bad transaction in %s", filename);

	/* Optional appended [:input-amount]* */
	for (len = 0; len < tx->input_count; len++) {
		if (*end != ':')
			break;
		tx->input[len].input_amount = strtoull(end + 1, &end, 10);
	}
	if (len == tx->input_count) {
		if (*end != '\0')
			errx(1, "Additional input amounts appended to %s",
			     filename);
	} else {
		/* Input amounts are compulsory for alpha, to generate sigs */
#ifdef ALPHA_TXSTYLE
		errx(1, "No input amount #%zu in %s", len, filename);
#endif
	}
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

static bool write_input_amounts(int fd, const struct bitcoin_tx *tx)
{
	/* Alpha required input amounts, so append them */
#ifdef ALPHA_TXSTYLE
	size_t i;

	for (i = 0; i < tx->input_count; i++) {
		char str[1 + STR_MAX_CHARS(tx->input[i].input_amount)];
		sprintf(str, ":%llu",
			(unsigned long long)tx->input[i].input_amount);
		if (!write_all(fd, str, strlen(str)))
			return false;
	}
#endif
	return true;
}

bool bitcoin_tx_write(int fd, const struct bitcoin_tx *tx)
{
	u8 *tx_arr;
	char *tx_hex;
	bool ok;

	tx_arr = linearize_tx(NULL, tx);
	tx_hex = tal_arr(tx_arr, char, hex_str_size(tal_count(tx_arr)));
	hex_encode(tx_arr, tal_count(tx_arr), tx_hex, tal_count(tx_hex));

	ok = write_all(fd, tx_hex, strlen(tx_hex))
		&& write_input_amounts(fd, tx);
	tal_free(tx_arr);
	return ok;
}
