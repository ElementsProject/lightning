#include "config.h"
#include <assert.h>
#include <bitcoin/psbt.h>
#include <bitcoin/pubkey.h>
#include <bitcoin/signature.h>
#include <common/psbt_internal.h>
#include <common/setup.h>
#include <common/utils.h>
#include <stdio.h>
#include <string.h>
#include <wally_psbt.h>
#include <wire/peer_wire.h>

static struct witness *witness_raw(const tal_t *ctx, const void *data, size_t n)
{
	struct witness *w = tal(ctx, struct witness);

	w->witness_data = tal_dup_arr(w, u8, data, n, 0);
	return w;
}

static struct witness *witness_items(const tal_t *ctx,
				     const u8 *const *items,
				     const size_t *lens,
				     size_t n)
{
	struct witness *w = tal(ctx, struct witness);

	w->witness_data = tal_arr(w, u8, 0);
	add_varint(&w->witness_data, n);
	for (size_t i = 0; i < n; i++) {
		add_varint(&w->witness_data, lens[i]);
		if (lens[i])
			tal_expand(&w->witness_data, items[i], lens[i]);
	}
	return w;
}

/* OP_0 PUSH20 <20 bytes>. */
static const u8 p2wpkh_spk[] = {
	0x00, 0x14,
	0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
	0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11
};

static struct witness *p2wpkh_witness(const tal_t *ctx)
{
	static const u8 sig[] = { 0x30, 0x01 };
	static const u8 pk[PUBKEY_CMPR_LEN] = { 0x02 };
	const u8 *items[] = { sig, pk };
	size_t lens[] = { sizeof(sig), sizeof(pk) };

	return witness_items(ctx, items, lens, 2);
}

static struct wally_psbt_input *input_for_script(const tal_t *ctx,
						 const u8 *script,
						 size_t script_len)
{
	struct wally_psbt_input *in = talz(ctx, struct wally_psbt_input);
	struct wally_tx_output *out;

	tal_wally_start();
	assert(wally_tx_output_init_alloc(1000, script, script_len, &out)
	       == WALLY_OK);
	tal_wally_end(in);
	in->witness_utxo = out;
	return in;
}

static void expect_reject(const char *what,
			  const struct wally_psbt_input *in,
			  const struct witness *witness,
			  const char *needle)
{
	const char *err = check_tx_signatures_witness(tmpctx, in, witness);

	if (!err || !strstr(err, needle)) {
		fprintf(stderr, "%s: expected '%s', got '%s'\n",
			what, needle, err ? err : "(accepted)");
		abort();
	}
}

static void expect_ok(const char *what,
		      const struct wally_psbt_input *in,
		      const struct witness *witness)
{
	const char *err = check_tx_signatures_witness(tmpctx, in, witness);

	if (err) {
		fprintf(stderr, "%s: unexpected reject: %s\n", what, err);
		abort();
	}
}

static void test_witness_cases(void)
{
	struct wally_psbt_input *in;
	struct witness *empty, *zero, *trunc_count, *trunc_item, *ok;
	u8 *spk;
	static const u8 trunc_count_raw[] = { 0x02, 0x00 };
	static const u8 trunc_item_raw[] = { 0x01, 0x05, 0xaa };
	static const u8 zero_raw[] = { 0x00 };

	spk = tal_dup_arr(tmpctx, u8, p2wpkh_spk, sizeof(p2wpkh_spk), 0);
	in = input_for_script(tmpctx, spk, tal_count(spk));

	expect_reject("null witness", in, NULL, "witness is empty");

	empty = tal(tmpctx, struct witness);
	empty->witness_data = NULL;
	expect_reject("null witness_data", in, empty, "witness is empty");

	empty->witness_data = tal_arr(empty, u8, 0);
	expect_reject("empty witness", in, empty, "witness is empty");

	zero = witness_raw(tmpctx, zero_raw, sizeof(zero_raw));
	expect_reject("zero-count witness", in, zero, "witness is empty");

	trunc_count = witness_raw(tmpctx, trunc_count_raw, sizeof(trunc_count_raw));
	expect_reject("truncated count", in, trunc_count,
		      "truncated or has trailing bytes");

	trunc_item = witness_raw(tmpctx, trunc_item_raw, sizeof(trunc_item_raw));
	expect_reject("truncated item", in, trunc_item,
		      "truncated or has trailing bytes");

	ok = p2wpkh_witness(tmpctx);
	expect_ok("p2wpkh witness", in, ok);
}

/* OP_1 PUSH32 <32 bytes>. */
static const u8 p2tr_spk[] = {
	0x51, 0x20,
	0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
	0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
	0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
	0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22
};

static struct witness *one_item(const tal_t *ctx, const u8 *item, size_t len)
{
	const u8 *items[] = { item };
	size_t lens[] = { len };

	return witness_items(ctx, items, lens, 1);
}

static void test_sighash(void)
{
	struct wally_psbt_input *p2wpkh, *p2tr;
	u8 *spk;
	u8 bad_sig[] = { 0x30, 0x03 };
	u8 keypath64[64] = { 0 };
	u8 keypath65[65] = { 0 };
	static const u8 pk[PUBKEY_CMPR_LEN] = { 0x02 };
	const u8 *bad_items[] = { bad_sig, pk };
	size_t bad_lens[] = { sizeof(bad_sig), sizeof(pk) };

	spk = tal_dup_arr(tmpctx, u8, p2wpkh_spk, sizeof(p2wpkh_spk), 0);
	p2wpkh = input_for_script(tmpctx, spk, tal_count(spk));
	expect_reject("p2wpkh sighash none", p2wpkh,
		      witness_items(tmpctx, bad_items, bad_lens, 2),
		      "not SIGHASH_ALL");

	spk = tal_dup_arr(tmpctx, u8, p2tr_spk, sizeof(p2tr_spk), 0);
	p2tr = input_for_script(tmpctx, spk, tal_count(spk));
	expect_ok("p2tr default sighash", p2tr,
		  one_item(tmpctx, keypath64, sizeof(keypath64)));
	keypath65[64] = SIGHASH_ALL;
	expect_ok("p2tr explicit sighash all", p2tr,
		  one_item(tmpctx, keypath65, sizeof(keypath65)));
	keypath65[64] = 0x03;
	expect_reject("p2tr sighash single", p2tr,
		      one_item(tmpctx, keypath65, sizeof(keypath65)),
		      "not SIGHASH_ALL");
}

int main(int argc, char *argv[])
{
	common_setup(argv[0]);
	chainparams = chainparams_for_network("bitcoin");

	test_witness_cases();
	test_sighash();

	common_shutdown();
	return 0;
}
