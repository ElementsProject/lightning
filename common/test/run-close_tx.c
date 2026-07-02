#include "config.h"
#include <assert.h>
#include <bitcoin/chainparams.h>
#include <bitcoin/pubkey.h>
#include <bitcoin/script.h>
#include <bitcoin/tx.h>
#include <common/close_tx.h>
#include <common/setup.h>
#include <common/utils.h>
#include <external/libwally-core/include/wally_script.h>
#include <stdio.h>

static void test_create_simple_close_tx_basic(void)
{
	struct bitcoin_tx *tx;
	struct bitcoin_outpoint funding_outpoint;
	struct amount_sat funding_sats = AMOUNT_SAT(1000000);
	struct amount_sat closer_amount = AMOUNT_SAT(600000);
	struct amount_sat closee_amount = AMOUNT_SAT(400000);
	u32 locktime = 12345;
	const u8 *closer_script, *closee_script, *funding_wscript;

	/* Create test scripts */
	static const u8 closer_script_data[] = {0x00, 0x14, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x11, 0x22, 0x33, 0x44};
	static const u8 closee_script_data[] = {0x00, 0x14, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
	closer_script = tal_dup_arr(tmpctx, u8, closer_script_data, sizeof(closer_script_data), 0);
	closee_script = tal_dup_arr(tmpctx, u8, closee_script_data, sizeof(closee_script_data), 0);

	/* Create funding script (2-of-2 multisig) */
	struct pubkey *pk1 = tal(tmpctx, struct pubkey);
	struct pubkey *pk2 = tal(tmpctx, struct pubkey);
	assert(pubkey_from_hexstr("034fede2c619f647fe7c01d40ae22e4c285291ca2ffb47937bbfb7d6e8285a081f",
				  2 * PUBKEY_CMPR_LEN, pk1));
	assert(pubkey_from_hexstr("028dfe31019dd61fa04c76ad065410e5d063ac2949c04c14b214c1b363e517452f",
				  2 * PUBKEY_CMPR_LEN, pk2));
	funding_wscript = bitcoin_redeem_2of2(tmpctx, pk1, pk2);

	/* Create outpoint */
	memset(&funding_outpoint, 0, sizeof(funding_outpoint));
	/* Just use a fixed txid for testing */
	funding_outpoint.n = 0;

	/* Test basic functionality */
	tx = create_simple_close_tx(tmpctx, NULL, NULL, closer_script,
		closee_script, funding_wscript, &funding_outpoint, funding_sats,
		closer_amount, closee_amount, locktime);

	assert(tx != NULL);
	assert(tx->wtx->num_inputs == 1);
	assert(tx->wtx->num_outputs == 2);
	assert(tx->wtx->locktime == locktime);
	assert(tx->wtx->inputs[0].sequence == 0xFFFFFFFD); /* RBF */

	/* Check outputs (BIP69 order: smallest sats first). */
	assert(tx->wtx->outputs[0].satoshi == closee_amount.satoshis);
	assert(tx->wtx->outputs[1].satoshi == closer_amount.satoshis);

	tal_free(tx);
}

static void test_create_simple_close_tx_omitted_closer_output(void)
{
	struct bitcoin_tx *tx;
	struct bitcoin_outpoint funding_outpoint;
	struct amount_sat funding_sats = AMOUNT_SAT(1000000);
	struct amount_sat closer_amount = AMOUNT_SAT(600000);
	struct amount_sat closee_amount = AMOUNT_SAT(400000);
	u32 locktime = 12345;
	const u8 *closee_script, *funding_wscript;

	/* Create test scripts - closer_script is NULL */
	static const u8 closee_script_data[] = {0x00, 0x14, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
	closee_script = tal_dup_arr(tmpctx, u8, closee_script_data, sizeof(closee_script_data), 0);

	/* Create funding script (2-of-2 multisig) */
	struct pubkey *pk1 = tal(tmpctx, struct pubkey);
	struct pubkey *pk2 = tal(tmpctx, struct pubkey);
	assert(pubkey_from_hexstr("034fede2c619f647fe7c01d40ae22e4c285291ca2ffb47937bbfb7d6e8285a081f",
				  2 * PUBKEY_CMPR_LEN, pk1));
	assert(pubkey_from_hexstr("028dfe31019dd61fa04c76ad065410e5d063ac2949c04c14b214c1b363e517452f",
				  2 * PUBKEY_CMPR_LEN, pk2));
	funding_wscript = bitcoin_redeem_2of2(tmpctx, pk1, pk2);

	/* Create outpoint */
	memset(&funding_outpoint, 0, sizeof(funding_outpoint));
	funding_outpoint.n = 0;

	/* Test omitted closer output */
	tx = create_simple_close_tx(tmpctx, NULL, NULL, NULL, closee_script,
		funding_wscript, &funding_outpoint, funding_sats, closer_amount,
		closee_amount, locktime);

	assert(tx != NULL);
	assert(tx->wtx->num_inputs == 1);
	assert(tx->wtx->num_outputs == 1); /* Only closee output */
	assert(tx->wtx->locktime == locktime);
	assert(tx->wtx->inputs[0].sequence == 0xFFFFFFFD); /* RBF */

	/* Check output */
	assert(tx->wtx->outputs[0].satoshi == closee_amount.satoshis);

	tal_free(tx);
}

static void test_create_simple_close_tx_omitted_closee_output(void)
{
	struct bitcoin_tx *tx;
	struct bitcoin_outpoint funding_outpoint;
	struct amount_sat funding_sats = AMOUNT_SAT(1000000);
	struct amount_sat closer_amount = AMOUNT_SAT(600000);
	struct amount_sat closee_amount = AMOUNT_SAT(400000);
	u32 locktime = 12345;
	const u8 *closer_script, *funding_wscript;

	/* Create test scripts - closee_script is NULL */
	static const u8 closer_script_data[] = {0x00, 0x14, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x11, 0x22, 0x33, 0x44};
	closer_script = tal_dup_arr(tmpctx, u8, closer_script_data, sizeof(closer_script_data), 0);

	/* Create funding script (2-of-2 multisig) */
	struct pubkey *pk1 = tal(tmpctx, struct pubkey);
	struct pubkey *pk2 = tal(tmpctx, struct pubkey);
	assert(pubkey_from_hexstr("034fede2c619f647fe7c01d40ae22e4c285291ca2ffb47937bbfb7d6e8285a081f",
				  2 * PUBKEY_CMPR_LEN, pk1));
	assert(pubkey_from_hexstr("028dfe31019dd61fa04c76ad065410e5d063ac2949c04c14b214c1b363e517452f",
				  2 * PUBKEY_CMPR_LEN, pk2));
	funding_wscript = bitcoin_redeem_2of2(tmpctx, pk1, pk2);

	/* Create outpoint */
	memset(&funding_outpoint, 0, sizeof(funding_outpoint));
	funding_outpoint.n = 0;

	/* Test omitted closee output */
	tx = create_simple_close_tx(tmpctx, NULL, NULL, closer_script, NULL,
		funding_wscript, &funding_outpoint, funding_sats, closer_amount,
		closee_amount, locktime);

	assert(tx != NULL);
	assert(tx->wtx->num_inputs == 1);
	assert(tx->wtx->num_outputs == 1); /* Only closer output */
	assert(tx->wtx->locktime == locktime);
	assert(tx->wtx->inputs[0].sequence == 0xFFFFFFFD); /* RBF */

	/* Check output */
	assert(tx->wtx->outputs[0].satoshi == closer_amount.satoshis);

	tal_free(tx);
}

static void test_create_simple_close_tx_op_return_closer(void)
{
	struct bitcoin_tx *tx;
	struct bitcoin_outpoint funding_outpoint;
	struct amount_sat funding_sats = AMOUNT_SAT(1000000);
	struct amount_sat closer_amount = AMOUNT_SAT(600000);
	struct amount_sat closee_amount = AMOUNT_SAT(400000);
	u32 locktime = 12345;
	const u8 *closer_script, *closee_script, *funding_wscript;

	/* Create OP_RETURN script for closer */
	static const u8 closer_script_data[] = {OP_RETURN, 0x04, 't', 'e', 's', 't'};
	static const u8 closee_script_data[] = {0x00, 0x14, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
	closer_script = tal_dup_arr(tmpctx, u8, closer_script_data, sizeof(closer_script_data), 0);
	closee_script = tal_dup_arr(tmpctx, u8, closee_script_data, sizeof(closee_script_data), 0);

	/* Create funding script (2-of-2 multisig) */
	struct pubkey *pk1 = tal(tmpctx, struct pubkey);
	struct pubkey *pk2 = tal(tmpctx, struct pubkey);
	assert(pubkey_from_hexstr("034fede2c619f647fe7c01d40ae22e4c285291ca2ffb47937bbfb7d6e8285a081f",
				  2 * PUBKEY_CMPR_LEN, pk1));
	assert(pubkey_from_hexstr("028dfe31019dd61fa04c76ad065410e5d063ac2949c04c14b214c1b363e517452f",
				  2 * PUBKEY_CMPR_LEN, pk2));
	funding_wscript = bitcoin_redeem_2of2(tmpctx, pk1, pk2);

	/* Create outpoint */
	memset(&funding_outpoint, 0, sizeof(funding_outpoint));
	funding_outpoint.n = 0;

	/* Test OP_RETURN closer output - should have zero amount */
	tx = create_simple_close_tx(tmpctx, NULL, NULL, closer_script,
		closee_script, funding_wscript, &funding_outpoint, funding_sats,
		closer_amount, closee_amount, locktime);

	assert(tx != NULL);
	assert(tx->wtx->num_inputs == 1);
	assert(tx->wtx->num_outputs == 2);
	assert(tx->wtx->locktime == locktime);
	assert(tx->wtx->inputs[0].sequence == 0xFFFFFFFD); /* RBF */

	/* Check outputs - closer should be zero due to OP_RETURN */
	assert(tx->wtx->outputs[0].satoshi == 0);
	assert(tx->wtx->outputs[1].satoshi == closee_amount.satoshis);

	tal_free(tx);
}

static void test_create_simple_close_tx_op_return_closee(void)
{
	struct bitcoin_tx *tx;
	struct bitcoin_outpoint funding_outpoint;
	struct amount_sat funding_sats = AMOUNT_SAT(1000000);
	struct amount_sat closer_amount = AMOUNT_SAT(600000);
	struct amount_sat closee_amount = AMOUNT_SAT(400000);
	u32 locktime = 12345;
	const u8 *closer_script, *closee_script, *funding_wscript;

	/* Create OP_RETURN script for closee */
	static const u8 closer_script_data[] = {0x00, 0x14, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x11, 0x22, 0x33, 0x44};
	static const u8 closee_script_data[] = {OP_RETURN, 0x04, 't', 'e', 's', 't'};
	closer_script = tal_dup_arr(tmpctx, u8, closer_script_data, sizeof(closer_script_data), 0);
	closee_script = tal_dup_arr(tmpctx, u8, closee_script_data, sizeof(closee_script_data), 0);

	/* Create funding script (2-of-2 multisig) */
	struct pubkey *pk1 = tal(tmpctx, struct pubkey);
	struct pubkey *pk2 = tal(tmpctx, struct pubkey);
	assert(pubkey_from_hexstr("034fede2c619f647fe7c01d40ae22e4c285291ca2ffb47937bbfb7d6e8285a081f",
				  2 * PUBKEY_CMPR_LEN, pk1));
	assert(pubkey_from_hexstr("028dfe31019dd61fa04c76ad065410e5d063ac2949c04c14b214c1b363e517452f",
				  2 * PUBKEY_CMPR_LEN, pk2));
	funding_wscript = bitcoin_redeem_2of2(tmpctx, pk1, pk2);

	/* Create outpoint */
	memset(&funding_outpoint, 0, sizeof(funding_outpoint));
	funding_outpoint.n = 0;

	/* Test OP_RETURN closee output - should have zero amount */
	tx = create_simple_close_tx(tmpctx, NULL, NULL, closer_script,
		closee_script, funding_wscript, &funding_outpoint, funding_sats,
		closer_amount, closee_amount, locktime);

	assert(tx != NULL);
	assert(tx->wtx->num_inputs == 1);
	assert(tx->wtx->num_outputs == 2);
	assert(tx->wtx->locktime == locktime);
	assert(tx->wtx->inputs[0].sequence == 0xFFFFFFFD); /* RBF */

	/* Check outputs - closee should be zero due to OP_RETURN */
	assert(tx->wtx->outputs[0].satoshi == 0);
	assert(tx->wtx->outputs[1].satoshi == closer_amount.satoshis);

	tal_free(tx);
}

static void test_create_simple_close_tx_both_outputs_omitted(void)
{
	struct bitcoin_tx *tx;
	struct bitcoin_outpoint funding_outpoint;
	struct amount_sat funding_sats = AMOUNT_SAT(1000000);
	struct amount_sat closer_amount = AMOUNT_SAT(600000);
	struct amount_sat closee_amount = AMOUNT_SAT(400000);
	u32 locktime = 12345;
	const u8 *funding_wscript;

	/* Create funding script (2-of-2 multisig) */
	struct pubkey *pk1 = tal(tmpctx, struct pubkey);
	struct pubkey *pk2 = tal(tmpctx, struct pubkey);
	assert(pubkey_from_hexstr("034fede2c619f647fe7c01d40ae22e4c285291ca2ffb47937bbfb7d6e8285a081f",
				  2 * PUBKEY_CMPR_LEN, pk1));
	assert(pubkey_from_hexstr("028dfe31019dd61fa04c76ad065410e5d063ac2949c04c14b214c1b363e517452f",
				  2 * PUBKEY_CMPR_LEN, pk2));
	funding_wscript = bitcoin_redeem_2of2(tmpctx, pk1, pk2);

	/* Create outpoint */
	memset(&funding_outpoint, 0, sizeof(funding_outpoint));
	funding_outpoint.n = 0;

	/* Test both outputs omitted - should return NULL */
	tx = create_simple_close_tx(tmpctx, NULL, NULL, NULL, NULL,
		funding_wscript, &funding_outpoint, funding_sats, closer_amount,
		closee_amount, locktime);

	assert(tx == NULL); /* Should fail with no outputs */
}

int main(int argc, char *argv[])
{
	common_setup(argv[0]);
	chainparams = chainparams_for_network("bitcoin");

	test_create_simple_close_tx_basic();
	test_create_simple_close_tx_omitted_closer_output();
	test_create_simple_close_tx_omitted_closee_output();
	test_create_simple_close_tx_op_return_closer();
	test_create_simple_close_tx_op_return_closee();
	test_create_simple_close_tx_both_outputs_omitted();

	common_shutdown();
	return 0;
}
