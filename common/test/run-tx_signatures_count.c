#include "config.h"
#include <bitcoin/psbt.h>
#include <bitcoin/tx.h>
#include <common/psbt_internal.h>
#include <common/psbt_open.h>
#include <common/setup.h>
#include <common/utils.h>
#include <stdio.h>
#include <string.h>

static struct wally_psbt *psbt_with_serials(const tal_t *ctx,
					    const u64 *serials,
					    size_t n)
{
	struct wally_psbt *psbt = create_psbt(ctx, 0, 0, 0);

	for (size_t i = 0; i < n; i++) {
		struct bitcoin_outpoint outpoint;

		memset(&outpoint, 0, sizeof(outpoint));
		outpoint.n = i;
		psbt_append_input(psbt, &outpoint, BITCOIN_TX_RBF_SEQUENCE,
				  NULL, NULL, NULL);
		psbt_input_set_serial_id(psbt, &psbt->inputs[i], serials[i]);
	}
	return psbt;
}

static void expect_count(const char *what,
			 const u64 *serials,
			 size_t ninputs,
			 enum tx_role role,
			 size_t num_witnesses,
			 const char *needle)
{
	struct wally_psbt *psbt = psbt_with_serials(tmpctx, serials, ninputs);
	const char *err = check_tx_signatures_witness_count(tmpctx, psbt, role,
							    num_witnesses, -1);

	if (needle) {
		if (!err || !strstr(err, needle)) {
			fprintf(stderr, "%s: expected '%s', got '%s'\n",
				what, needle, err ? err : "(accepted)");
			abort();
		}
	} else if (err) {
		fprintf(stderr, "%s: unexpected reject: %s\n", what, err);
		abort();
	}
}

/* Extra witnesses used to be ignored. Peer serials are odd. */
static void test_witness_count(void)
{
	const u64 one_peer[] = { 1 };
	const u64 ours_and_peer[] = { 0, 1 };
	const u64 two_peer[] = { 1, 3 };

	expect_count("matching count", one_peer, 1, TX_ACCEPTER, 1, NULL);
	expect_count("extra witness", one_peer, 1, TX_ACCEPTER, 2,
		     "expecting 1, got 2");
	expect_count("too few witnesses", one_peer, 1, TX_ACCEPTER, 0,
		     "expecting 1, got 0");
	expect_count("our input is not counted", ours_and_peer, 2,
		     TX_ACCEPTER, 1, NULL);
	expect_count("two peer inputs, one witness", two_peer, 2,
		     TX_ACCEPTER, 1, "expecting 2, got 1");
}

/* Splice does not put the shared funding input in the witness array. */
static void test_ignored_funding_input(void)
{
	const u64 serials[] = { 1, 3 };
	struct wally_psbt *psbt = psbt_with_serials(tmpctx, serials, 2);
	const char *err;

	err = check_tx_signatures_witness_count(tmpctx, psbt, TX_ACCEPTER,
						1, 0);
	if (err) {
		fprintf(stderr, "ignored funding input: unexpected reject: %s\n",
			err);
		abort();
	}
	err = check_tx_signatures_witness_count(tmpctx, psbt, TX_ACCEPTER,
						2, 0);
	if (!err || !strstr(err, "expecting 1, got 2")) {
		fprintf(stderr, "ignored funding input: expected mismatch, got '%s'\n",
			err ? err : "(accepted)");
		abort();
	}
}

int main(int argc, char *argv[])
{
	common_setup(argv[0]);
	chainparams = chainparams_for_network("bitcoin");

	test_witness_count();
	test_ignored_funding_input();

	common_shutdown();
	return 0;
}
