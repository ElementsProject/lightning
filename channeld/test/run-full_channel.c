#include "../../common/key_derive.c"
#include "../../common/keyset.c"
#include "../../common/initial_channel.c"
#include "../../channeld/full_channel.c"
#include "../../common/initial_commit_tx.c"
#include "../../channeld/commit_tx.c"
#include "../../common/htlc_tx.c"
#include <bitcoin/preimage.h>
#include <bitcoin/privkey.h>
#include <bitcoin/pubkey.h>
#include <ccan/err/err.h>
#include <ccan/str/hex/hex.h>
#include <common/sphinx.h>
#include <common/type_to_string.h>
#include <stdio.h>

void status_fmt(enum log_level level UNUSED, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vprintf(fmt, ap);
	printf("\n");
	va_end(ap);
}

/* bitcoind loves its backwards txids! */
static struct bitcoin_txid txid_from_hex(const char *hex)
{
	struct bitcoin_txid txid;

	if (!bitcoin_txid_from_hex(hex, strlen(hex), &txid))
		abort();
	return txid;
}

static struct bitcoin_tx *tx_from_hex(const tal_t *ctx, const char *hex)
{
	return bitcoin_tx_from_hex(ctx, hex, strlen(hex));
}

/* BOLT #3:
 *
 *     local_feerate_per_kw: 0
 *     ...
 *     local_feerate_per_kw: 647
 *     ...
 *     local_feerate_per_kw: 648
 *     ...
 *     local_feerate_per_kw: 2069
 *     ...
 *     local_feerate_per_kw: 2070
 *     ...
 *     local_feerate_per_kw: 2194
 *     ...
 *     local_feerate_per_kw: 2195
 *     ...
 *     local_feerate_per_kw: 3702
 *     ...
 *     local_feerate_per_kw: 3703
 *     ...
 *     local_feerate_per_kw: 4914
 *     ...
 *     local_feerate_per_kw: 4915
 *     ...
 *     local_feerate_per_kw: 9651180
 *     ...
 *     local_feerate_per_kw: 9651181
 *     ...
 *     local_feerate_per_kw: 9651936
 */
static u32 feerates[] = {
	647, 648,
	2069, 2070,
	2194, 2195,
	3702, 3703,
	4914, 4915,
	9651180, 9651181,
	9651936
};

/* BOLT #3:
 *
 *    htlc 0 direction: remote->local
 *    htlc 0 amount_msat: 1000000
 *    htlc 0 expiry: 500
 *    htlc 0 payment_preimage: 0000000000000000000000000000000000000000000000000000000000000000
 *    htlc 1 direction: remote->local
 *    htlc 1 amount_msat: 2000000
 *    htlc 1 expiry: 501
 *    htlc 1 payment_preimage: 0101010101010101010101010101010101010101010101010101010101010101
 *    htlc 2 direction: local->remote
 *    htlc 2 amount_msat: 2000000
 *    htlc 2 expiry: 502
 *    htlc 2 payment_preimage: 0202020202020202020202020202020202020202020202020202020202020202
 *    htlc 3 direction: local->remote
 *    htlc 3 amount_msat: 3000000
 *    htlc 3 expiry: 503
 *    htlc 3 payment_preimage: 0303030303030303030303030303030303030303030303030303030303030303
 *    htlc 4 direction: remote->local
 *    htlc 4 amount_msat: 4000000
 *    htlc 4 expiry: 504
 *    htlc 4 payment_preimage: 0404040404040404040404040404040404040404040404040404040404040404
 */
static const struct htlc **include_htlcs(struct channel *channel, enum side side)
{
	int i;
	const struct htlc **htlcs = tal_arr(channel, const struct htlc *, 5);
	const struct htlc **changed_htlcs;
	u8 *dummy_routing = tal_arr(htlcs, u8, TOTAL_PACKET_SIZE);
	bool ret;

	for (i = 0; i < 5; i++) {
		struct preimage preimage;
		struct sha256 hash;
		enum channel_add_err e;
		enum side sender;
		u64 msatoshi = 0;

		switch (i) {
		case 0:
			sender = !side;
			msatoshi = 1000000;
			break;
		case 1:
			sender = !side;
			msatoshi = 2000000;
			break;
		case 2:
			sender = side;
			msatoshi = 2000000;
			break;
		case 3:
			sender = side;
			msatoshi = 3000000;
			break;
		case 4:
			sender = !side;
			msatoshi = 4000000;
			break;
		}
		assert(msatoshi != 0);

		memset(&preimage, i, sizeof(preimage));
		sha256(&hash, &preimage, sizeof(preimage));
		e = channel_add_htlc(channel, sender, i, msatoshi, 500+i, &hash,
				     dummy_routing, NULL);
		assert(e == CHANNEL_ERR_ADD_OK);
		htlcs[i] = channel_get_htlc(channel, sender, i);
	}
	tal_free(dummy_routing);

	/* Now make HTLCs fully committed. */
	changed_htlcs = tal_arr(htlcs, const struct htlc *, 0);
	ret = channel_sending_commit(channel, &changed_htlcs);
	assert(ret);
	ret = channel_rcvd_revoke_and_ack(channel, &changed_htlcs);
	assert(ret);
	ret = channel_rcvd_commit(channel, &changed_htlcs);
	assert(ret);
	ret = channel_sending_revoke_and_ack(channel);
	assert(ret);
	ret = channel_sending_commit(channel, &changed_htlcs);
	assert(ret);
	ret = channel_rcvd_revoke_and_ack(channel, &changed_htlcs);
	assert(!ret);
	return htlcs;
}

static struct pubkey pubkey_from_hex(const char *hex)
{
	struct pubkey pubkey;

	if (strstarts(hex, "0x"))
		hex += 2;
	if (!pubkey_from_hexstr(hex, strlen(hex), &pubkey))
		abort();
	return pubkey;
}

static void tx_must_be_eq(const struct bitcoin_tx *a,
			  const struct bitcoin_tx *b)
{
	u8 *lina, *linb;
	size_t i;

	lina = linearize_tx(tmpctx, a);
	linb = linearize_tx(tmpctx, b);

	for (i = 0; i < tal_len(lina); i++) {
		if (i >= tal_len(linb))
			errx(1, "Second tx is truncated:\n"
			     "%s\n"
			     "%s",
			     tal_hex(tmpctx, lina),
			     tal_hex(tmpctx, linb));
		if (lina[i] != linb[i])
			errx(1, "tx differ at offset %zu:\n"
			     "%s\n"
			     "%s",
			     i,
			     tal_hex(tmpctx, lina),
			     tal_hex(tmpctx, linb));
	}
	if (i != tal_len(linb))
		errx(1, "First tx is truncated:\n"
		     "%s\n"
		     "%s",
		     tal_hex(tmpctx, lina),
		     tal_hex(tmpctx, linb));
}

static void txs_must_be_eq(struct bitcoin_tx **a, struct bitcoin_tx **b)
{
	size_t i;

	if (tal_count(a) != tal_count(b))
		errx(1, "A has %zu txs, B has %zu",
		     tal_count(a), tal_count(b));

	for (i = 0; i < tal_count(a); i++)
		tx_must_be_eq(a[i], b[i]);
}

static void send_and_fulfill_htlc(struct channel *channel,
				  enum side sender,
				  u64 msatoshi)
{
	struct preimage r;
	struct sha256 rhash;
	u8 *dummy_routing = tal_arr(channel, u8, TOTAL_PACKET_SIZE);
	bool ret;
	const struct htlc **changed_htlcs;

	memset(&r, 0, sizeof(r));
	sha256(&rhash, &r, sizeof(r));

	assert(channel_add_htlc(channel, sender, 1337, msatoshi, 900, &rhash,
				dummy_routing, NULL) == CHANNEL_ERR_ADD_OK);

	changed_htlcs = tal_arr(channel, const struct htlc *, 0);

	if (sender == LOCAL) {
		/* Step through a complete cycle. */
		ret = channel_sending_commit(channel, &changed_htlcs);
		assert(ret);
		ret = channel_rcvd_revoke_and_ack(channel, &changed_htlcs);
		assert(ret);
		ret = channel_rcvd_commit(channel, &changed_htlcs);
		assert(ret);
		ret = channel_sending_revoke_and_ack(channel);
		assert(!ret);
		assert(channel_fulfill_htlc(channel, LOCAL, 1337, &r, NULL)
		       == CHANNEL_ERR_REMOVE_OK);
		ret = channel_rcvd_commit(channel, &changed_htlcs);
		assert(ret);
		ret = channel_sending_revoke_and_ack(channel);
		assert(ret);
		ret = channel_sending_commit(channel, &changed_htlcs);
		assert(ret);
		ret = channel_rcvd_revoke_and_ack(channel, &changed_htlcs);
		assert(!ret);
		assert(channel_get_htlc(channel, sender, 1337)->state
		       == RCVD_REMOVE_ACK_REVOCATION);
	} else {
		ret = channel_rcvd_commit(channel, &changed_htlcs);
		assert(ret);
		ret = channel_sending_revoke_and_ack(channel);
		assert(ret);
		ret = channel_sending_commit(channel, &changed_htlcs);
		assert(ret);
		ret = channel_rcvd_revoke_and_ack(channel, &changed_htlcs);
		assert(!ret);
		assert(channel_fulfill_htlc(channel, REMOTE, 1337, &r, NULL)
		       == CHANNEL_ERR_REMOVE_OK);
		ret = channel_sending_commit(channel, &changed_htlcs);
		assert(ret);
		ret = channel_rcvd_revoke_and_ack(channel, &changed_htlcs);
		assert(ret);
		ret = channel_rcvd_commit(channel, &changed_htlcs);
		assert(ret);
		ret = channel_sending_revoke_and_ack(channel);
		assert(!ret);
		assert(channel_get_htlc(channel, sender, 1337)->state
		       == SENT_REMOVE_ACK_REVOCATION);
	}
}

static void update_feerate(struct channel *channel, u32 feerate)
{
	bool ret;

	ret = channel_update_feerate(channel, feerate);
	assert(ret);
	if (channel->funder == LOCAL) {
		ret = channel_sending_commit(channel, NULL);
		assert(ret);
		ret = channel_rcvd_revoke_and_ack(channel, NULL);
		assert(ret);
		ret = channel_rcvd_commit(channel, NULL);
		assert(ret);
		ret = channel_sending_revoke_and_ack(channel);
		assert(!ret);
	} else {
		ret = channel_rcvd_commit(channel, NULL);
		assert(ret);
		ret = channel_sending_revoke_and_ack(channel);
		assert(ret);
		ret = channel_sending_commit(channel, NULL);
		assert(ret);
		ret = channel_rcvd_revoke_and_ack(channel, NULL);
		assert(!ret);
	}
	assert(channel_feerate(channel, LOCAL) == feerate);
	assert(channel_feerate(channel, REMOTE) == feerate);
}

int main(void)
{
	setup_locale();

	struct bitcoin_txid funding_txid;
	/* We test from both sides. */
	struct channel *lchannel, *rchannel;
	u64 funding_amount_satoshi;
	u32 *feerate_per_kw;
	unsigned int funding_output_index;
	struct keyset keyset;
	struct pubkey local_funding_pubkey, remote_funding_pubkey;
	struct pubkey local_per_commitment_point;
	struct basepoints localbase, remotebase;
	struct pubkey *unknown;
	struct bitcoin_tx *raw_tx, **txs, **txs2;
	struct channel_config *local_config, *remote_config;
	u64 to_local_msat, to_remote_msat;
	const struct htlc **htlc_map, **htlcs;
	const u8 *funding_wscript, **wscripts;
	size_t i;

	secp256k1_ctx = wally_get_secp_context();
	setup_tmpctx();

	feerate_per_kw = tal_arr(tmpctx, u32, NUM_SIDES);
	unknown = tal(tmpctx, struct pubkey);
	local_config = tal(tmpctx, struct channel_config);
	remote_config = tal(tmpctx, struct channel_config);

	/* BOLT #3:
	 *
	 * # Appendix C: Commitment and HTLC Transaction Test Vectors
	 *
	 * In the following:
	 *  - *local* transactions are considered, which implies that all
	 *    payments to *local* are delayed.
	 *  - It's assumed that *local* is the funder.
	 *  - Private keys are displayed as 32 bytes plus a trailing 1
	 *    (Bitcoin's convention for "compressed" private keys, i.e. keys for
	 *    which the public key is compressed).
	 *  - Transaction signatures are all deterministic, using RFC6979 (using
	 *    HMAC-SHA256).
	 *
	 * To start, common basic parameters for each test vector are defined:
	 * the HTLCs are not used for the first "simple commitment tx with no
	 * HTLCs" test.
	 *
	 *     funding_tx_id: 8984484a580b825b9972d7adb15050b3ab624ccd731946b3eeddb92f4e7ef6be
	 *     funding_output_index: 0
	 *     funding_amount_satoshi: 10000000
	 *     commitment_number: 42
	 *     local_delay: 144
	 *     local_dust_limit_satoshi: 546
	 */
	funding_txid = txid_from_hex("8984484a580b825b9972d7adb15050b3ab624ccd731946b3eeddb92f4e7ef6be");
	funding_output_index = 0;
	funding_amount_satoshi = 10000000;

	remote_config->to_self_delay = 144;
	local_config->dust_limit_satoshis = 546;
	/* This matters only because we check if added HTLC will create new
	 * output, for fee considerations. */
	remote_config->dust_limit_satoshis = 546;

	local_config->max_htlc_value_in_flight_msat = -1ULL;
	remote_config->max_htlc_value_in_flight_msat = -1ULL;
	local_config->channel_reserve_satoshis = 0;
	remote_config->channel_reserve_satoshis = 0;
	local_config->htlc_minimum_msat = 0;
	remote_config->htlc_minimum_msat = 0;
	local_config->max_accepted_htlcs = 0xFFFF;
	remote_config->max_accepted_htlcs = 0xFFFF;

	/* BOLT #3:
	 *
	 * # From remote_revocation_basepoint_secret
	 * INTERNAL: remote_revocation_basepoint: 02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27
	 * # From local_delayed_payment_basepoint_secret
	 * INTERNAL: local_delayed_payment_basepoint: 023c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b1
	*/
	remotebase.revocation = pubkey_from_hex("02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27");
	localbase.delayed_payment = pubkey_from_hex("023c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b1");

	/* BOLT #3:
	 *
	 * local_payment_basepoint: 034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa
	 * remote_payment_basepoint: 032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991
	 * # obscured commitment transaction number = 0x2bb038521914 ^ 42
	 */
	localbase.payment = pubkey_from_hex("034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa");
	remotebase.payment = pubkey_from_hex("032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991");

	/* FIXME: Update bolt */
	localbase.htlc = localbase.payment;
	remotebase.htlc = remotebase.payment;

	/* We put unknown in for some things; valgrind will warn if used. */
	localbase.revocation = *unknown;
	remotebase.delayed_payment = *unknown;

	/* BOLT #3:
	 *
	 * local_funding_pubkey: 023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb
	 * remote_funding_pubkey: 030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c1
	 */
	local_funding_pubkey = pubkey_from_hex("023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb");
	remote_funding_pubkey = pubkey_from_hex("030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c1");

	/* BOLT #3:
	 *
	 *     # funding wscript = 5221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae
	 */
	funding_wscript = tal_hexdata(tmpctx, "5221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae", strlen("5221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae"));

	/* BOLT #3:
	 *
	 *    commitment_number: 42
	 *...
	 *    name: simple commitment tx with no HTLCs
	 *    to_local_msat: 7000000000
	 *    to_remote_msat: 3000000000
	 *    local_feerate_per_kw: 15000
	 */

	to_local_msat = 7000000000;
	to_remote_msat = 3000000000;
	feerate_per_kw[LOCAL] = feerate_per_kw[REMOTE] = 15000;
	lchannel = new_full_channel(tmpctx, &funding_txid, funding_output_index,
				    funding_amount_satoshi, to_local_msat,
				    feerate_per_kw,
				    local_config,
				    remote_config,
				    &localbase, &remotebase,
				    &local_funding_pubkey,
				    &remote_funding_pubkey,
				    LOCAL);
	rchannel = new_full_channel(tmpctx, &funding_txid, funding_output_index,
				    funding_amount_satoshi, to_remote_msat,
				    feerate_per_kw,
				    remote_config,
				    local_config,
				    &remotebase, &localbase,
				    &remote_funding_pubkey,
				    &local_funding_pubkey,
				    REMOTE);

	/* BOLT #3:
	 *
	 * INTERNAL: local_per_commitment_point: 025f7117a78150fe2ef97db7cfc83bd57b2e2c0d0dd25eaf467a4a1c2a45ce1486
	 */
	local_per_commitment_point = pubkey_from_hex("025f7117a78150fe2ef97db7cfc83bd57b2e2c0d0dd25eaf467a4a1c2a45ce1486");
	/* BOLT #3:
	 * localpubkey: 030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e7
	 * remotepubkey: 0394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b
	 * local_delayedpubkey: 03fd5960528dc152014952efdb702a88f71e3c1653b2314431701ec77e57fde83c
	 * local_revocation_pubkey: 0212a140cd0c6539d07cd08dfe09984dec3251ea808b892efeac3ede9402bf2b19
	 */
	keyset.self_payment_key = pubkey_from_hex("030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e7");
	keyset.other_payment_key = pubkey_from_hex("0394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b");
	keyset.self_delayed_payment_key = pubkey_from_hex("03fd5960528dc152014952efdb702a88f71e3c1653b2314431701ec77e57fde83c");
	keyset.self_revocation_key = pubkey_from_hex("0212a140cd0c6539d07cd08dfe09984dec3251ea808b892efeac3ede9402bf2b19");

	/* FIXME: Update bolt */
	keyset.self_htlc_key = keyset.self_payment_key;
	keyset.other_htlc_key = keyset.other_payment_key;

	raw_tx = commit_tx(tmpctx, &funding_txid, funding_output_index,
			   funding_amount_satoshi,
			   LOCAL, remote_config->to_self_delay,
			   &keyset,
			   feerate_per_kw[LOCAL],
			   local_config->dust_limit_satoshis,
			   to_local_msat,
			   to_remote_msat,
			   NULL, &htlc_map, 0x2bb038521914 ^ 42, LOCAL);

	txs = channel_txs(tmpctx, &htlc_map, &wscripts,
			  lchannel, &local_per_commitment_point, 42, LOCAL);
	assert(tal_count(txs) == 1);
	assert(tal_count(htlc_map) == 2);
	assert(tal_count(wscripts) == 1);
	assert(scripteq(wscripts[0], funding_wscript));
	tx_must_be_eq(txs[0], raw_tx);

	txs2 = channel_txs(tmpctx, &htlc_map, &wscripts,
			   rchannel, &local_per_commitment_point, 42, REMOTE);
	txs_must_be_eq(txs, txs2);

	/* BOLT #3:
	 *
	 *    name: commitment tx with all five HTLCs untrimmed (minimum feerate)
	 *    to_local_msat: 6988000000
	 *    to_remote_msat: 3000000000
	 *    local_feerate_per_kw: 0
	 */
	to_local_msat = 6988000000;
	to_remote_msat = 3000000000;
	feerate_per_kw[LOCAL] = feerate_per_kw[REMOTE] = 0;

	/* Now, BOLT doesn't adjust owed amounts the same way we do
	 * here: it's as if local side paid for all the HTLCs.  We can
	 * fix this by having local side offer an HTLC, and having
	 * remote side accept it */
	send_and_fulfill_htlc(lchannel, LOCAL, 7000000);
	send_and_fulfill_htlc(rchannel, REMOTE, 7000000);

	assert(lchannel->view[LOCAL].owed_msat[LOCAL]
	       == rchannel->view[REMOTE].owed_msat[REMOTE]);
	assert(lchannel->view[REMOTE].owed_msat[REMOTE]
	       == rchannel->view[LOCAL].owed_msat[LOCAL]);

	txs = channel_txs(tmpctx, &htlc_map, &wscripts,
			  lchannel, &local_per_commitment_point, 42, LOCAL);
	assert(tal_count(txs) == 1);
	txs2 = channel_txs(tmpctx, &htlc_map, &wscripts,
			   rchannel, &local_per_commitment_point, 42, REMOTE);
	txs_must_be_eq(txs, txs2);

	update_feerate(lchannel, feerate_per_kw[LOCAL]);
	update_feerate(rchannel, feerate_per_kw[REMOTE]);

	htlcs = include_htlcs(lchannel, LOCAL);
	include_htlcs(rchannel, REMOTE);

	assert(lchannel->view[LOCAL].owed_msat[LOCAL]
	       == rchannel->view[REMOTE].owed_msat[REMOTE]);
	assert(lchannel->view[REMOTE].owed_msat[REMOTE]
	       == rchannel->view[LOCAL].owed_msat[LOCAL]);

	txs = channel_txs(tmpctx, &htlc_map, &wscripts,
			  lchannel, &local_per_commitment_point, 42, LOCAL);
	assert(tal_count(txs) == 6);
	txs2 = channel_txs(tmpctx, &htlc_map, &wscripts,
			   rchannel, &local_per_commitment_point, 42, REMOTE);
	txs_must_be_eq(txs, txs2);

	/* FIXME: Compare signatures! */
	/* BOLT #3:
	 *
	 *     output htlc_success_tx 0: 020000000001018154ecccf11a5fb56c39654c4deb4d2296f83c69268280b94d021370c94e219700000000000000000001e8030000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e050047304402206a6e59f18764a5bf8d4fa45eebc591566689441229c918b480fb2af8cc6a4aeb02205248f273be447684b33e3c8d1d85a8e0ca9fa0bae9ae33f0527ada9c162919a60147304402207cb324fa0de88f452ffa9389678127ebcf4cabe1dd848b8e076c1a1962bf34720220116ed922b12311bd602d67e60d2529917f21c5b82f25ff6506c0f87886b4dfd5012000000000000000000000000000000000000000000000000000000000000000008a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a914b8bcb07f6344b42ab04250c86a6e8b75d3fdbbc688527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f401b175ac686800000000
	 */
	raw_tx = tx_from_hex(tmpctx, "020000000001018154ecccf11a5fb56c39654c4deb4d2296f83c69268280b94d021370c94e219700000000000000000001e8030000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e050047304402206a6e59f18764a5bf8d4fa45eebc591566689441229c918b480fb2af8cc6a4aeb02205248f273be447684b33e3c8d1d85a8e0ca9fa0bae9ae33f0527ada9c162919a60147304402207cb324fa0de88f452ffa9389678127ebcf4cabe1dd848b8e076c1a1962bf34720220116ed922b12311bd602d67e60d2529917f21c5b82f25ff6506c0f87886b4dfd5012000000000000000000000000000000000000000000000000000000000000000008a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a914b8bcb07f6344b42ab04250c86a6e8b75d3fdbbc688527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f401b175ac686800000000");
	raw_tx->input[0].witness = NULL;
	tx_must_be_eq(raw_tx, txs[1]);

	/* BOLT #3:
	 *
	 *     output htlc_timeout_tx 2: 020000000001018154ecccf11a5fb56c39654c4deb4d2296f83c69268280b94d021370c94e219701000000000000000001d0070000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100d5275b3619953cb0c3b5aa577f04bc512380e60fa551762ce3d7a1bb7401cff9022037237ab0dac3fe100cde094e82e2bed9ba0ed1bb40154b48e56aa70f259e608b01483045022100c89172099507ff50f4c925e6c5150e871fb6e83dd73ff9fbb72f6ce829a9633f02203a63821d9162e99f9be712a68f9e589483994feae2661e4546cd5b6cec007be501008576a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a914b43e1b38138a41b37f7cd9a1d274bc63e3a9b5d188ac6868f6010000
	 */
	raw_tx = tx_from_hex(tmpctx, "020000000001018154ecccf11a5fb56c39654c4deb4d2296f83c69268280b94d021370c94e219701000000000000000001d0070000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100d5275b3619953cb0c3b5aa577f04bc512380e60fa551762ce3d7a1bb7401cff9022037237ab0dac3fe100cde094e82e2bed9ba0ed1bb40154b48e56aa70f259e608b01483045022100c89172099507ff50f4c925e6c5150e871fb6e83dd73ff9fbb72f6ce829a9633f02203a63821d9162e99f9be712a68f9e589483994feae2661e4546cd5b6cec007be501008576a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a914b43e1b38138a41b37f7cd9a1d274bc63e3a9b5d188ac6868f6010000");
	raw_tx->input[0].witness = NULL;
	tx_must_be_eq(raw_tx, txs[2]);

	/* BOLT #3:
	 *
	 *     output htlc_success_tx 1: 020000000001018154ecccf11a5fb56c39654c4deb4d2296f83c69268280b94d021370c94e219702000000000000000001d0070000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e050047304402201b63ec807771baf4fdff523c644080de17f1da478989308ad13a58b51db91d360220568939d38c9ce295adba15665fa68f51d967e8ed14a007b751540a80b325f20201483045022100def389deab09cee69eaa1ec14d9428770e45bcbe9feb46468ecf481371165c2f022015d2e3c46600b2ebba8dcc899768874cc6851fd1ecb3fffd15db1cc3de7e10da012001010101010101010101010101010101010101010101010101010101010101018a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a9144b6b2e5444c2639cc0fb7bcea5afba3f3cdce23988527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f501b175ac686800000000
	 */
	raw_tx = tx_from_hex(tmpctx, "020000000001018154ecccf11a5fb56c39654c4deb4d2296f83c69268280b94d021370c94e219702000000000000000001d0070000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e050047304402201b63ec807771baf4fdff523c644080de17f1da478989308ad13a58b51db91d360220568939d38c9ce295adba15665fa68f51d967e8ed14a007b751540a80b325f20201483045022100def389deab09cee69eaa1ec14d9428770e45bcbe9feb46468ecf481371165c2f022015d2e3c46600b2ebba8dcc899768874cc6851fd1ecb3fffd15db1cc3de7e10da012001010101010101010101010101010101010101010101010101010101010101018a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a9144b6b2e5444c2639cc0fb7bcea5afba3f3cdce23988527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f501b175ac686800000000");
	raw_tx->input[0].witness = NULL;
	tx_must_be_eq(raw_tx, txs[3]);

	/* BOLT #3:
	 *
	 *     output htlc_timeout_tx 3: 020000000001018154ecccf11a5fb56c39654c4deb4d2296f83c69268280b94d021370c94e219703000000000000000001b80b0000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100daee1808f9861b6c3ecd14f7b707eca02dd6bdfc714ba2f33bc8cdba507bb182022026654bf8863af77d74f51f4e0b62d461a019561bb12acb120d3f7195d148a554014730440220643aacb19bbb72bd2b635bc3f7375481f5981bace78cdd8319b2988ffcc6704202203d27784ec8ad51ed3bd517a05525a5139bb0b755dd719e0054332d186ac0872701008576a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a9148a486ff2e31d6158bf39e2608864d63fefd09d5b88ac6868f7010000
	 */
	raw_tx = tx_from_hex(tmpctx, "020000000001018154ecccf11a5fb56c39654c4deb4d2296f83c69268280b94d021370c94e219703000000000000000001b80b0000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100daee1808f9861b6c3ecd14f7b707eca02dd6bdfc714ba2f33bc8cdba507bb182022026654bf8863af77d74f51f4e0b62d461a019561bb12acb120d3f7195d148a554014730440220643aacb19bbb72bd2b635bc3f7375481f5981bace78cdd8319b2988ffcc6704202203d27784ec8ad51ed3bd517a05525a5139bb0b755dd719e0054332d186ac0872701008576a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a9148a486ff2e31d6158bf39e2608864d63fefd09d5b88ac6868f7010000");
	raw_tx->input[0].witness = NULL;
	tx_must_be_eq(raw_tx, txs[4]);

	/* BOLT #3:
	 *
	 *     output htlc_success_tx 4: 020000000001018154ecccf11a5fb56c39654c4deb4d2296f83c69268280b94d021370c94e219704000000000000000001a00f0000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e050047304402207e0410e45454b0978a623f36a10626ef17b27d9ad44e2760f98cfa3efb37924f0220220bd8acd43ecaa916a80bd4f919c495a2c58982ce7c8625153f8596692a801d014730440220549e80b4496803cbc4a1d09d46df50109f546d43fbbf86cd90b174b1484acd5402205f12a4f995cb9bded597eabfee195a285986aa6d93ae5bb72507ebc6a4e2349e012004040404040404040404040404040404040404040404040404040404040404048a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a91418bc1a114ccf9c052d3d23e28d3b0a9d1227434288527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f801b175ac686800000000
	 */
	raw_tx = tx_from_hex(tmpctx, "020000000001018154ecccf11a5fb56c39654c4deb4d2296f83c69268280b94d021370c94e219704000000000000000001a00f0000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e050047304402207e0410e45454b0978a623f36a10626ef17b27d9ad44e2760f98cfa3efb37924f0220220bd8acd43ecaa916a80bd4f919c495a2c58982ce7c8625153f8596692a801d014730440220549e80b4496803cbc4a1d09d46df50109f546d43fbbf86cd90b174b1484acd5402205f12a4f995cb9bded597eabfee195a285986aa6d93ae5bb72507ebc6a4e2349e012004040404040404040404040404040404040404040404040404040404040404048a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a91418bc1a114ccf9c052d3d23e28d3b0a9d1227434288527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f801b175ac686800000000");
	raw_tx->input[0].witness = NULL;
	tx_must_be_eq(raw_tx, txs[5]);

	/* FIXME: Compare HTLCs for these too! */
	for (i = 0; i < ARRAY_SIZE(feerates); i++) {
		feerate_per_kw[LOCAL] = feerate_per_kw[REMOTE] = feerates[i];

		lchannel->view[LOCAL].feerate_per_kw = feerate_per_kw[LOCAL];
		rchannel->view[REMOTE].feerate_per_kw = feerate_per_kw[REMOTE];

		raw_tx = commit_tx(tmpctx, &funding_txid, funding_output_index,
				   funding_amount_satoshi,
				   LOCAL, remote_config->to_self_delay,
				   &keyset,
				   feerate_per_kw[LOCAL],
				   local_config->dust_limit_satoshis,
				   to_local_msat,
				   to_remote_msat,
				   htlcs, &htlc_map,
				   0x2bb038521914 ^ 42, LOCAL);

		txs = channel_txs(tmpctx, &htlc_map, &wscripts,
				  lchannel, &local_per_commitment_point,
				  42, LOCAL);
		tx_must_be_eq(txs[0], raw_tx);

		txs2 = channel_txs(tmpctx,  &htlc_map, &wscripts,
				   rchannel, &local_per_commitment_point,
				   42, REMOTE);
		txs_must_be_eq(txs, txs2);
	}

	/* No memory leaks please */
	wally_cleanup(0);
	tal_free(tmpctx);

	/* FIXME: Do BOLT comparison! */
	return 0;
}
