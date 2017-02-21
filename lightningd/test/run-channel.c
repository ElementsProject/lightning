 #include <status.h>
 #include <stdio.h>
#define status_trace(fmt , ...) \
	printf(fmt "\n" , ## __VA_ARGS__)

#include "../key_derive.c"
#include "../channel.c"
#include "../commit_tx.c"
#include "../htlc_tx.c"
#include <bitcoin/preimage.h>
#include <bitcoin/privkey.h>
#include <bitcoin/pubkey.h>
#include <ccan/err/err.h>
#include <ccan/str/hex/hex.h>
#include <type_to_string.h>

static struct sha256 sha256_from_hex(const char *hex)
{
	struct sha256 sha256;
	if (strstarts(hex, "0x"))
		hex += 2;
	if (!hex_decode(hex, strlen(hex), &sha256, sizeof(sha256)))
		abort();
	return sha256;
}

/* bitcoind loves its backwards txids! */
static struct sha256_double txid_from_hex(const char *hex)
{
	struct sha256_double sha256;
	struct sha256 rev = sha256_from_hex(hex);
	size_t i;

	for (i = 0; i < sizeof(rev); i++)
		sha256.sha.u.u8[sizeof(sha256) - 1 - i] = rev.u.u8[i];
	return sha256;
}

/* BOLT #3:
 *
 *     local_feerate_per_kw: 0
 *     ...
 *     local_feerate_per_kw: 678
 *     ...
 *     local_feerate_per_kw: 679
 *     ...
 *     local_feerate_per_kw: 2168
 *     ...
 *     local_feerate_per_kw: 2169
 *     ...
 *     local_feerate_per_kw: 2294
 *     ...
 *     local_feerate_per_kw: 2295
 *     ...
 *     local_feerate_per_kw: 3872
 *     ...
 *     local_feerate_per_kw: 3873
 *     ...
 *     local_feerate_per_kw: 5149
 *     ...
 *     local_feerate_per_kw: 5150
 *     ...
 *     local_feerate_per_kw: 9651180
 *     ...
 *     local_feerate_per_kw: 9651181
 *     ...
 *     local_feerate_per_kw: 9651936
 */
static u64 feerates[] = {
	0,
	678,
	679,
	2168,
	2169,
	2294,
	2295,
	3872,
	3873,
	5149,
	5150,
	9651180,
	9651181,
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
static const struct htlc **add_htlcs(struct channel *channel, enum side side)
{
	int i;
	const struct htlc **htlcs = tal_arr(channel, const struct htlc *, 5);
	u8 *dummy_routing = tal_arr(htlcs, u8, 1254);

	for (i = 0; i < 5; i++) {
		struct preimage preimage;
		struct sha256 hash;
		enum channel_add_err e;
		enum side sender;
		u64 msatoshi;

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
		memset(&preimage, i, sizeof(preimage));
		sha256(&hash, &preimage, sizeof(preimage));
		e = channel_add_htlc(channel, sender, i, msatoshi, 500+i, &hash,
				     dummy_routing);
		assert(e == CHANNEL_ERR_ADD_OK);
		htlcs[i] = channel_get_htlc(channel, sender, i);
	}
	tal_free(dummy_routing);

	/* Now make HTLCs fully committed. */
	channel_sent_commit(channel);
	channel_rcvd_revoke_and_ack(channel);
	channel_rcvd_commit(channel);
	channel_sent_revoke_and_ack(channel);
	channel_sent_commit(channel);
	channel_rcvd_revoke_and_ack(channel);
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
	tal_t *tmpctx = tal_tmpctx(NULL);
	u8 *lina, *linb;
	size_t i, len;

	lina = linearize_tx(tmpctx, a);
	linb = linearize_tx(tmpctx, b);

	len = tal_len(lina);
	if (tal_len(linb) < len)
		len = tal_len(linb);

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
	tal_free(tmpctx);
}

static void send_and_fulfill_htlc(struct channel *channel,
				  enum side sender,
				  u64 msatoshi)
{
	struct preimage r;
	struct sha256 rhash;
	u8 *dummy_routing = tal_arr(channel, u8, 1254);

	memset(&r, 0, sizeof(r));
	sha256(&rhash, &r, sizeof(r));

	assert(channel_add_htlc(channel, sender, 1337, msatoshi, 900, &rhash,
				dummy_routing) == CHANNEL_ERR_ADD_OK);

	if (sender == LOCAL) {
		/* Step through a complete cycle. */
		channel_sent_commit(channel);
		channel_rcvd_revoke_and_ack(channel);
		channel_rcvd_commit(channel);
		channel_sent_revoke_and_ack(channel);
		assert(channel_fulfill_htlc(channel, REMOTE, 1337, &r)
		       == CHANNEL_ERR_REMOVE_OK);
		channel_rcvd_commit(channel);
		channel_sent_revoke_and_ack(channel);
		channel_sent_commit(channel);
		channel_rcvd_revoke_and_ack(channel);
		assert(channel_get_htlc(channel, sender, 1337)->state
		       == RCVD_REMOVE_ACK_REVOCATION);
	} else {
		channel_rcvd_commit(channel);
		channel_sent_revoke_and_ack(channel);
		channel_sent_commit(channel);
		channel_rcvd_revoke_and_ack(channel);
		assert(channel_fulfill_htlc(channel, LOCAL, 1337, &r)
		       == CHANNEL_ERR_REMOVE_OK);
		channel_sent_commit(channel);
		channel_rcvd_revoke_and_ack(channel);
		channel_rcvd_commit(channel);
		channel_sent_revoke_and_ack(channel);
		assert(channel_get_htlc(channel, sender, 1337)->state
		       == SENT_REMOVE_ACK_REVOCATION);
	}
}

int main(void)
{
	tal_t *tmpctx = tal_tmpctx(NULL);
	struct sha256_double funding_txid;
	/* We test from both sides. */
	struct channel *lchannel, *rchannel;
	u64 funding_amount_satoshi, feerate_per_kw;
	unsigned int funding_output_index;
	struct pubkey localkey, remotekey;
	struct pubkey local_delayedkey;
	struct pubkey local_revocation_key;
	struct pubkey local_revocation_basepoint, local_delayed_payment_basepoint,
		local_payment_basepoint, remote_payment_basepoint,
		local_per_commitment_point;
	struct pubkey *unknown = tal(tmpctx, struct pubkey);
	struct bitcoin_tx *raw_tx, *tx;
	struct channel_config *local_config = tal(tmpctx, struct channel_config);
	struct channel_config *remote_config = tal(tmpctx, struct channel_config);
	u64 to_local_msat, to_remote_msat;
	const struct htlc **htlc_map, **htlcs;
	size_t i;

	secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY
						 | SECP256K1_CONTEXT_SIGN);

	/* BOLT #3:
	 *
	 * # Appendix C: Commitment and HTLC Transaction Test Vectors
	 *
	 * In the following:
	 * - we consider *local* transactions, which implies that all payments
         *    to *local* are delayed
	 * - we assume that *local* is the funder
	 * - private keys are displayed as 32 bytes plus a trailing 1
         *    (bitcoin's convention for "compressed" private keys, i.e. keys
         *    for which the public key is compressed)
	 *
	 * - transaction signatures are all deterministic, using
         *    RFC6979 (using HMAC-SHA256)
	 *
	 * We start by defining common basic parameters for each test vector:
	 * the HTLCs are not used for the first "simple commitment tx with no
	 * HTLCs" test.
	 *
	 *     funding_tx_id: 8984484a580b825b9972d7adb15050b3ab624ccd731946b3eeddb92f4e7ef6be
	 *     funding_output_index: 0
	 *     funding_amount_satoshi: 10000000
	 *...
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
	 * # From local_revocation_basepoint_secret
	 * INTERNAL: local_revocation_basepoint: 02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27
	 * # From local_delayed_payment_basepoint_secret
	 * INTERNAL: local_delayed_payment_basepoint: 023c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b1
	*/
	local_revocation_basepoint = pubkey_from_hex("02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27");
	local_delayed_payment_basepoint = pubkey_from_hex("023c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b1");

	/* BOLT #3:
	 *
	 * local_payment_basepoint: 034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa
	 * remote_payment_basepoint: 032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991
	 * # obscured commitment transaction number = 0x2bb038521914 ^ 42
	 */
	local_payment_basepoint = pubkey_from_hex("034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa");
	remote_payment_basepoint = pubkey_from_hex("032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991");

	/* BOLT #3:
	 *
	 *    name: simple commitment tx with no HTLCs
	 *    to_local_msat: 7000000000
	 *    to_remote_msat: 3000000000
	 *    feerate_per_kw: 15000
	 */

	/* We put unknown in for some things; valgrind will warn if used. */
	to_local_msat = 7000000000;
	to_remote_msat = 3000000000;
	feerate_per_kw = 15000;
	lchannel = new_channel(tmpctx, &funding_txid, funding_output_index,
			       funding_amount_satoshi, to_remote_msat,
			       feerate_per_kw,
			       local_config,
			       remote_config,
			       &local_revocation_basepoint,
			       unknown,
			       &local_payment_basepoint,
			       &remote_payment_basepoint,
			       &local_delayed_payment_basepoint,
			       unknown,
			       LOCAL);

	rchannel = new_channel(tmpctx, &funding_txid, funding_output_index,
			       funding_amount_satoshi, to_remote_msat,
			       feerate_per_kw,
			       remote_config,
			       local_config,
			       unknown,
			       &local_revocation_basepoint,
			       &remote_payment_basepoint,
			       &local_payment_basepoint,
			       unknown,
			       &local_delayed_payment_basepoint,
			       REMOTE);
	/* BOLT #3:
	 *
	 *     commitment_number: 42
	 */
	lchannel->view[LOCAL].commitment_number
		= rchannel->view[REMOTE].commitment_number = 42;

	/* BOLT #3:
	 *
	 * INTERNAL: local_per_commitment_point: 025f7117a78150fe2ef97db7cfc83bd57b2e2c0d0dd25eaf467a4a1c2a45ce1486
	 */
	local_per_commitment_point = pubkey_from_hex("025f7117a78150fe2ef97db7cfc83bd57b2e2c0d0dd25eaf467a4a1c2a45ce1486");
	/* BOLT #3:
	 * localkey: 030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e7
	 * remotekey: 0394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b
	 * local_delayedkey: 03fd5960528dc152014952efdb702a88f71e3c1653b2314431701ec77e57fde83c
	 * local_revocation_key: 0212a140cd0c6539d07cd08dfe09984dec3251ea808b892efeac3ede9402bf2b19
	 */
	localkey = pubkey_from_hex("030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e7");
	remotekey = pubkey_from_hex("0394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b");
	local_delayedkey = pubkey_from_hex("03fd5960528dc152014952efdb702a88f71e3c1653b2314431701ec77e57fde83c");
	local_revocation_key = pubkey_from_hex("0212a140cd0c6539d07cd08dfe09984dec3251ea808b892efeac3ede9402bf2b19");

	raw_tx = commit_tx(tmpctx, &funding_txid, funding_output_index,
			   funding_amount_satoshi,
			   LOCAL, remote_config->to_self_delay,
			   &local_revocation_key,
			   &local_delayedkey,
			   &localkey,
			   &remotekey,
			   feerate_per_kw,
			   local_config->dust_limit_satoshis,
			   to_local_msat,
			   to_remote_msat,
			   NULL, &htlc_map, 0x2bb038521914 ^ 42, LOCAL);

	tx = channel_tx(tmpctx, lchannel, &local_per_commitment_point,
			&htlc_map, LOCAL);
	tx_must_be_eq(tx, raw_tx);

	tx = channel_tx(tmpctx, rchannel, &local_per_commitment_point,
			&htlc_map, REMOTE);
	tx_must_be_eq(tx, raw_tx);

	/* BOLT #3:
	 *
	 *    name: commitment tx with all 5 htlcs untrimmed (minimum feerate)
	 *    to_local_msat: 6988000000
	 *    to_remote_msat: 3000000000
	 *    local_feerate_per_kw: 0
	 */
	to_local_msat = 6988000000;
	to_remote_msat = 3000000000;
	feerate_per_kw = 0;

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

	raw_tx = channel_tx(tmpctx, lchannel, &local_per_commitment_point,
			    &htlc_map, LOCAL);
	tx = channel_tx(tmpctx, rchannel, &local_per_commitment_point,
			&htlc_map, REMOTE);
	tx_must_be_eq(tx, raw_tx);

	/* FIXME: Adjust properly! */
	lchannel->view[LOCAL].feerate_per_kw = feerate_per_kw;
	rchannel->view[REMOTE].feerate_per_kw = feerate_per_kw;
	htlcs = add_htlcs(lchannel, LOCAL);
	add_htlcs(rchannel, REMOTE);

	assert(lchannel->view[LOCAL].owed_msat[LOCAL]
	       == rchannel->view[REMOTE].owed_msat[REMOTE]);
	assert(lchannel->view[REMOTE].owed_msat[REMOTE]
	       == rchannel->view[LOCAL].owed_msat[LOCAL]);

	for (i = 0; i < ARRAY_SIZE(feerates); i++) {
		feerate_per_kw = feerates[i];

		lchannel->view[LOCAL].feerate_per_kw = feerate_per_kw;
		rchannel->view[REMOTE].feerate_per_kw = feerate_per_kw;

		raw_tx = commit_tx(tmpctx, &funding_txid, funding_output_index,
				   funding_amount_satoshi,
				   LOCAL, remote_config->to_self_delay,
				   &local_revocation_key,
				   &local_delayedkey,
				   &localkey,
				   &remotekey,
				   feerate_per_kw,
				   local_config->dust_limit_satoshis,
				   to_local_msat,
				   to_remote_msat,
				   htlcs, &htlc_map,
				   0x2bb038521914 ^ 42, LOCAL);

		tx = channel_tx(tmpctx, lchannel, &local_per_commitment_point,
				&htlc_map, LOCAL);
		tx_must_be_eq(tx, raw_tx);

		tx = channel_tx(tmpctx, rchannel, &local_per_commitment_point,
				&htlc_map, REMOTE);
		tx_must_be_eq(tx, raw_tx);
	}

	/* No memory leaks please */
	secp256k1_context_destroy(secp256k1_ctx);
	tal_free(tmpctx);

	/* FIXME: Do BOLT comparison! */
	return 0;
}
