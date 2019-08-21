/* Code to make a commitment tx, useful for generating test cases.
 *
 * For example, in the spec tests we use the following:
 *
 * lightning/devtools/mkcommit 0 41085b995c1f591cfc3ae79ccde012bf0b37c7bde23d80a61c9732bdd6210b2f 0 999878sat 253 999878sat local \
   5 546 9900sat						\
   6 546 9900sat							\
   0000000000000000000000000000000000000000000000000000000000000020 0000000000000000000000000000000000000000000000000000000000000000 0000000000000000000000000000000000000000000000000000000000000021 0000000000000000000000000000000000000000000000000000000000000022 0000000000000000000000000000000000000000000000000000000000000023 0000000000000000000000000000000000000000000000000000000000000024 \
   0000000000000000000000000000000000000000000000000000000000000010 FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF 0000000000000000000000000000000000000000000000000000000000000011 0000000000000000000000000000000000000000000000000000000000000012 0000000000000000000000000000000000000000000000000000000000000013 0000000000000000000000000000000000000000000000000000000000000014
 */
#include <bitcoin/script.h>
#include <bitcoin/tx.h>
#include <ccan/err/err.h>
#include <ccan/str/hex/hex.h>
#include <channeld/full_channel.h>
#include <common/amount.h>
#include <common/derive_basepoints.h>
#include <common/htlc_wire.h>
#include <common/key_derive.h>
#include <common/keyset.h>
#include <common/status.h>
#include <common/type_to_string.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>

static bool verbose = false;

void status_fmt(enum log_level level, const char *fmt, ...)
{
	if (verbose) {
		va_list ap;

		va_start(ap, fmt);
		printf("#TRACE: ");
		vprintf(fmt, ap);
		printf("\n");
		va_end(ap);
	}
}

void status_failed(enum status_failreason reason, const char *fmt, ...)
{
	abort();
}

static int parse_secrets(char *argv[],
			 struct secrets *secrets,
			 struct sha256 *seed,
			 const char *desc)
{
	int argnum = 0;
	if (!hex_decode(argv[argnum], strlen(argv[argnum]),
			&secrets->funding_privkey,
			sizeof(secrets->funding_privkey)))
		errx(1, "Parsing %s.funding_privkey", desc);
	argnum++;
	if (!hex_decode(argv[argnum], strlen(argv[argnum]),
			seed, sizeof(*seed)))
		errx(1, "Parsing %s seed", desc);
	argnum++;
	if (!hex_decode(argv[argnum], strlen(argv[argnum]),
			&secrets->revocation_basepoint_secret,
			sizeof(secrets->revocation_basepoint_secret)))
		errx(1, "Parsing %s.revocation_basepoint_secret", desc);
	argnum++;
	if (!hex_decode(argv[argnum], strlen(argv[argnum]),
			&secrets->payment_basepoint_secret,
			sizeof(secrets->payment_basepoint_secret)))
		errx(1, "Parsing %s.payment_basepoint_secret", desc);
	argnum++;
	if (!hex_decode(argv[argnum], strlen(argv[argnum]),
			&secrets->delayed_payment_basepoint_secret,
			sizeof(secrets->delayed_payment_basepoint_secret)))
		errx(1, "Parsing %s.delayed_payment_basepoint_secret", desc);
	argnum++;
	if (!hex_decode(argv[argnum], strlen(argv[argnum]),
			&secrets->htlc_basepoint_secret,
			sizeof(secrets->htlc_basepoint_secret)))
		errx(1, "Parsing %s.htlc_basepoint_secret", desc);
	argnum++;
	return argnum;
}

static void print_basepoints(const char *desc,
			     const struct secrets *secrets,
			     const struct sha256 *shaseed,
			     const struct basepoints *basepoints,
			     const struct pubkey *fundingkey,
			     u64 commitnum)
{
	struct secret per_commitment_secret;
	struct pubkey per_commitment_point;

	printf("## %s\n", desc);
	printf("# funding_privkey=%s\n",
	       type_to_string(NULL, struct secret, &secrets->funding_privkey.secret));
	printf("funding_pubkey=%s\n",
	       type_to_string(NULL, struct pubkey, fundingkey));
	printf("# revocation_basepoint_secret=%s\n",
	       type_to_string(NULL, struct secret,
			      &secrets->revocation_basepoint_secret));
	printf("revocation_basepoint=%s\n",
	       type_to_string(NULL, struct pubkey, &basepoints->revocation));
	printf("# payment_basepoint_secret=%s\n",
	       type_to_string(NULL, struct secret,
			      &secrets->payment_basepoint_secret));
	printf("payment_basepoint=%s\n",
	       type_to_string(NULL, struct pubkey, &basepoints->payment));
	printf("# delayed_payment_basepoint_secret=%s\n",
	       type_to_string(NULL, struct secret,
			      &secrets->delayed_payment_basepoint_secret));
	printf("delayed_payment_basepoint=%s\n",
	       type_to_string(NULL, struct pubkey, &basepoints->delayed_payment));
	printf("# htlc_basepoint_secret=%s\n",
	       type_to_string(NULL, struct secret,
			      &secrets->htlc_basepoint_secret));
	printf("htlc_basepoint=%s\n",
	       type_to_string(NULL, struct pubkey, &basepoints->htlc));
	if (!per_commit_secret(shaseed, &per_commitment_secret, commitnum))
		errx(1, "Bad deriving %s per_commitment_secret #%"PRIu64,
		     desc, commitnum);
	if (!per_commit_point(shaseed, &per_commitment_point, commitnum))
		errx(1, "Bad deriving %s per_commitment_point #%"PRIu64,
		     desc, commitnum);
	printf("# shachain seed=%s\n",
	       type_to_string(NULL, struct sha256, shaseed));
	printf("# per_commitment_secret %"PRIu64"=%s\n",
	       commitnum,
	       type_to_string(NULL, struct secret,  &per_commitment_secret));
	printf("per_commitment_point %"PRIu64"=%s\n\n",
	       commitnum,
	       type_to_string(NULL, struct pubkey, &per_commitment_point));
}

static int parse_config(char *argv[],
			struct channel_config *config,
			const char *desc)
{
	int argnum = 0;

	config->id = 0;
	/* FIXME: Allow overriding these on cmdline! */
	config->max_htlc_value_in_flight = AMOUNT_MSAT(-1ULL);
	config->htlc_minimum = AMOUNT_MSAT(0);
	config->max_accepted_htlcs = 483;

	config->to_self_delay = atoi(argv[argnum]);
	argnum++;
	if (!parse_amount_sat(&config->dust_limit,
			      argv[argnum], strlen(argv[argnum])))
		errx(1, "Bad %s dustlimit", desc);
	argnum++;
	if (!parse_amount_sat(&config->channel_reserve,
			      argv[argnum], strlen(argv[argnum])))
		errx(1, "Bad %s reserve", desc);
	argnum++;
	return argnum;
}

static char *sig_as_hex(const struct bitcoin_signature *sig)
{
	u8 compact_sig[64];

	secp256k1_ecdsa_signature_serialize_compact(secp256k1_ctx,
						    compact_sig,
						    &sig->s);
	return tal_hexstr(NULL, compact_sig, sizeof(compact_sig));
}

static int parse_htlc(char *argv[],
		      struct added_htlc **htlcs,
		      enum htlc_state **htlc_states,
		      struct preimage **preimages)
{
	struct added_htlc add;
	int argnum = 0;
	struct preimage preimage;

	add.id = tal_count(*htlcs);
	if (streq(argv[argnum], "local"))
		tal_arr_expand(htlc_states, SENT_ADD_ACK_REVOCATION);
	else if (streq(argv[argnum], "remote"))
		tal_arr_expand(htlc_states, RCVD_ADD_ACK_REVOCATION);
	else
		errx(1, "Bad htlc offer: %s should be 'local' or 'remote'",
		     argv[argnum]);
	argnum++;
	if (!hex_decode(argv[argnum], strlen(argv[argnum]),
			&preimage, sizeof(preimage)))
		errx(1, "Bad payment-preimage %s", argv[argnum]);
	tal_arr_expand(preimages, preimage);
	sha256(&add.payment_hash, &preimage, sizeof(preimage));
	argnum++;
	if (!parse_amount_msat(&add.amount,
			       argv[argnum], strlen(argv[argnum])))
		errx(1, "Bad htlc amount %s", argv[argnum]);
	argnum++;
	add.cltv_expiry = atoi(argv[argnum]);
	argnum++;

	printf("# HTLC %"PRIu64": %s amount=%s preimage=%s payment_hash=%s cltv=%u\n",
	       add.id, argv[0],
	       type_to_string(tmpctx, struct amount_msat, &add.amount),
	       type_to_string(tmpctx, struct preimage, &preimage),
	       type_to_string(tmpctx, struct sha256, &add.payment_hash),
	       add.cltv_expiry);

	tal_arr_expand(htlcs, add);
	return argnum;
}

static const struct preimage *preimage_of(const struct sha256 *hash,
					  const struct added_htlc *htlcs,
					  const struct preimage *preimages)
{
	for (size_t i = 0; i < tal_count(preimages); i++)
		if (sha256_eq(hash, &htlcs[i].payment_hash))
			return preimages + i;
	abort();
}

int main(int argc, char *argv[])
{
	struct secrets local, remote;
	struct sha256 localseed, remoteseed;
	struct basepoints localbase, remotebase;
	struct pubkey funding_localkey, funding_remotekey;
	u64 commitnum;
	struct amount_sat funding_amount;
	struct bitcoin_txid funding_txid;
	unsigned int funding_outnum;
	u32 feerate_per_kw[NUM_SIDES];
	struct pubkey local_per_commit_point, remote_per_commit_point;
	struct bitcoin_signature local_sig, remote_sig;
	struct channel_config localconfig, remoteconfig;
	struct amount_msat local_msat, remote_msat;
	int argnum;
	struct bitcoin_tx **local_txs, **remote_txs;
	enum side fee_payer;
	u8 **witness;
	const u8 **wscripts;
	struct channel *channel;
	struct added_htlc *htlcs = tal_arr(NULL, struct added_htlc, 0);
	enum htlc_state *hstates = tal_arr(NULL, enum htlc_state, 0);
	struct preimage *preimages = tal_arr(NULL, struct preimage, 0);
	const struct htlc **htlcmap;
	struct privkey local_htlc_privkey, remote_htlc_privkey;
	struct pubkey local_htlc_pubkey, remote_htlc_pubkey;
	const struct chainparams *chainparams = chainparams_for_network("bitcoin");

	setup_locale();

	secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY |
						 SECP256K1_CONTEXT_SIGN);

	if (argv[1] && streq(argv[1], "-v")) {
		verbose = true;
		argv++;
		argc--;
	}

	if (argc < 1 + 7 + 3*2 + 6*2)
		errx(1, "Usage: mkcommit [-v] <commitnum> <funding-txid> <funding-txout> <funding-amount> <feerate-per-kw> <local-msat> <fee-payer> <localconfig> <remoteconfig> <localsecrets> <remotesecrets> [<htlc>...]\n"
		     "Where <config> are:\n"
		     "   <to-self-delay>\n"
		     "   <dustlimit>\n"
		     "   <reserve-sat>\n"
		     "Where <secrets> are:\n"
		     "   <funding-privkey>\n"
		     "   <shachain-seed>\n"
		     "   <revocation-base-secret>\n"
		     "   <payment-base-secret>\n"
		     "   <delayed-payment-base-secret>\n"
		     "   <htlc-base-secret>\n"
		     "Where <htlc>s are:\n"
		     "   <offer-side>\n"
		     "   <payment-preimage>\n"
		     "   <amount-msat>\n"
		     "   <cltv-expiry>\n");

	argnum = 1;
	commitnum = atol(argv[argnum++]);
	if (!bitcoin_txid_from_hex(argv[argnum],
				   strlen(argv[argnum]), &funding_txid))
		errx(1, "Bad funding-txid");
	argnum++;
	funding_outnum = atoi(argv[argnum++]);
	if (!parse_amount_sat(&funding_amount, argv[argnum], strlen(argv[argnum])))
		errx(1, "Bad funding-amount");
	argnum++;
	feerate_per_kw[LOCAL] = feerate_per_kw[REMOTE] = atoi(argv[argnum++]);
	if (!parse_amount_msat(&local_msat,
			       argv[argnum], strlen(argv[argnum])))
		errx(1, "Bad local-msat");
	argnum++;
	if (streq(argv[argnum], "local"))
		fee_payer = LOCAL;
	else if (streq(argv[argnum], "remote"))
		fee_payer = REMOTE;
	else
		errx(1, "fee-payer must be 'local' or 'remote'");
	argnum++;

	argnum += parse_config(argv + argnum, &localconfig, "local");
	argnum += parse_config(argv + argnum, &remoteconfig, "remote");

	argnum += parse_secrets(argv + argnum, &local, &localseed, "local");
	argnum += parse_secrets(argv + argnum, &remote, &remoteseed, "remote");

	if (!amount_sat_sub_msat(&remote_msat, funding_amount, local_msat))
		errx(1, "Can't afford local_msat");

	printf("## HTLCs\n");
	while (argnum < argc)
		argnum += parse_htlc(argv + argnum, &htlcs, &hstates, &preimages);
	printf("\n");

	if (!pubkey_from_privkey(&local.funding_privkey, &funding_localkey)
	    || !pubkey_from_secret(&local.revocation_basepoint_secret,
				   &localbase.revocation)
	    || !pubkey_from_secret(&local.payment_basepoint_secret,
				   &localbase.payment)
	    || !pubkey_from_secret(&local.delayed_payment_basepoint_secret,
				   &localbase.delayed_payment)
	    || !pubkey_from_secret(&local.htlc_basepoint_secret,
				   &localbase.htlc))
		errx(1, "Bad deriving local basepoints");

	if (!pubkey_from_privkey(&remote.funding_privkey, &funding_remotekey)
	    || !pubkey_from_secret(&remote.revocation_basepoint_secret,
				   &remotebase.revocation)
	    || !pubkey_from_secret(&remote.payment_basepoint_secret,
				   &remotebase.payment)
	    || !pubkey_from_secret(&remote.delayed_payment_basepoint_secret,
				   &remotebase.delayed_payment)
	    || !pubkey_from_secret(&remote.htlc_basepoint_secret,
				   &remotebase.htlc))
		errx(1, "Bad deriving remote basepoints");

	print_basepoints("local",
			 &local, &localseed,
			 &localbase, &funding_localkey, commitnum);
	print_basepoints("remote",
			 &remote, &remoteseed,
			 &remotebase, &funding_remotekey, commitnum);

	channel = new_full_channel(NULL,
				   &chainparams_for_network("regtest")
				   ->genesis_blockhash,
				   &funding_txid, funding_outnum, 1,
				   funding_amount,
				   local_msat,
				   feerate_per_kw,
				   &localconfig, &remoteconfig,
				   &localbase, &remotebase,
				   &funding_localkey, &funding_remotekey,
				   fee_payer);

	if (!channel_force_htlcs(channel, htlcs, hstates, NULL, NULL, NULL, NULL))
		errx(1, "Cannot add HTLCs");

	u8 *funding_wscript = bitcoin_redeem_2of2(NULL,
						  &funding_localkey,
						  &funding_remotekey);

	/* Create the local commitment_tx */
	if (!per_commit_point(&localseed, &local_per_commit_point, commitnum))
		errx(1, "Bad deriving local per-commitment-point");

	local_txs = channel_txs(NULL, chainparams, &htlcmap, &wscripts, channel,
				&local_per_commit_point, commitnum, LOCAL);

	printf("## local_commitment\n"
	       "# input amount %s, funding_wscript %s, key %s\n",
	       type_to_string(NULL, struct amount_sat, &funding_amount),
	       tal_hex(NULL, funding_wscript),
	       type_to_string(NULL, struct pubkey, &funding_localkey));
	printf("# unsigned local commitment tx: %s\n",
	       tal_hex(NULL, linearize_tx(NULL, local_txs[0])));

	sign_tx_input(local_txs[0], 0, NULL, funding_wscript,
		      &local.funding_privkey,
		      &funding_localkey,
		      SIGHASH_ALL,
		      &local_sig);
	printf("localsig_on_local: %s\n", sig_as_hex(&local_sig));

	sign_tx_input(local_txs[0], 0, NULL, funding_wscript,
		      &remote.funding_privkey,
		      &funding_remotekey,
		      SIGHASH_ALL,
		      &remote_sig);
	printf("remotesig_on_local: %s\n", sig_as_hex(&remote_sig));

	witness =
		bitcoin_witness_2of2(NULL, &local_sig, &remote_sig,
				     &funding_localkey, &funding_remotekey);
	bitcoin_tx_input_set_witness(local_txs[0], 0, take(witness));

	printf("# signed local commitment: %s\n",
	       tal_hex(NULL, linearize_tx(NULL, local_txs[0])));

	if (!derive_simple_privkey(&local.htlc_basepoint_secret,
				   &localbase.htlc,
				   &local_per_commit_point,
				   &local_htlc_privkey))
		errx(1, "Failure deriving local htlc privkey");

	if (!derive_simple_key(&localbase.htlc,
			       &local_per_commit_point,
			       &local_htlc_pubkey))
		errx(1, "Failure deriving local htlc pubkey");

	if (!derive_simple_privkey(&remote.htlc_basepoint_secret,
				   &remotebase.htlc,
				   &local_per_commit_point,
				   &remote_htlc_privkey))
		errx(1, "Failure deriving remote htlc privkey");

	if (!derive_simple_key(&remotebase.htlc,
			       &local_per_commit_point,
			       &remote_htlc_pubkey))
		errx(1, "Failure deriving remote htlc pubkey");

	for (size_t i = 0; i < tal_count(htlcmap); i++) {
		struct bitcoin_signature local_htlc_sig, remote_htlc_sig;
		struct amount_sat amt;

		if (!htlcmap[i])
			continue;
		printf("# Output %zu: %s HTLC %"PRIu64"\n",
		       i, side_to_str(htlc_owner(htlcmap[i])), htlcmap[i]->id);
		printf("# unsigned htlc tx for output %zu: %s\n",
		       i, tal_hex(NULL, linearize_tx(NULL, local_txs[1+i])));
		amt = amount_msat_to_sat_round_down(htlcmap[i]->amount);
		local_txs[1+i]->input_amounts[0]
			= tal_dup(local_txs[1+i], struct amount_sat, &amt);

		printf("# wscript: %s\n", tal_hex(NULL, wscripts[1+i]));
		sign_tx_input(local_txs[1+i], 0, NULL, wscripts[1+i],
			      &local_htlc_privkey, &local_htlc_pubkey,
			      SIGHASH_ALL, &local_htlc_sig);
		sign_tx_input(local_txs[1+i], 0, NULL, wscripts[1+i],
			      &remote_htlc_privkey, &remote_htlc_pubkey,
			      SIGHASH_ALL, &remote_htlc_sig);
		printf("localsig_on_local output %zu: %s\n",
		       i, sig_as_hex(&local_htlc_sig));
		printf("remotesig_on_local output %zu: %s\n",
		       i, sig_as_hex(&remote_htlc_sig));

		if (htlc_owner(htlcmap[i]) == LOCAL)
			witness = bitcoin_witness_htlc_timeout_tx(NULL,
								  &local_htlc_sig,
								  &remote_htlc_sig,
								  wscripts[1+i]);
		else
			witness = bitcoin_witness_htlc_success_tx(NULL,
								  &local_htlc_sig,
								  &remote_htlc_sig,
								  preimage_of(&htlcmap[i]->rhash, htlcs, preimages),
								  wscripts[1+i]);
		bitcoin_tx_input_set_witness(local_txs[1+i], 0, witness);
		printf("htlc tx for output %zu: %s\n",
		       i, tal_hex(NULL, linearize_tx(NULL, local_txs[1+i])));
	}
	printf("\n");

	/* Create the remote commitment tx */
	if (!per_commit_point(&remoteseed, &remote_per_commit_point, commitnum))
		errx(1, "Bad deriving remote per-commitment-point");
	remote_txs = channel_txs(NULL, chainparams, &htlcmap, &wscripts, channel,
				 &remote_per_commit_point, commitnum, REMOTE);
	remote_txs[0]->input_amounts[0]
		= tal_dup(remote_txs[0], struct amount_sat, &funding_amount);

	printf("## remote_commitment\n"
	       "# input amount %s, funding_wscript %s, key %s\n",
	       type_to_string(NULL, struct amount_sat, &funding_amount),
	       tal_hex(NULL, funding_wscript),
	       type_to_string(NULL, struct pubkey, &funding_remotekey));
	printf("# unsigned remote commitment tx: %s\n",
	       tal_hex(NULL, linearize_tx(NULL, remote_txs[0])));

	sign_tx_input(remote_txs[0], 0, NULL, funding_wscript,
		      &local.funding_privkey,
		      &funding_localkey,
		      SIGHASH_ALL,
		      &local_sig);
	printf("localsig_on_remote: %s\n", sig_as_hex(&local_sig));

	sign_tx_input(remote_txs[0], 0, NULL, funding_wscript,
		      &remote.funding_privkey,
		      &funding_remotekey,
		      SIGHASH_ALL,
		      &remote_sig);
	printf("remotesig_on_remote: %s\n", sig_as_hex(&remote_sig));

	witness =
		bitcoin_witness_2of2(NULL, &local_sig, &remote_sig,
				     &funding_localkey, &funding_remotekey);
	bitcoin_tx_input_set_witness(remote_txs[0], 0, witness);

	printf("# signed remote commitment: %s\n",
	       tal_hex(NULL, linearize_tx(NULL, remote_txs[0])));

	if (!derive_simple_privkey(&local.htlc_basepoint_secret,
				   &localbase.htlc,
				   &remote_per_commit_point,
				   &local_htlc_privkey))
		errx(1, "Failure deriving local htlc privkey");

	if (!derive_simple_key(&localbase.htlc,
			       &remote_per_commit_point,
			       &local_htlc_pubkey))
		errx(1, "Failure deriving local htlc pubkey");

	if (!derive_simple_privkey(&remote.htlc_basepoint_secret,
				   &remotebase.htlc,
				   &remote_per_commit_point,
				   &remote_htlc_privkey))
		errx(1, "Failure deriving remote htlc privkey");

	if (!derive_simple_key(&remotebase.htlc,
			       &remote_per_commit_point,
			       &remote_htlc_pubkey))
		errx(1, "Failure deriving remote htlc pubkey");

	for (size_t i = 0; i < tal_count(htlcmap); i++) {
		struct bitcoin_signature local_htlc_sig, remote_htlc_sig;
		struct amount_sat amt;

		if (!htlcmap[i])
			continue;
		printf("# Output %zu: %s HTLC %"PRIu64"\n",
		       i, side_to_str(htlc_owner(htlcmap[i])), htlcmap[i]->id);
		printf("# unsigned htlc tx for output %zu: %s\n",
		       i, tal_hex(NULL, linearize_tx(NULL, remote_txs[1+i])));
		amt = amount_msat_to_sat_round_down(htlcmap[i]->amount);
		remote_txs[1+i]->input_amounts[0]
			= tal_dup(remote_txs[1+i], struct amount_sat, &amt);

		printf("# wscript: %s\n", tal_hex(NULL, wscripts[1+i]));
		sign_tx_input(remote_txs[1+i], 0, NULL, wscripts[1+i],
			      &local_htlc_privkey, &local_htlc_pubkey,
			      SIGHASH_ALL, &local_htlc_sig);
		sign_tx_input(remote_txs[1+i], 0, NULL, wscripts[1+i],
			      &remote_htlc_privkey, &remote_htlc_pubkey,
			      SIGHASH_ALL, &remote_htlc_sig);
		printf("localsig_on_remote output %zu: %s\n",
		       i, sig_as_hex(&local_htlc_sig));
		printf("remotesig_on_remote output %zu: %s\n",
		       i, sig_as_hex(&remote_htlc_sig));

		if (htlc_owner(htlcmap[i]) == REMOTE)
			witness = bitcoin_witness_htlc_timeout_tx(NULL,
								  &remote_htlc_sig,
								  &local_htlc_sig,
								  wscripts[1+i]);
		else
			witness = bitcoin_witness_htlc_success_tx(NULL,
								  &remote_htlc_sig,
								  &local_htlc_sig,
								  preimage_of(&htlcmap[i]->rhash, htlcs, preimages),
								  wscripts[1+i]);
		bitcoin_tx_input_set_witness(remote_txs[1+i], 0, witness);
		printf("htlc tx for output %zu: %s\n",
		       i, tal_hex(NULL, linearize_tx(NULL, remote_txs[1+i])));
	}
	printf("\n");

	return 0;
}
