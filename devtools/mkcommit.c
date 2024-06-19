/* Code to make a commitment tx, useful for generating test cases.
 *
 * For example, in the spec tests we use the following:
 *
 * lightning/devtools/mkcommit 0 41085b995c1f591cfc3ae79ccde012bf0b37c7bde23d80a61c9732bdd6210b2f 0 999878sat 253 999878sat local \
   5 546 9998sat						\
   6 546 9998sat							\
   0000000000000000000000000000000000000000000000000000000000000020 0000000000000000000000000000000000000000000000000000000000000000 0000000000000000000000000000000000000000000000000000000000000021 0000000000000000000000000000000000000000000000000000000000000022 0000000000000000000000000000000000000000000000000000000000000023 0000000000000000000000000000000000000000000000000000000000000024 \
   0000000000000000000000000000000000000000000000000000000000000010 FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF 0000000000000000000000000000000000000000000000000000000000000011 0000000000000000000000000000000000000000000000000000000000000012 0000000000000000000000000000000000000000000000000000000000000013 0000000000000000000000000000000000000000000000000000000000000014
 */
#include "config.h"
#include <bitcoin/chainparams.h>
#include <bitcoin/script.h>
#include <ccan/cast/cast.h>
#include <ccan/err/err.h>
#include <ccan/opt/opt.h>
#include <ccan/str/hex/hex.h>
#include <ccan/tal/str/str.h>
#include <channeld/full_channel.h>
#include <common/blockheight_states.h>
#include <common/channel_type.h>
#include <common/fee_states.h>
#include <common/htlc_wire.h>
#include <common/key_derive.h>
#include <common/status.h>
#include <common/version.h>
#include <inttypes.h>
#include <stdio.h>

static bool verbose = false;

void status_fmt(enum log_level level,
		const struct node_id *node_id,
		const char *fmt, ...)
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
	       fmt_secret(NULL, &secrets->funding_privkey.secret));
	printf("funding_pubkey=%s\n",
	       fmt_pubkey(NULL, fundingkey));
	printf("# revocation_basepoint_secret=%s\n",
	       fmt_secret(NULL,
			      &secrets->revocation_basepoint_secret));
	printf("revocation_basepoint=%s\n",
	       fmt_pubkey(NULL, &basepoints->revocation));
	printf("# payment_basepoint_secret=%s\n",
	       fmt_secret(NULL,
			      &secrets->payment_basepoint_secret));
	printf("payment_basepoint=%s\n",
	       fmt_pubkey(NULL, &basepoints->payment));
	printf("# delayed_payment_basepoint_secret=%s\n",
	       fmt_secret(NULL,
			      &secrets->delayed_payment_basepoint_secret));
	printf("delayed_payment_basepoint=%s\n",
	       fmt_pubkey(NULL, &basepoints->delayed_payment));
	printf("# htlc_basepoint_secret=%s\n",
	       fmt_secret(NULL,
			      &secrets->htlc_basepoint_secret));
	printf("htlc_basepoint=%s\n",
	       fmt_pubkey(NULL, &basepoints->htlc));
	if (!per_commit_secret(shaseed, &per_commitment_secret, commitnum))
		errx(1, "Bad deriving %s per_commitment_secret #%"PRIu64,
		     desc, commitnum);
	if (!per_commit_point(shaseed, &per_commitment_point, commitnum))
		errx(1, "Bad deriving %s per_commitment_point #%"PRIu64,
		     desc, commitnum);
	printf("# shachain seed=%s\n",
	       fmt_sha256(NULL, shaseed));
	printf("# per_commitment_secret %"PRIu64"=%s\n",
	       commitnum,
	       fmt_secret(NULL,  &per_commitment_secret));
	printf("per_commitment_point %"PRIu64"=%s\n\n",
	       commitnum,
	       fmt_pubkey(NULL, &per_commitment_point));
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
	config->max_dust_htlc_exposure_msat = AMOUNT_MSAT(-1ULL);

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

static int parse_htlc(char *argv[], struct existing_htlc ***htlcs)
{
	struct existing_htlc *exist = tal(*htlcs, struct existing_htlc);
	int argnum = 0;

	exist->id = tal_count(*htlcs);
	if (streq(argv[argnum], "local"))
		exist->state = SENT_ADD_ACK_REVOCATION;
	else if (streq(argv[argnum], "remote"))
		exist->state = RCVD_ADD_ACK_REVOCATION;
	else
		errx(1, "Bad htlc offer: %s should be 'local' or 'remote'",
		     argv[argnum]);
	argnum++;
	exist->payment_preimage = tal(*htlcs, struct preimage);
	if (!hex_decode(argv[argnum], strlen(argv[argnum]),
			exist->payment_preimage, sizeof(*exist->payment_preimage)))
		errx(1, "Bad payment-preimage %s", argv[argnum]);

	sha256(&exist->payment_hash, exist->payment_preimage,
	       sizeof(*exist->payment_preimage));
	argnum++;
	if (!parse_amount_msat(&exist->amount,
			       argv[argnum], strlen(argv[argnum])))
		errx(1, "Bad htlc amount %s", argv[argnum]);
	argnum++;
	exist->cltv_expiry = atoi(argv[argnum]);
	argnum++;

	printf("# HTLC %"PRIu64": %s amount=%s preimage=%s payment_hash=%s cltv=%u\n",
	       exist->id, argv[0],
	       fmt_amount_msat(tmpctx, exist->amount),
	       fmt_preimage(tmpctx, exist->payment_preimage),
	       fmt_sha256(tmpctx, &exist->payment_hash),
	       exist->cltv_expiry);

	tal_arr_expand(htlcs, exist);
	return argnum;
}

static const struct preimage *preimage_of(const struct sha256 *hash,
					  const struct existing_htlc **htlcs)
{
	for (size_t i = 0; i < tal_count(htlcs); i++)
		if (sha256_eq(hash, &htlcs[i]->payment_hash))
			return htlcs[i]->payment_preimage;
	abort();
}

static char *sig_as_hex(const struct bitcoin_signature *sig)
{
	u8 compact_sig[64];

	secp256k1_ecdsa_signature_serialize_compact(secp256k1_ctx,
						    compact_sig,
						    &sig->s);
	return tal_hexstr(NULL, compact_sig, sizeof(compact_sig));
}


static char *sig_notation(const struct sha256_double *hash,
			  const struct privkey *privkey,
			  const struct bitcoin_signature *sig)
{
	const char *pstr = tal_hexstr(NULL, privkey->secret.data, sizeof(privkey->secret.data));
	const char *hstr = fmt_sha256_double(NULL, hash);

	if (verbose)
		return tal_fmt(NULL,
			       "SIG(%s:%s)\n privkey: %s\n tx_hash: %s\n"
			       " sig: %s",
			       pstr, hstr, pstr, hstr, sig_as_hex(sig));

	return tal_fmt(NULL, "SIG(%s:%s)", pstr, hstr);
}

int main(int argc, char *argv[])
{
	struct secrets local, remote;
	struct sha256 localseed, remoteseed;
	struct basepoints localbase, remotebase;
	struct pubkey funding_localkey, funding_remotekey;
	u64 commitnum;
	struct amount_sat funding_amount;
	struct channel_id cid;
	struct bitcoin_outpoint funding;
	u32 feerate_per_kw;
	struct pubkey local_per_commit_point, remote_per_commit_point;
	struct bitcoin_signature local_sig, remote_sig;
	struct channel_config localconfig, remoteconfig;
	struct amount_msat local_msat, remote_msat;
	int argnum;
	struct bitcoin_tx **local_txs, **remote_txs;
	enum side fee_payer;
	u8 **witness;
	const u8 *funding_wscript;
	struct channel *channel;
	struct existing_htlc **htlcs = tal_arr(NULL, struct existing_htlc *, 0);
	const struct htlc **htlcmap;
	struct privkey local_htlc_privkey, remote_htlc_privkey;
	struct pubkey local_htlc_pubkey, remote_htlc_pubkey;
	bool option_static_remotekey = false, option_anchor_outputs = false;
	const struct channel_type *channel_type;
	struct sha256_double hash;
	u32 blockheight = 0;
	int local_anchor_outnum;

	setup_locale();
	chainparams = chainparams_for_network("bitcoin");

	secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY |
						 SECP256K1_CONTEXT_SIGN);

	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "<commitnum> <funding-txid> <funding-txout> <funding-amount> <feerate-per-kw> <local-msat> <fee-payer> <localconfig> <remoteconfig> <localsecrets> <remotesecrets> [<htlc>...]\n"
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
			   "   <cltv-expiry>\n",
			   "Show this message");
	opt_register_noarg("-v|--verbose", opt_set_bool, &verbose,
			   "Increase verbosity");
	opt_register_noarg("--option-static-remotekey", opt_set_bool,
			   &option_static_remotekey,
			   "Use option_static_remotekey generation rules");
	opt_register_noarg("--option-anchor-outputs", opt_set_bool,
			   &option_anchor_outputs,
			   "Use option_anchors_zero_fee_htlc_tx generation rules");
	opt_register_version();

	opt_parse(&argc, argv, opt_log_stderr_exit);

	if (argc < 1 + 7 + 3*2 + 6*2)
		opt_usage_exit_fail("Too few arguments");

	argnum = 1;
	commitnum = atol(argv[argnum++]);
	if (!bitcoin_txid_from_hex(argv[argnum],
				   strlen(argv[argnum]), &funding.txid))
		errx(1, "Bad funding-txid");
	argnum++;
	funding.n = atoi(argv[argnum++]);
	if (!parse_amount_sat(&funding_amount, argv[argnum], strlen(argv[argnum])))
		errx(1, "Bad funding-amount");
	argnum++;
	feerate_per_kw = atoi(argv[argnum++]);
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

	if (option_anchor_outputs) {
		printf("Using option-anchor-outputs\n");
		option_static_remotekey = true;
	}
	if (option_static_remotekey)
		printf("Using option-static-remotekey\n");

	printf("## HTLCs\n");
	while (argnum < argc) {
		if (argnum + 4 > argc)
			opt_usage_exit_fail("Too few arguments for htlc");
		argnum += parse_htlc(argv + argnum, &htlcs);
	}
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

	/* FIXME: option for v2? */
	derive_channel_id(&cid, &funding);

	if (option_anchor_outputs)
		channel_type = channel_type_anchors_zero_fee_htlc(NULL);
	else if (option_static_remotekey)
		channel_type = channel_type_static_remotekey(NULL);
	else
		channel_type = channel_type_none_obsolete(NULL);

	channel = new_full_channel(NULL,
				   &cid,
				   &funding, 1,
				   take(new_height_states(NULL, fee_payer,
							  &blockheight)),
				   0, /* Defaults to no lease */
				   funding_amount,
				   local_msat,
				   take(new_fee_states(NULL, fee_payer,
						       &feerate_per_kw)),
				   &localconfig, &remoteconfig,
				   &localbase, &remotebase,
				   &funding_localkey, &funding_remotekey,
				   channel_type,
				   false,
				   fee_payer);

	if (!channel_force_htlcs(channel,
			 cast_const2(const struct existing_htlc **, htlcs)))
		errx(1, "Cannot add HTLCs");

	/* Create the local commitment_tx */
	if (!per_commit_point(&localseed, &local_per_commit_point, commitnum))
		errx(1, "Bad deriving local per-commitment-point");

	local_txs = channel_txs(NULL, &channel->funding, channel->funding_sats,
				&htlcmap, NULL, &funding_wscript, channel,
				&local_per_commit_point, commitnum,
				LOCAL, 0, 0, &local_anchor_outnum);

	printf("## local_commitment\n"
	       "# input amount %s, funding_wscript %s, pubkey %s\n",
	       fmt_amount_sat(NULL, funding_amount),
	       tal_hex(NULL, funding_wscript),
	       fmt_pubkey(NULL, &funding_localkey));
	printf("# unsigned local commitment tx: %s\n",
	       tal_hex(NULL, linearize_tx(NULL, local_txs[0])));

	/* Get the hash out, for printing */
	bitcoin_tx_hash_for_sig(local_txs[0], 0, funding_wscript,
				SIGHASH_ALL, &hash);
	sign_tx_input(local_txs[0], 0, NULL, funding_wscript,
		      &local.funding_privkey,
		      &funding_localkey,
		      SIGHASH_ALL,
		      &local_sig);
	printf("localsig_on_local: %s\n", sig_notation(&hash,
						       &local.funding_privkey,
						       &local_sig));

	sign_tx_input(local_txs[0], 0, NULL, funding_wscript,
		      &remote.funding_privkey,
		      &funding_remotekey,
		      SIGHASH_ALL,
		      &remote_sig);
	printf("remotesig_on_local: %s\n", sig_notation(&hash,
							&remote.funding_privkey,
							&remote_sig));

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
		u8 *wscript;

		if (!htlcmap[i])
			continue;
		printf("# Output %zu: %s HTLC %"PRIu64"\n",
		       i, side_to_str(htlc_owner(htlcmap[i])), htlcmap[i]->id);
		printf("# unsigned htlc tx for output %zu: %s\n",
		       i, tal_hex(NULL, linearize_tx(NULL, local_txs[1+i])));

		wscript = bitcoin_tx_output_get_witscript(NULL, local_txs[1+i], 1+i);
		printf("# wscript: %s\n", tal_hex(NULL, wscript));

		bitcoin_tx_hash_for_sig(local_txs[1+i], 0, wscript,
					SIGHASH_ALL, &hash);
		sign_tx_input(local_txs[1+i], 0, NULL, wscript,
			      &local_htlc_privkey, &local_htlc_pubkey,
			      SIGHASH_ALL, &local_htlc_sig);
		sign_tx_input(local_txs[1+i], 0, NULL, wscript,
			      &remote_htlc_privkey, &remote_htlc_pubkey,
			      SIGHASH_ALL, &remote_htlc_sig);
		printf("localsig_on_local output %zu: %s\n",
		       i, sig_notation(&hash, &local_htlc_privkey, &local_htlc_sig));
		printf("remotesig_on_local output %zu: %s\n",
		       i, sig_notation(&hash, &remote_htlc_privkey, &remote_htlc_sig));

		if (htlc_owner(htlcmap[i]) == LOCAL)
			witness = bitcoin_witness_htlc_timeout_tx(NULL,
								  &local_htlc_sig,
								  &remote_htlc_sig,
								  wscript);
		else
			witness = bitcoin_witness_htlc_success_tx(NULL,
								  &local_htlc_sig,
								  &remote_htlc_sig,
								  preimage_of(&htlcmap[i]->rhash, cast_const2(const struct existing_htlc **, htlcs)),
								  wscript);
		bitcoin_tx_input_set_witness(local_txs[1+i], 0, witness);
		printf("htlc tx for output %zu: %s\n",
		       i, tal_hex(NULL, linearize_tx(NULL, local_txs[1+i])));
	}
	printf("\n");

	/* Create the remote commitment tx */
	if (!per_commit_point(&remoteseed, &remote_per_commit_point, commitnum))
		errx(1, "Bad deriving remote per-commitment-point");
	remote_txs = channel_txs(NULL, &channel->funding, channel->funding_sats,
				 &htlcmap, NULL, &funding_wscript, channel,
				 &remote_per_commit_point, commitnum,
				 REMOTE, 0, 0, &local_anchor_outnum);

	printf("## remote_commitment\n"
	       "# input amount %s, funding_wscript %s, key %s\n",
	       fmt_amount_sat(NULL, funding_amount),
	       tal_hex(NULL, funding_wscript),
	       fmt_pubkey(NULL, &funding_remotekey));
	printf("# unsigned remote commitment tx: %s\n",
	       tal_hex(NULL, linearize_tx(NULL, remote_txs[0])));

	bitcoin_tx_hash_for_sig(remote_txs[0], 0, funding_wscript,
				SIGHASH_ALL, &hash);
	sign_tx_input(remote_txs[0], 0, NULL, funding_wscript,
		      &local.funding_privkey,
		      &funding_localkey,
		      SIGHASH_ALL,
		      &local_sig);
	printf("localsig_on_remote: %s\n", sig_notation(&hash,
							&local.funding_privkey,
							&local_sig));

	sign_tx_input(remote_txs[0], 0, NULL, funding_wscript,
		      &remote.funding_privkey,
		      &funding_remotekey,
		      SIGHASH_ALL,
		      &remote_sig);
	printf("remotesig_on_remote: %s\n", sig_notation(&hash,
							 &remote.funding_privkey,
							 &remote_sig));

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
		u8 *wscript;

		if (!htlcmap[i])
			continue;
		printf("# Output %zu: %s HTLC %"PRIu64"\n",
		       i, side_to_str(htlc_owner(htlcmap[i])), htlcmap[i]->id);
		printf("# unsigned htlc tx for output %zu: %s\n",
		       i, tal_hex(NULL, linearize_tx(NULL, remote_txs[1+i])));

		wscript = bitcoin_tx_output_get_witscript(NULL, remote_txs[1+i], 1+i);
		printf("# wscript: %s\n", tal_hex(NULL, wscript));
		bitcoin_tx_hash_for_sig(remote_txs[1+i], 0, wscript,
					SIGHASH_ALL, &hash);
		sign_tx_input(remote_txs[1+i], 0, NULL, wscript,
			      &local_htlc_privkey, &local_htlc_pubkey,
			      SIGHASH_ALL, &local_htlc_sig);
		sign_tx_input(remote_txs[1+i], 0, NULL, wscript,
			      &remote_htlc_privkey, &remote_htlc_pubkey,
			      SIGHASH_ALL, &remote_htlc_sig);
		printf("localsig_on_remote output %zu: %s\n",
		       i, sig_notation(&hash, &local_htlc_privkey, &local_htlc_sig));
		printf("remotesig_on_remote output %zu: %s\n",
		       i, sig_notation(&hash, &remote_htlc_privkey, &remote_htlc_sig));

		if (htlc_owner(htlcmap[i]) == REMOTE)
			witness = bitcoin_witness_htlc_timeout_tx(NULL,
								  &remote_htlc_sig,
								  &local_htlc_sig,
								  wscript);
		else
			witness = bitcoin_witness_htlc_success_tx(NULL,
								  &remote_htlc_sig,
								  &local_htlc_sig,
								  preimage_of(&htlcmap[i]->rhash, cast_const2(const struct existing_htlc **, htlcs)),
								  wscript);
		bitcoin_tx_input_set_witness(remote_txs[1+i], 0, witness);
		printf("htlc tx for output %zu: %s\n",
		       i, tal_hex(NULL, linearize_tx(NULL, remote_txs[1+i])));
	}
	printf("\n");

	return 0;
}
