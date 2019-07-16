/* For example, in the spec tests we use the following:
 *
 * lightning/devtools/mkcommit 0 41085b995c1f591cfc3ae79ccde012bf0b37c7bde23d80a61c9732bdd6210b2f 0 999878sat 253 999878sat local \
   6 546 9900sat						\
   6 546 9900sat							\
   0000000000000000000000000000000000000000000000000000000000000020 0000000000000000000000000000000000000000000000000000000000000000 0000000000000000000000000000000000000000000000000000000000000021 0000000000000000000000000000000000000000000000000000000000000022 0000000000000000000000000000000000000000000000000000000000000023 0000000000000000000000000000000000000000000000000000000000000024 \
   0000000000000000000000000000000000000000000000000000000000000010 FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF 0000000000000000000000000000000000000000000000000000000000000011 0000000000000000000000000000000000000000000000000000000000000012 0000000000000000000000000000000000000000000000000000000000000013 0000000000000000000000000000000000000000000000000000000000000014
 */
#include <bitcoin/script.h>
#include <bitcoin/tx.h>
#include <ccan/err/err.h>
#include <ccan/str/hex/hex.h>
#include <common/amount.h>
#include <common/derive_basepoints.h>
#include <common/initial_commit_tx.h>
#include <common/keyset.h>
#include <common/status.h>
#include <common/type_to_string.h>
#include <inttypes.h>
#include <stdio.h>

void status_fmt(enum log_level level, const char *fmt, ...)
{
}

/* Code to make a commitment tx, useful for generating test cases. */
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
		errx(1, "Bad deriving %s per_commitment_secret", desc);
	if (!per_commit_point(shaseed, &per_commitment_point, commitnum))
		errx(1, "Bad deriving %s per_commitment_point", desc);
	printf("# shachain seed=%s\n",
	       type_to_string(NULL, struct sha256, shaseed));
	printf("# per_commitment_secret %"PRIu64"=%s\n",
	       commitnum,
	       type_to_string(NULL, struct secret,  &per_commitment_secret));
	printf("per_commitment_point %"PRIu64"=%s\n\n",
	       commitnum,
	       type_to_string(NULL, struct pubkey, &per_commitment_point));
}

struct settings {
	u32 to_self_delay;
	struct amount_sat dustlimit;
	struct amount_sat reserve;
};

static int parse_settings(char *argv[],
			 struct settings *settings,
			 const char *desc)
{
	int argnum = 0;
	settings->to_self_delay = atoi(argv[argnum]);
	argnum++;
	if (!parse_amount_sat(&settings->dustlimit,
			      argv[argnum], strlen(argv[argnum])))
		errx(1, "Bad %s dustlimit", desc);
	argnum++;
	if (!parse_amount_sat(&settings->reserve,
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
	unsigned int feerate_per_kw;
	struct pubkey local_per_commit_point, remote_per_commit_point;
	struct keyset localkeys, remotekeys;
	struct bitcoin_signature local_sig, remote_sig;
	struct settings localsettings, remotesettings;
	struct amount_msat local_msat, remote_msat;
	int argnum;
	struct bitcoin_tx *local_tx, *remote_tx;
	enum side fee_payer;
	char *err;
	u8 **witness;

	setup_locale();

	secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY |
						 SECP256K1_CONTEXT_SIGN);

	if (argc != 1 + 7 + 3*2 + 6*2)
		errx(1, "Usage: mkcommit <commitnum> <funding-txid> <funding-txout> <funding-amount> <feerate-per-kw> <local-msat> <fee-payer> <localsettings> <remotesettings> <remote-reserve> <localsecrets> <remotesecrets>\n"
		     "Where <settings> are:\n"
		     "   <to-self-delay>\n"
		     "   <dustlimit>\n"
		     "   <reserve-sat>\n"
		     "Where <secrets> are:\n"
		     "   <funding-privkey>\n"
		     "   <shachain-seed>\n"
		     "   <revocation-base-secret>\n"
		     "   <payment-base-secret>\n"
		     "   <delayed-payment-base-secret>\n"
		     "   <htlc-base-secret>");

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

	argnum += parse_settings(argv + argnum, &localsettings, "local");
	argnum += parse_settings(argv + argnum, &remotesettings, "remote");

	argnum += parse_secrets(argv + argnum, &local, &localseed, "local");
	argnum += parse_secrets(argv + argnum, &remote, &remoteseed, "remote");

	if (!amount_sat_sub_msat(&remote_msat, funding_amount, local_msat))
		errx(1, "Can't afford local_msat");

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

	u8 *funding_wscript = bitcoin_redeem_2of2(NULL,
						  &funding_localkey,
						  &funding_remotekey);

	/* Create the local commitment_tx */
	if (!per_commit_point(&localseed, &local_per_commit_point, commitnum))
		errx(1, "Bad deriving local per-commitment-point");

	if (!derive_keyset(&local_per_commit_point, &localbase, &remotebase,
			   &localkeys))
		errx(1, "Bad deriving local keyset");

	local_tx = initial_commit_tx(NULL, &funding_txid, funding_outnum,
				     funding_amount, fee_payer,
				     localsettings.to_self_delay,
				     &localkeys,
				     feerate_per_kw,
				     localsettings.dustlimit,
				     local_msat,
				     remote_msat,
				     localsettings.reserve,
				     commitnum
				     ^ commit_number_obscurer(&localbase.payment,
							      &remotebase.payment),
				     LOCAL, &err);
	if (!local_tx)
		errx(1, "Can't make local commit tx: %s", err);
	local_tx->input_amounts[0]
		= tal_dup(local_tx, struct amount_sat, &funding_amount);

	printf("## local_commitment\n"
	       "# input amount %s, funding_wscript %s, key %s\n",
	       type_to_string(NULL, struct amount_sat, &funding_amount),
	       tal_hex(NULL, funding_wscript),
	       type_to_string(NULL, struct pubkey, &funding_localkey));
	printf("# unsigned local commitment tx: %s\n",
	       tal_hex(NULL, linearize_tx(NULL, local_tx)));

	sign_tx_input(local_tx, 0, NULL, funding_wscript,
		      &local.funding_privkey,
		      &funding_localkey,
		      SIGHASH_ALL,
		      &local_sig);
	printf("localsig_on_local: %s\n", sig_as_hex(&local_sig));

	sign_tx_input(local_tx, 0, NULL, funding_wscript,
		      &remote.funding_privkey,
		      &funding_remotekey,
		      SIGHASH_ALL,
		      &remote_sig);
	printf("remotesig_on_local: %s\n", sig_as_hex(&remote_sig));

	witness =
		bitcoin_witness_2of2(NULL, &local_sig, &remote_sig,
				     &funding_localkey, &funding_remotekey);
	bitcoin_tx_input_set_witness(local_tx, 0, witness);

	printf("# signed local commitment: %s\n\n",
	       tal_hex(NULL, linearize_tx(NULL, local_tx)));

	/* Create the remote commitment tx */
	if (!per_commit_point(&remoteseed, &remote_per_commit_point, commitnum))
		errx(1, "Bad deriving remote per-commitment-point");
	if (!derive_keyset(&remote_per_commit_point, &remotebase, &localbase,
			   &remotekeys))
		errx(1, "Bad deriving remote keyset");

	remote_tx = initial_commit_tx(NULL, &funding_txid, funding_outnum,
				      funding_amount,
				      fee_payer,
				      remotesettings.to_self_delay,
				      &remotekeys,
				      feerate_per_kw,
				      remotesettings.dustlimit,
				      remote_msat,
				      local_msat,
				      remotesettings.reserve,
				      commitnum
				      ^ commit_number_obscurer(&localbase.payment,
							       &remotebase.payment),
				      REMOTE, &err);
	if (!remote_tx)
		errx(1, "Can't make remote commit tx: %s", err);
	remote_tx->input_amounts[0]
		= tal_dup(remote_tx, struct amount_sat, &funding_amount);

	printf("## remote_commitment\n"
	       "# input amount %s, funding_wscript %s, key %s\n",
	       type_to_string(NULL, struct amount_sat, &funding_amount),
	       tal_hex(NULL, funding_wscript),
	       type_to_string(NULL, struct pubkey, &funding_remotekey));
	printf("# unsigned remote commitment tx: %s\n",
	       tal_hex(NULL, linearize_tx(NULL, remote_tx)));

	sign_tx_input(remote_tx, 0, NULL, funding_wscript,
		      &local.funding_privkey,
		      &funding_localkey,
		      SIGHASH_ALL,
		      &local_sig);
	printf("localsig_on_remote: %s\n", sig_as_hex(&local_sig));

	sign_tx_input(remote_tx, 0, NULL, funding_wscript,
		      &remote.funding_privkey,
		      &funding_remotekey,
		      SIGHASH_ALL,
		      &remote_sig);
	printf("remotesig_on_remote: %s\n", sig_as_hex(&remote_sig));

	witness =
		bitcoin_witness_2of2(NULL, &local_sig, &remote_sig,
				     &funding_localkey, &funding_remotekey);
	bitcoin_tx_input_set_witness(remote_tx, 0, witness);

	printf("# signed remote commitment: %s\n",
	       tal_hex(NULL, linearize_tx(NULL, remote_tx)));

	return 0;
}
