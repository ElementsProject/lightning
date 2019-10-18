/* Code to make a commitment point, useful for recovering funds.
 *
 * For example:
 *
 * lightning/devtools/mkpoint 03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad 10 0
 */
#include <bitcoin/script.h>
#include <bitcoin/tx.h>
#include <ccan/opt/opt.h>
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
#include <common/version.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>

// MINDLESS INCLUDES from hsmd.c
#include <ccan/crypto/hkdf_sha256/hkdf_sha256.h>
#include <ccan/read_write_all/read_write_all.h>
#include <wally_bip32.h>
#include <fcntl.h> // for open
#include <unistd.h> // for close
#include <errno.h>
#include <bitcoin/chainparams.h>
// END MINDLESS INCLUDES

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


// ------------------------------
// MINDLESSLY COPIED FROM hsmd.c
// TODO: use messages to communicate with HSM

/* Version codes for BIP32 extended keys in libwally-core.
 * It's not suitable to add this struct into client struct,
 * so set it static.*/
static struct  bip32_key_version  bip32_key_version;

static struct {
	struct secret hsm_secret;
	struct ext_key bip32;
} secretstuff;

#if DEVELOPER
/* If they specify --dev-force-bip32-seed it ends up in here. */
static struct secret *dev_force_bip32_seed;
#endif

/*~ Called at startup to derive the bip32 field. */
static void populate_secretstuff(void)
{
	u8 bip32_seed[BIP32_ENTROPY_LEN_256];
	u32 salt = 0;
	struct ext_key master_extkey, child_extkey;

	assert(bip32_key_version.bip32_pubkey_version == BIP32_VER_MAIN_PUBLIC
			|| bip32_key_version.bip32_pubkey_version == BIP32_VER_TEST_PUBLIC);

	assert(bip32_key_version.bip32_privkey_version == BIP32_VER_MAIN_PRIVATE
			|| bip32_key_version.bip32_privkey_version == BIP32_VER_TEST_PRIVATE);

	/* Fill in the BIP32 tree for bitcoin addresses. */
	/* In libwally-core, the version BIP32_VER_TEST_PRIVATE is for testnet/regtest,
	 * and BIP32_VER_MAIN_PRIVATE is for mainnet. For litecoin, we also set it like
	 * bitcoin else.*/
	do {
		hkdf_sha256(bip32_seed, sizeof(bip32_seed),
			    &salt, sizeof(salt),
			    &secretstuff.hsm_secret,
			    sizeof(secretstuff.hsm_secret),
			    "bip32 seed", strlen("bip32 seed"));
		salt++;
	} while (bip32_key_from_seed(bip32_seed, sizeof(bip32_seed),
				     bip32_key_version.bip32_privkey_version,
				     0, &master_extkey) != WALLY_OK);

#if DEVELOPER
	/* In DEVELOPER mode, we can override with --dev-force-bip32-seed */
	if (dev_force_bip32_seed) {
		if (bip32_key_from_seed(dev_force_bip32_seed->data,
					sizeof(dev_force_bip32_seed->data),
					bip32_key_version.bip32_privkey_version,
					0, &master_extkey) != WALLY_OK)
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "Can't derive bip32 master key");
	}
#endif /* DEVELOPER */

	/* BIP 32:
	 *
	 * The default wallet layout
	 *
	 * An HDW is organized as several 'accounts'. Accounts are numbered,
	 * the default account ("") being number 0. Clients are not required
	 * to support more than one account - if not, they only use the
	 * default account.
	 *
	 * Each account is composed of two keypair chains: an internal and an
	 * external one. The external keychain is used to generate new public
	 * addresses, while the internal keychain is used for all other
	 * operations (change addresses, generation addresses, ..., anything
	 * that doesn't need to be communicated). Clients that do not support
	 * separate keychains for these should use the external one for
	 * everything.
	 *
	 *  - m/iH/0/k corresponds to the k'th keypair of the external chain of
	 * account number i of the HDW derived from master m.
	 */
	/* Hence child 0, then child 0 again to get extkey to derive from. */
	if (bip32_key_from_parent(&master_extkey, 0, BIP32_FLAG_KEY_PRIVATE,
				  &child_extkey) != WALLY_OK)
		/*~ status_failed() is a helper which exits and sends lightningd
		 * a message about what happened.  For hsmd, that's fatal to
		 * lightningd. */
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Can't derive child bip32 key");

	if (bip32_key_from_parent(&child_extkey, 0, BIP32_FLAG_KEY_PRIVATE,
				  &secretstuff.bip32) != WALLY_OK)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Can't derive private bip32 key");
}


static void load_hsm(void)
{
	int fd = open("hsm_secret", O_RDONLY);
  fprintf(stderr, "%s %d\n", "Open?", fd);
	if (fd < 0)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "opening: %s", strerror(errno));
	if (!read_all(fd, &secretstuff.hsm_secret, sizeof(secretstuff.hsm_secret)))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "reading: %s", strerror(errno));
	close(fd);
  fprintf(stderr, "%s\n", "Read...");

	populate_secretstuff();
}


static void hsm_channel_secret_base(struct secret *channel_seed_base)
{
	hkdf_sha256(channel_seed_base, sizeof(struct secret), NULL, 0,
		    &secretstuff.hsm_secret, sizeof(secretstuff.hsm_secret),
		    /*~ Initially, we didn't support multiple channels per
		     * peer at all: a channel had to be completely forgotten
		     * before another could exist.  That was slightly relaxed,
		     * but the phrase "peer seed" is wired into the seed
		     * generation here, so we need to keep it that way for
		     * existing clients, rather than using "channel seed". */
		    "peer seed", strlen("peer seed"));
}

static void get_channel_seed(const struct node_id *peer_id, u64 dbid,
			     struct secret *channel_seed)
{
	struct secret channel_base;
	u8 input[sizeof(peer_id->k) + sizeof(dbid)];
	/*~ Again, "per-peer" should be "per-channel", but Hysterical Raisins */
	const char *info = "per-peer seed";

	/*~ We use the DER encoding of the pubkey, because it's platform
	 * independent.  Since the dbid is unique, however, it's completely
	 * unnecessary, but again, existing users can't be broken. */
	/* FIXME: lnd has a nicer BIP32 method for deriving secrets which we
	 * should migrate to. */
	hsm_channel_secret_base(&channel_base);
	memcpy(input, peer_id->k, sizeof(peer_id->k));
	BUILD_ASSERT(sizeof(peer_id->k) == PUBKEY_CMPR_LEN);
	/*~ For all that talk about platform-independence, note that this
	 * field is endian-dependent!  But let's face it, little-endian won.
	 * In related news, we don't support EBCDIC or middle-endian. */
	memcpy(input + PUBKEY_CMPR_LEN, &dbid, sizeof(dbid));

	hkdf_sha256(channel_seed, sizeof(*channel_seed),
		    input, sizeof(input),
		    &channel_base, sizeof(channel_base),
		    info, strlen(info));
}
// !END OF MINLESS COPY

int main(int argc, char *argv[])
{
  struct node_id node_id;
	// struct secrets local, remote;
	// struct sha256 localseed, remoteseed;
	// struct basepoints localbase, remotebase;
	// struct pubkey funding_localkey, funding_remotekey;
  u64 channel_db_id;
	u64 commit_num;

  struct sha256 shaseed;
  struct secret channel_seed;
  struct secret per_commitment_secret;
  struct pubkey per_commitment_point;

  bip32_key_version.bip32_pubkey_version = BIP32_VER_MAIN_PUBLIC;
  bip32_key_version.bip32_privkey_version = BIP32_VER_MAIN_PRIVATE;

	setup_locale();

	secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY |
						 SECP256K1_CONTEXT_SIGN);

	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "<node_id> <channel_db_id> <commit_num>\n",
			   "Show this message");
	opt_register_noarg("-v|--verbose", opt_set_bool, &verbose,
			   "Increase verbosity");
	opt_register_version();

	opt_parse(&argc, argv, opt_log_stderr_exit);

	if (argc < 3)
		opt_usage_exit_fail("Too few arguments");

	int argnum = 1;
	if (!node_id_from_hexstr(argv[argnum],
				   strlen(argv[argnum]), &node_id))
		errx(1, "Bad node-id");
	argnum++;

  channel_db_id = atol(argv[argnum++]);

  commit_num = atol(argv[argnum++]);
  fprintf(stderr, "%s\n", "Load HSM...");
  load_hsm();
  fprintf(stderr, "%s\n", "Loaded");
  get_channel_seed(&node_id, channel_db_id, &channel_seed);
  derive_shaseed(&channel_seed, &shaseed);

  if (!per_commit_secret(&shaseed, &per_commitment_secret, commit_num))
		errx(1, "Bad deriving local per_commitment_secret #%"PRIu64, commit_num);
	if (!per_commit_point(&shaseed, &per_commitment_point, commit_num))
		errx(1, "Bad deriving local per_commitment_point #%"PRIu64, commit_num);
	printf("# shachain seed=%s\n",
	       type_to_string(NULL, struct sha256, &shaseed));
	printf("# per_commitment_secret %"PRIu64"=%s\n",
	       commit_num,
	       type_to_string(NULL, struct secret,  &per_commitment_secret));
	printf("per_commitment_point %"PRIu64"=%s\n\n",
	       commit_num,
	       type_to_string(NULL, struct pubkey, &per_commitment_point));

	printf("\n");

	return 0;
}
