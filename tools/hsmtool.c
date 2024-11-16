#include "config.h"
#include <bitcoin/tx.h>
#include <ccan/array_size/array_size.h>
#include <ccan/crypto/hkdf_sha256/hkdf_sha256.h>
#include <ccan/err/err.h>
#include <ccan/noerr/noerr.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/rune/rune.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/tal/path/path.h>
#include <ccan/tal/str/str.h>
#include <common/bech32.h>
#include <common/bech32_util.h>
#include <common/codex32.h>
#include <common/configdir.h>
#include <common/derive_basepoints.h>
#include <common/descriptor_checksum.h>
#include <common/errcode.h>
#include <common/hsm_encryption.h>
#include <common/node_id.h>
#include <common/utils.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <unistd.h>
#include <wally_bip32.h>
#include <wally_bip39.h>

#define ERROR_USAGE 2
#define ERROR_LIBSODIUM 3
#define ERROR_LIBWALLY 4
#define ERROR_KEYDERIV 5
#define ERROR_LANG_NOT_SUPPORTED 6
#define ERROR_TERM 7

static void show_usage(const char *progname)
{
	printf("%s <method> [arguments]\n", progname);
	printf("methods:\n");
	printf("	- decrypt <path/to/hsm_secret>\n");
	printf("	- encrypt <path/to/hsm_secret>\n");
	printf("	- dumpcommitments <node id> <channel dbid> <depth> "
	       "<path/to/hsm_secret>\n");
	printf("	- guesstoremote <P2WPKH address> <node id> <tries> "
	       "<path/to/hsm_secret>\n");
	printf("	- generatehsm <path/to/new/hsm_secret> [<language_id> <word list> [<password>]]\n");
	printf("	- checkhsm <path/to/new/hsm_secret>\n");
	printf("	- dumponchaindescriptors [--show-secrets] <path/to/hsm_secret> [network]\n");
	printf("	- makerune <path/to/hsm_secret>\n");
	printf("	- getcodexsecret <path/to/hsm_secret> <id>\n");
	printf("	- getemergencyrecover <path/to/emergency.recover>\n");
	printf("	- getnodeid <path/to/hsm_secret>\n");
	exit(0);
}

static bool ensure_hsm_secret_exists(int fd, const char *path)
{
	const char *config_dir = path_dirname(NULL, path);
	if (fsync(fd) != 0) {
		close(fd);
		return false;
	}
	if (close(fd) != 0)
		return false;

	fd = open(config_dir, O_RDONLY);
	if (fd < 0)
		return false;
	if (fsync(fd) != 0) {
		close(fd);
		return false;
	}

	close(fd);
	tal_free(config_dir);
	return true;
}

static void grab_hsm_file(const char *hsm_secret_path,
			  void *dst, size_t dstlen)
{
	u8 *contents = grab_file(tmpctx, hsm_secret_path);
	if (!contents)
		errx(EXITCODE_ERROR_HSM_FILE, "Reading hsm_secret");

	/* grab_file always appends a NUL char for convenience */
	if (tal_bytelen(contents) != dstlen + 1)
		errx(EXITCODE_ERROR_HSM_FILE,
		     "hsm_secret invalid length %zu (expected %zu)",
		     tal_bytelen(contents)-1, dstlen);
	memcpy(dst, contents, dstlen);
}

static void get_unencrypted_hsm_secret(struct secret *hsm_secret,
				       const char *hsm_secret_path)
{
	grab_hsm_file(hsm_secret_path, hsm_secret, sizeof(*hsm_secret));
}

/* Derive the encryption key from the password provided, and try to decrypt
 * the cipher. */
static void get_encrypted_hsm_secret(struct secret *hsm_secret,
                                     const char *hsm_secret_path,
                                     const char *passwd)
{
	struct secret key;
	struct encrypted_hsm_secret encrypted_secret;
	const char *err;
	int exit_code;

	grab_hsm_file(hsm_secret_path,
		      &encrypted_secret, sizeof(encrypted_secret));

	exit_code = hsm_secret_encryption_key_with_exitcode(passwd, &key, &err);
	if (exit_code > 0)
		errx(exit_code, "%s", err);
	if (!decrypt_hsm_secret(&key, &encrypted_secret, hsm_secret))
		errx(ERROR_LIBSODIUM, "Could not retrieve the seed. Wrong password ?");
}

/* Taken from hsmd. */
static void get_channel_seed(struct secret *channel_seed, struct node_id *peer_id,
                             u64 dbid, struct secret *hsm_secret)
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
	hkdf_sha256(&channel_base, sizeof(struct secret), NULL, 0,
	            hsm_secret, sizeof(*hsm_secret),
	            /*~ Initially, we didn't support multiple channels per
	             * peer at all: a channel had to be completely forgotten
	             * before another could exist.  That was slightly relaxed,
	             * but the phrase "peer seed" is wired into the seed
	             * generation here, so we need to keep it that way for
	             * existing clients, rather than using "channel seed". */
	             "peer seed", strlen("peer seed"));
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

/* We detect an encrypted hsm_secret as a hsm_secret which is 73-bytes long. */
static bool hsm_secret_is_encrypted(const char *hsm_secret_path)
{
        switch (is_hsm_secret_encrypted(hsm_secret_path)) {
		case -1:
			err(EXITCODE_ERROR_HSM_FILE, "Cannot open '%s'", hsm_secret_path);
		case 1:
			return true;
	        case 0: {
			/* Extra sanity check on HSM file! */
			struct stat st;
			stat(hsm_secret_path, &st);
			if (st.st_size != 32)
				errx(EXITCODE_ERROR_HSM_FILE,
				     "Invalid hsm_secret '%s' (neither plaintext "
				     "nor encrypted).", hsm_secret_path);
			return false;
		}
	}

	abort();
}

/* If encrypted, ask for a passphrase */
static void get_hsm_secret(struct secret *hsm_secret,
			   const char *hsm_secret_path)
{
	/* This checks the file existence, too. */
	if (hsm_secret_is_encrypted(hsm_secret_path)) {
		int exit_code;
		char *passwd;
		const char *err;

		printf("Enter hsm_secret password:\n");
		fflush(stdout);
		passwd = read_stdin_pass_with_exit_code(&err, &exit_code);
		if (!passwd)
			errx(exit_code, "%s", err);
		get_encrypted_hsm_secret(hsm_secret, hsm_secret_path, passwd);
		free(passwd);
	} else {
		get_unencrypted_hsm_secret(hsm_secret, hsm_secret_path);
	}
}

static int decrypt_hsm(const char *hsm_secret_path)
{
	int fd;
	struct secret hsm_secret;
	char *passwd;
	const char *dir, *backup, *err;
	int exit_code = 0;
	/* This checks the file existence, too. */
	if (!hsm_secret_is_encrypted(hsm_secret_path))
		errx(ERROR_USAGE, "hsm_secret is not encrypted");
	printf("Enter hsm_secret password:\n");
	fflush(stdout);
	passwd = read_stdin_pass_with_exit_code(&err, &exit_code);
	if (!passwd)
		errx(exit_code, "%s", err);

	dir = path_dirname(NULL, hsm_secret_path);
	backup = path_join(dir, dir, "hsm_secret.backup");

	get_encrypted_hsm_secret(&hsm_secret, hsm_secret_path, passwd);
	/* Once the encryption key derived, we don't need it anymore. */
	if (passwd)
		free(passwd);

	/* Create a backup file, "just in case". */
	rename(hsm_secret_path, backup);
	fd = open(hsm_secret_path, O_CREAT|O_EXCL|O_WRONLY, 0400);
	if (fd < 0)
		errx(EXITCODE_ERROR_HSM_FILE, "Could not open new hsm_secret");

	if (!write_all(fd, &hsm_secret, sizeof(hsm_secret))) {
		unlink_noerr(hsm_secret_path);
		close(fd);
		rename("hsm_secret.backup", hsm_secret_path);
		errx(EXITCODE_ERROR_HSM_FILE,
		    "Failure writing plaintext seed to hsm_secret.");
	}

	/* Be as paranoïd as in hsmd with the file state on disk. */
	if (!ensure_hsm_secret_exists(fd, hsm_secret_path)) {
		unlink_noerr(hsm_secret_path);
		rename(backup, hsm_secret_path);
		errx(EXITCODE_ERROR_HSM_FILE,
		    "Could not ensure hsm_secret existence.");
	}
	unlink_noerr(backup);
	tal_free(dir);

	printf("Successfully decrypted hsm_secret, be careful now :-).\n");
	return 0;
}

static int make_codexsecret(const char *hsm_secret_path,
			    const char *id)
{
	struct secret hsm_secret;
	char *bip93;
	const char *err;
	get_hsm_secret(&hsm_secret, hsm_secret_path);

	err = codex32_secret_encode(tmpctx, "cl", id, 0, hsm_secret.data, 32, &bip93);
	if (err)
		errx(ERROR_USAGE, "%s", err);

	printf("%s\n", bip93);
	return 0;
}

static int getemergencyrecover(const char *emer_rec_path)
{
	u8 *scb = grab_file(tmpctx, emer_rec_path);
	char *output, *hrp = "clnemerg";
	if (!scb) {
		errx(EXITCODE_ERROR_HSM_FILE, "Reading emergency.recover");
	} else {
		/* grab_file adds nul term */
		tal_resize(&scb, tal_bytelen(scb) - 1);
	}
	u5 *data = tal_arr(tmpctx, u5, 0);

	bech32_push_bits(&data, scb, tal_bytelen(scb) * 8);
	output = tal_arr(tmpctx, char, strlen(hrp) + tal_count(data) + 8);

	bech32_encode(output, hrp, data, tal_count(data), (size_t)-1,
			   BECH32_ENCODING_BECH32);

	printf("%s\n", output);
	return 0;
}

static int encrypt_hsm(const char *hsm_secret_path)
{
	int fd;
	struct secret key, hsm_secret;
	struct encrypted_hsm_secret encrypted_hsm_secret;
	char *passwd, *passwd_confirmation;
	const char *err, *dir, *backup;
	int exit_code = 0;

	/* This checks the file existence, too. */
	if (hsm_secret_is_encrypted(hsm_secret_path))
		errx(ERROR_USAGE, "hsm_secret is already encrypted");

	printf("Enter hsm_secret password:\n");
	fflush(stdout);
	passwd = read_stdin_pass_with_exit_code(&err, &exit_code);
	if (!passwd)
		errx(exit_code, "%s", err);
	printf("Confirm hsm_secret password:\n");
	fflush(stdout);
	passwd_confirmation = read_stdin_pass_with_exit_code(&err, &exit_code);
	if (!passwd_confirmation)
		errx(exit_code, "%s", err);
	if (!streq(passwd, passwd_confirmation))
		errx(ERROR_USAGE, "Passwords confirmation mismatch.");
	get_unencrypted_hsm_secret(&hsm_secret, hsm_secret_path);

	dir = path_dirname(NULL, hsm_secret_path);
	backup = path_join(dir, dir, "hsm_secret.backup");

	/* Derive the encryption key from the password provided, and try to encrypt
	 * the seed. */
        exit_code = hsm_secret_encryption_key_with_exitcode(passwd, &key, &err);
	if (exit_code > 0)
		errx(exit_code, "%s", err);
	if (!encrypt_hsm_secret(&key, &hsm_secret, &encrypted_hsm_secret))
		errx(ERROR_LIBSODIUM, "Could not encrypt the hsm_secret seed.");

	/* Once the encryption key derived, we don't need it anymore. */
	free(passwd);
	free(passwd_confirmation);

	/* Create a backup file, "just in case". */
	rename(hsm_secret_path, backup);
	fd = open(hsm_secret_path, O_CREAT|O_EXCL|O_WRONLY, 0400);
	if (fd < 0)
		errx(EXITCODE_ERROR_HSM_FILE, "Could not open new hsm_secret");

	/* Write the encrypted hsm_secret. */
	if (!write_all(fd, encrypted_hsm_secret.data,
		       sizeof(encrypted_hsm_secret.data))) {
		unlink_noerr(hsm_secret_path);
		close(fd);
		rename(backup, hsm_secret_path);
		errx(EXITCODE_ERROR_HSM_FILE, "Failure writing cipher to hsm_secret.");
	}

	/* Be as paranoïd as in hsmd with the file state on disk. */
	if (!ensure_hsm_secret_exists(fd, hsm_secret_path)) {
		unlink_noerr(hsm_secret_path);
		rename(backup, hsm_secret_path);
		errx(EXITCODE_ERROR_HSM_FILE, "Could not ensure hsm_secret existence.");
	}
	unlink_noerr(backup);
	tal_free(dir);

	printf("Successfully encrypted hsm_secret. You'll now have to pass the "
	       "--encrypted-hsm startup option.\n");
	return 0;
}

static int dump_commitments_infos(struct node_id *node_id, u64 channel_id,
                                  u64 depth, char *hsm_secret_path)
{
	struct sha256 shaseed;
	struct secret hsm_secret, channel_seed, per_commitment_secret;
	struct pubkey per_commitment_point;

	get_hsm_secret(&hsm_secret, hsm_secret_path);
	get_channel_seed(&channel_seed, node_id, channel_id, &hsm_secret);

	derive_shaseed(&channel_seed, &shaseed);
	printf("shaseed: %s\n", fmt_sha256(tmpctx, &shaseed));
	for (u64 i = 0; i < depth; i++) {
		if (!per_commit_secret(&shaseed, &per_commitment_secret, i))
			errx(ERROR_KEYDERIV, "Could not derive secret #%"PRIu64, i);
		printf("commit secret #%"PRIu64": %s\n",
		       i, tal_hexstr(tmpctx, per_commitment_secret.data,
		                     sizeof(per_commitment_secret.data)));
		if (!per_commit_point(&shaseed, &per_commitment_point, i))
			errx(ERROR_KEYDERIV, "Could not derive point #%"PRIu64, i);
		printf("commit point #%"PRIu64": %s\n",
		       i, fmt_pubkey(tmpctx, &per_commitment_point));
	}

	return 0;
}

/* In case of an unilateral close from the remote side while we suffered a
 * loss of data, this tries to recover the private key from the `to_remote`
 * output.
 * This basically iterates over every `dbid` to derive the channel_seed and
 * then derives the payment basepoint to compare to the pubkey hash specified
 * in the witness programm.
 * Note that since a node generates the key for the to_remote output from its
 * *local* per_commitment_point, there is nothing we can do if
 * `option_static_remotekey` was not negotiated.
 *
 * :param address: The bech32 address of the v0 P2WPKH witness programm
 * :param node_id: The id of the node with which the channel was established
 * :param tries: How many dbids to try.
 * :param hsm_secret_path: The path to the hsm_secret
 * :param passwd: The *optional* hsm_secret password
 */
static int guess_to_remote(const char *address, struct node_id *node_id,
                           u64 tries, char *hsm_secret_path)
{
	struct secret hsm_secret, channel_seed, basepoint_secret;
	struct pubkey basepoint;
	struct ripemd160 pubkeyhash;
	/* We only support P2WPKH, hence 20. */
	u8 goal_pubkeyhash[20];
	/* See common/bech32.h for buffer size. */
	char hrp[strlen(address) - 6];
	int witver;
	size_t witlen;

	/* Get the hrp to accept addresses from any network. */
	if (bech32_decode(hrp, goal_pubkeyhash, &witlen, address, 90) != BECH32_ENCODING_BECH32)
		errx(ERROR_USAGE, "Could not get address' network");
	if (segwit_addr_decode(&witver, goal_pubkeyhash, &witlen, hrp, address) != 1)
		errx(ERROR_USAGE, "Wrong bech32 address");

	get_hsm_secret(&hsm_secret, hsm_secret_path);

	for (u64 dbid = 1; dbid < tries ; dbid++) {
		get_channel_seed(&channel_seed, node_id, dbid, &hsm_secret);
		if (!derive_payment_basepoint(&channel_seed,
		                              &basepoint, &basepoint_secret))
			errx(ERROR_KEYDERIV, "Could not derive basepoints for dbid %"PRIu64
			                     " and channel seed %s.", dbid,
			                     fmt_secret(tmpctx, &channel_seed));

		pubkey_to_hash160(&basepoint, &pubkeyhash);
		if (memcmp(pubkeyhash.u.u8, goal_pubkeyhash, 20) == 0) {
			printf("bech32      : %s\n", address);
			printf("pubkey hash : %s\n",
			       tal_hexstr(tmpctx, pubkeyhash.u.u8, 20));
			printf("pubkey      : %s \n",
			       fmt_pubkey(tmpctx, &basepoint));
			printf("privkey     : %s \n",
			       fmt_secret(tmpctx, &basepoint_secret));
			return 0;
		}
	}

	printf("Could not find any basepoint matching the provided witness programm.\n"
	       "Are you sure that the channel used `option_static_remotekey` ?\n");
	return 1;
}

struct wordlist_lang {
	char *abbr;
	char *name;
};

struct wordlist_lang languages[] = {
	{"en", "English"},
	{"es", "Spanish"},
	{"fr", "French"},
	{"it", "Italian"},
	{"jp", "Japanese"},
	{"zhs", "Chinese Simplified"},
	{"zht", "Chinese Traditional"},
};

static bool check_lang(const char *abbr)
{
	for (size_t i = 0; i < ARRAY_SIZE(languages); i++) {
		if (streq(abbr, languages[i].abbr))
			return true;
	}
	return false;
}

static void get_words(struct words **words) {

	printf("Select your language:\n");
	for (size_t i = 0; i < ARRAY_SIZE(languages); i++) {
		printf("  %zu) %s (%s)\n", i, languages[i].name, languages[i].abbr);
	}
	printf("Select [0-%zu]: ", ARRAY_SIZE(languages)-1);
	fflush(stdout);

	char *selected = NULL;
	size_t size = 0;
	size_t characters = getline(&selected, &size, stdin);
	if (characters < 0)
		errx(ERROR_USAGE, "Could not read line from stdin.");

	/* To distinguish success/failure after call */
	errno = 0;
	char *endptr;
	long val = strtol(selected, &endptr, 10);
	if (errno == ERANGE || (errno != 0 && val == 0) || endptr == selected || val < 0 || val >= ARRAY_SIZE(languages))
        errx(ERROR_USAGE, "Invalid language selection, select one from the list [0-6].");

	free(selected);
	bip39_get_wordlist(languages[val].abbr, words);
}

static char *get_mnemonic(void) {
	char *line = NULL;
	size_t line_size = 0;

	printf("Introduce your BIP39 word list separated by space (at least 12 words):\n");
	fflush(stdout);
	size_t characters = getline(&line, &line_size, stdin);
	if (characters < 0)
		errx(ERROR_USAGE, "Could not read line from stdin.");
	line[characters-1] = '\0';
	return line;
}

static char *read_mnemonic(void) {
	/* Get words for the mnemonic language */
	struct words *words;
	get_words(&words);

	/* Get mnemonic */
	char *mnemonic;
	mnemonic = get_mnemonic();

	if (bip39_mnemonic_validate(words, mnemonic) != 0) {
		errx(ERROR_USAGE, "Invalid mnemonic: \"%s\"", mnemonic);
	}
	return mnemonic;
}

static int generate_hsm(const char *hsm_secret_path,
			const char *lang_id,
			char *mnemonic,
			char *passphrase)
{
	const char *err;
	int exit_code = 0;

	if (lang_id == NULL) {
		mnemonic = read_mnemonic();
		printf("Warning: remember that different passphrases yield different "
		       "bitcoin wallets.\n");
		printf("If left empty, no password is used (echo is disabled).\n");
		printf("Enter your passphrase: \n");
		fflush(stdout);
		passphrase = read_stdin_pass_with_exit_code(&err, &exit_code);
		if (!passphrase)
			errx(exit_code, "%s", err);
		if (strlen(passphrase) == 0) {
			free(passphrase);
			passphrase = NULL;
		}
	} else {
		struct words *words;

		bip39_get_wordlist(lang_id, &words);

		if (bip39_mnemonic_validate(words, mnemonic) != 0)
			errx(ERROR_USAGE, "Invalid mnemonic: \"%s\"", mnemonic);
	}

	u8 bip32_seed[BIP39_SEED_LEN_512];
	size_t bip32_seed_len;

	if (bip39_mnemonic_to_seed(mnemonic, passphrase, bip32_seed, sizeof(bip32_seed), &bip32_seed_len) != WALLY_OK)
		errx(ERROR_LIBWALLY, "Unable to derive BIP32 seed from BIP39 mnemonic");

	int fd = open(hsm_secret_path, O_CREAT|O_EXCL|O_WRONLY, 0400);
	if (fd < 0) {
		errx(ERROR_USAGE, "Unable to create hsm_secret file");
	}
	/* Write only the first 32 bytes, length of the (plaintext) seed in the
	 * hsm_secret. */
	if (!write_all(fd, bip32_seed, 32))
		errx(ERROR_USAGE, "Error writing secret to hsm_secret file");

	if (fsync(fd) != 0)
		errx(ERROR_USAGE, "Error fsyncing hsm_secret file");

	/* This should never fail if fsync succeeded. But paranoia is good, and bugs exist */
	if (close(fd) != 0)
		errx(ERROR_USAGE, "Error closing hsm_secret file");

	printf("New hsm_secret file created at %s\n", hsm_secret_path);
	printf("Use the `encrypt` command to encrypt the BIP32 seed if needed\n");

	free(mnemonic);
	free(passphrase);
	return 0;
}

static int dumponchaindescriptors(const char *hsm_secret_path,
				  const char *old_passwd UNUSED,
				  const u32 version, bool show_secrets)
{
	struct secret hsm_secret;
	u8 bip32_seed[BIP32_ENTROPY_LEN_256];
	u32 salt = 0;
	struct ext_key master_extkey;
	char *enc_xkey, *descriptor;
	struct descriptor_checksum checksum;

	get_hsm_secret(&hsm_secret, hsm_secret_path);

	/* We use m/0/0/k as the derivation tree for onchain funds. */

	/* The root seed is derived from hsm_secret using hkdf.. */
	do {
		hkdf_sha256(bip32_seed, sizeof(bip32_seed),
			    &salt, sizeof(salt),
			    &hsm_secret, sizeof(hsm_secret),
			    "bip32 seed", strlen("bip32 seed"));
		salt++;
		/* ..Which is used to derive m/ */
	} while (bip32_key_from_seed(bip32_seed, sizeof(bip32_seed),
				     version, 0, &master_extkey) != WALLY_OK);

	if (show_secrets) {
		if (bip32_key_to_base58(&master_extkey, BIP32_FLAG_KEY_PRIVATE,
					&enc_xkey) != WALLY_OK)
			errx(ERROR_LIBWALLY, "Can't encode xpriv");
	} else {
		if (bip32_key_to_base58(&master_extkey, BIP32_FLAG_KEY_PUBLIC,
					&enc_xkey) != WALLY_OK)
			errx(ERROR_LIBWALLY, "Can't encode xpub");
	}

	/* Now we format the descriptor strings (we only ever create P2TR, P2WPKH, and
	 * P2SH-P2WPKH outputs). */

	descriptor = tal_fmt(NULL, "wpkh(%s/0/0/*)", enc_xkey);
	if (!descriptor_checksum(descriptor, strlen(descriptor), &checksum))
		errx(ERROR_LIBWALLY, "Can't derive descriptor checksum for wpkh");
	printf("%s#%s\n", descriptor, checksum.csum);
	tal_free(descriptor);

	descriptor = tal_fmt(NULL, "sh(wpkh(%s/0/0/*))", enc_xkey);
	if (!descriptor_checksum(descriptor, strlen(descriptor), &checksum))
		errx(ERROR_LIBWALLY, "Can't derive descriptor checksum for sh(wpkh)");
	printf("%s#%s\n", descriptor, checksum.csum);
	tal_free(descriptor);

	descriptor = tal_fmt(NULL, "tr(%s/0/0/*)", enc_xkey);
	if (!descriptor_checksum(descriptor, strlen(descriptor), &checksum))
		errx(ERROR_LIBWALLY, "Can't derive descriptor checksum for tr");
	printf("%s#%s\n", descriptor, checksum.csum);
	tal_free(descriptor);

	wally_free_string(enc_xkey);

	return 0;
}

static int check_hsm(const char *hsm_secret_path)
{
	char *mnemonic;
	struct secret hsm_secret;
	u8 bip32_seed[BIP39_SEED_LEN_512];
	size_t bip32_seed_len;
	int exit_code;
	char *passphrase;
	const char *err;

	get_hsm_secret(&hsm_secret, hsm_secret_path);

	printf("Warning: remember that different passphrases yield different "
	       "bitcoin wallets.\n");
	printf("If left empty, no password is used (echo is disabled).\n");
	printf("Enter your passphrase: \n");
	fflush(stdout);
	passphrase = read_stdin_pass_with_exit_code(&err, &exit_code);
	if (!passphrase)
		errx(exit_code, "%s", err);
	if (strlen(passphrase) == 0) {
		free(passphrase);
		passphrase = NULL;
	}

	mnemonic = read_mnemonic();
	if (bip39_mnemonic_to_seed(mnemonic, passphrase, bip32_seed, sizeof(bip32_seed), &bip32_seed_len) != WALLY_OK)
		errx(ERROR_LIBWALLY, "Unable to derive BIP32 seed from BIP39 mnemonic");

	/* We only use first 32 bytes */
	if (memcmp(bip32_seed, hsm_secret.data, sizeof(hsm_secret.data)) != 0)
		errx(ERROR_KEYDERIV, "resulting hsm_secret did not match");

	printf("OK\n");

	free(mnemonic);
	free(passphrase);
	return 0;
}

static int make_rune(const char *hsm_secret_path)
{
	struct secret hsm_secret, derived_secret, rune_secret;
	struct rune *master_rune, *rune;

	/* Get hsm_secret */
	get_hsm_secret(&hsm_secret, hsm_secret_path);

	/* HSM derives a root secret for `makesecret` */
	hkdf_sha256(&derived_secret, sizeof(struct secret), NULL, 0,
		    &hsm_secret, sizeof(hsm_secret),
		    "derived secrets", strlen("derived secrets"));

	/* Commando derives secret using makesecret "commando" */
	hkdf_sha256(&rune_secret, sizeof(struct secret), NULL, 0,
		    &derived_secret, sizeof(derived_secret),
		    "commando", strlen("commando"));

	master_rune = rune_new(tmpctx,
			       rune_secret.data,
			       ARRAY_SIZE(rune_secret.data),
			       NULL);
	rune = rune_derive_start(tmpctx, master_rune, "0");
	printf("%s\n", rune_to_base64(tmpctx, rune));
	return 0;
}

static int get_node_id(const char *hsm_secret_path)
{
	u32 salt = 0;
	struct secret hsm_secret;
	struct privkey node_privkey;
	struct pubkey node_id;

	/* Get hsm_secret */
	get_hsm_secret(&hsm_secret, hsm_secret_path);

	/*~ So, there is apparently a 1 in 2^127 chance that a random value is
	 * not a valid private key, so this never actually loops. */
	do {
		/*~ ccan/crypto/hkdf_sha256 implements RFC5869 "Hardened Key
		 * Derivation Functions".  That means that if a derived key
		 * leaks somehow, the other keys are not compromised. */
		hkdf_sha256(&node_privkey, sizeof(node_privkey),
			    &salt, sizeof(salt),
			    &hsm_secret,
			    sizeof(hsm_secret),
			    "nodeid", 6);
		salt++;
	} while (!secp256k1_ec_pubkey_create(secp256k1_ctx, &node_id.pubkey,
					     node_privkey.secret.data));

	printf("%s\n", fmt_pubkey(tmpctx, &node_id));
	return 0;
}

int main(int argc, char *argv[])
{
	const char *method;

	setup_locale();
	err_set_progname(argv[0]);
	secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY
	                                         | SECP256K1_CONTEXT_SIGN);

	method = argc > 1 ? argv[1] : NULL;
	if (!method)
		show_usage(argv[0]);

	if (streq(method, "decrypt")) {
		if (argc < 3)
			show_usage(argv[0]);
		return decrypt_hsm(argv[2]);
	}

	if (streq(method, "encrypt")) {
		if (argc < 3)
			show_usage(argv[0]);
		return encrypt_hsm(argv[2]);
	}

	if (streq(method, "dumpcommitments")) {
		/*   node_id    channel_id   depth    hsm_secret  */
		if (argc < 6)
			show_usage(argv[0]);
		struct node_id node_id;
		if (!node_id_from_hexstr(argv[2], strlen(argv[2]), &node_id))
			errx(ERROR_USAGE, "Bad node id");
		return dump_commitments_infos(&node_id, atol(argv[3]), atol(argv[4]),
		                              argv[5]);
	}

	if (streq(method, "guesstoremote")) {
		/*   address    node_id    depth    hsm_secret */
		if (argc < 6)
			show_usage(argv[0]);
		struct node_id node_id;
		if (!node_id_from_hexstr(argv[3], strlen(argv[3]), &node_id))
			errx(ERROR_USAGE, "Bad node id");
		return guess_to_remote(argv[2], &node_id, atol(argv[4]),
		                       argv[5]);
	}

	if (streq(method, "generatehsm")) {
		// argv[2] file, argv[3] lang_id, argv[4] word list, argv[5] passphrase
		if (argc < 3 || argc > 6 || argc == 4)
			show_usage(argv[0]);

		char *hsm_secret_path = argv[2];
		char *lang_id, *word_list, *passphrase;

		/* if hsm_secret already exists we abort the process
		 * we do not want to lose someone else's funds */
		struct stat st;
		if (stat(hsm_secret_path, &st) == 0)
			errx(ERROR_USAGE, "hsm_secret file at %s already exists", hsm_secret_path);

		lang_id = (argc > 3 ? argv[3] : NULL);
		if (lang_id && !check_lang(lang_id))
			show_usage(argv[0]);

		/* generate_hsm expects to free these, so use strdup */
		word_list = (argc > 4 ? strdup(argv[4]) : NULL);
		passphrase = (argc > 5 ? strdup(argv[5]) : NULL);

		return generate_hsm(hsm_secret_path, lang_id, word_list, passphrase);
	}

	if (streq(method, "dumponchaindescriptors")) {
		char *fname = NULL;
		char *net = NULL;
		bool show_secrets = false;
		bool only_arguments = false;
		u32 version;

		if (argc < 3)
			show_usage(argv[0]);

		for (int i = 2; i < argc; ++i) {
			char *next = argv[i];

			if (only_arguments || next[0] != '-') {
				// this is an argument
				if (!fname) {
					fname = next;
					continue;
				}
				if (!net) {
					net = next;
					continue;
				}
				errx(ERROR_USAGE,
				     "Argument '%s' was not expected.", next);
			}

			if (streq(next, "--")) {
				only_arguments = true;
				continue;
			}

			// we are processing an option here
			if (streq(next, "--show-secrets")) {
				show_secrets = true;
				continue;
			}
			errx(ERROR_USAGE, "Option '%s' is not recognized.",
			     next);
		}

		if (net && (streq(net, "testnet") || streq(net, "signet")))
			version = BIP32_VER_TEST_PRIVATE;
		else if (net && !streq(net, "bitcoin"))
			errx(ERROR_USAGE, "Network '%s' not supported."
					  " Supported networks: bitcoin (default),"
					  " testnet and signet", net);
		else
			version = BIP32_VER_MAIN_PRIVATE;

		return dumponchaindescriptors(fname, NULL, version, show_secrets);
	}

	if (streq(method, "checkhsm")) {
		if (argc < 3)
			show_usage(argv[0]);
		return check_hsm(argv[2]);
	}

	if (streq(method, "makerune")) {
		if (argc < 3)
			show_usage(argv[0]);
		return make_rune(argv[2]);
	}

	if(streq(method, "getcodexsecret")) {
		if (argc < 4)
			show_usage(argv[0]);
		return make_codexsecret(argv[2], argv[3]);
	}

	if(streq(method, "getemergencyrecover")) {
		if (argc < 3)
			show_usage(argv[0]);
		return getemergencyrecover(argv[2]);
	}

	if (streq(method, "getnodeid")) {
		if (argc < 3)
			show_usage(argv[0]);
		return get_node_id(argv[2]);
	}

	show_usage(argv[0]);
}
