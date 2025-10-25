#include "config.h"
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
#include <common/derive_basepoints.h>
#include <common/descriptor_checksum.h>
#include <common/errcode.h>
#include <common/hsm_secret.h>
#include <common/key_derive.h>
#include <common/memleak.h>
#include <common/utils.h>
#include <common/utxo.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <unistd.h>
#include <wally_bip32.h>
#include <wally_bip39.h>

#define ERROR_USAGE 2
#define ERROR_LIBSODIUM 3
#define ERROR_LIBWALLY 4
#define ERROR_KEYDERIV 5
#define ERROR_LANG_NOT_SUPPORTED 6
#define ERROR_TERM 7

/* We don't implement leak detection, since we don't persist. */
void *notleak_(void *ptr, bool plus_children)
{
	return ptr;
}

static void show_usage(const char *progname)
{
	printf("%s <method> [arguments]\n", progname);
	printf("methods:\n");
	printf("	- decrypt <path/to/hsm_secret> [LEGACY - binary format only]\n");
	printf("	- encrypt <path/to/hsm_secret> [LEGACY - binary format only]\n");
	printf("	- dumpcommitments <node id> <channel dbid> <depth> "
		"<path/to/hsm_secret>\n");
	printf("	- guesstoremote <P2WPKH address> <node id> <tries> "
		"<path/to/hsm_secret>\n");
	printf("	- generatehsm <path/to/new/hsm_secret>\n");
	printf("	- derivetoremote <node id> <channel dbid> [<cmt pt>] "
	       "<path/to/hsm_secret>\n");
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
/* Load hsm_secret using the unified interface */
static struct hsm_secret *load_hsm_secret(const tal_t *ctx, const char *hsm_secret_path)
{
	u8 *contents = grab_file_raw(tmpctx, hsm_secret_path);
	const char *passphrase = NULL;
	struct hsm_secret *hsms;
	enum hsm_secret_error error;

	if (!contents)
		err(EXITCODE_ERROR_HSM_FILE, "Reading hsm_secret");

	/* Get passphrase if needed */
	if (hsm_secret_needs_passphrase(contents, tal_bytelen(contents))) {
		printf("Enter hsm_secret password:\n");
		fflush(stdout);
		passphrase = read_stdin_pass(tmpctx, &error);
		if (!passphrase)
			errx(EXITCODE_ERROR_HSM_FILE, "Could not read password: %s", hsm_secret_error_str(error));
	}

	hsms = extract_hsm_secret(ctx, contents, tal_bytelen(contents), passphrase, &error);
	if (!hsms) {
		err(EXITCODE_ERROR_HSM_FILE, "%s", hsm_secret_error_str(error));
	}
	return hsms;
}

/* Legacy function - only works with binary encrypted format */
static void decrypt_hsm(const char *hsm_secret_path)
{
	int fd;
	struct hsm_secret *hsms;
	const char *dir, *backup;

	/* Check if it's a format we can decrypt */
	u8 *contents = grab_file_raw(tmpctx, hsm_secret_path);
	if (!contents)
		err(EXITCODE_ERROR_HSM_FILE, "Reading hsm_secret");

	enum hsm_secret_type type = detect_hsm_secret_type(contents, tal_bytelen(contents));

	if (type != HSM_SECRET_ENCRYPTED) {
		errx(ERROR_USAGE, "decrypt command only works on legacy encrypted binary format (73 bytes).\n"
		                  "Current file is: %s\n"
		                  "For mnemonic formats, use the generatehsm command to create a new hsm_secret instead.",
		                  format_type_name(type));
	}

	/* Load the hsm_secret */
	hsms = load_hsm_secret(tmpctx, hsm_secret_path);

	dir = path_dirname(NULL, hsm_secret_path);
	backup = path_join(dir, dir, "hsm_secret.backup");

	/* Create a backup file, "just in case". */
	rename(hsm_secret_path, backup);
	fd = open(hsm_secret_path, O_CREAT|O_EXCL|O_WRONLY, 0400);
	if (fd < 0)
		err(EXITCODE_ERROR_HSM_FILE, "Could not open new hsm_secret");

	if (!write_all(fd, hsms->secret_data, tal_bytelen(hsms->secret_data))) {
		unlink_noerr(hsm_secret_path);
		close(fd);
		rename("hsm_secret.backup", hsm_secret_path);
		err(EXITCODE_ERROR_HSM_FILE,
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
}

/* Legacy function - only works with binary plain format */
static void encrypt_hsm(const char *hsm_secret_path)
{
	int fd;
	struct hsm_secret *hsms;
	u8 encrypted_hsm_secret[ENCRYPTED_HSM_SECRET_LEN];
	const char *passwd, *passwd_confirmation;
	const char *dir, *backup;
	enum hsm_secret_error pass_err;

	/* Check if it's a format we can encrypt */
	u8 *contents = grab_file_raw(tmpctx, hsm_secret_path);
	if (!contents)
		err(EXITCODE_ERROR_HSM_FILE, "Reading hsm_secret");

	enum hsm_secret_type type = detect_hsm_secret_type(contents, tal_bytelen(contents));

	if (type != HSM_SECRET_PLAIN) {
		errx(ERROR_USAGE, "encrypt command only works on legacy plain binary format (32 bytes).\n"
		                  "Current file is: %s\n"
		                  "For mnemonic formats, the passphrase is already integrated into the format.",
		                  format_type_name(type));
	}

	/* Load the hsm_secret */
	hsms = load_hsm_secret(tmpctx, hsm_secret_path);

	printf("Enter hsm_secret password:\n");
	fflush(stdout);
	passwd = read_stdin_pass(tmpctx, &pass_err);
	if (!passwd)
		errx(EXITCODE_ERROR_HSM_FILE, "Could not read password: %s", hsm_secret_error_str(pass_err));

	printf("Confirm hsm_secret password:\n");
	fflush(stdout);
	passwd_confirmation = read_stdin_pass(tmpctx, &pass_err);
	if (!passwd_confirmation)
		errx(EXITCODE_ERROR_HSM_FILE, "Could not read password: %s", hsm_secret_error_str(pass_err));

	if (!streq(passwd, passwd_confirmation))
		errx(ERROR_USAGE, "Passwords confirmation mismatch.");

	dir = path_dirname(NULL, hsm_secret_path);
	backup = path_join(dir, dir, "hsm_secret.backup");

	/* Create encryption key and encrypt */
	struct secret *encryption_key = get_encryption_key(tmpctx, passwd);
	if (!encryption_key)
		errx(ERROR_LIBSODIUM, "Could not derive encryption key");

	struct secret legacy_secret;
	memcpy(legacy_secret.data, hsms->secret_data, 32);
	if (!encrypt_legacy_hsm_secret(encryption_key, &legacy_secret, encrypted_hsm_secret))
		errx(ERROR_LIBSODIUM, "Could not encrypt the hsm_secret seed.");

	/* Create a backup file, "just in case". */
	rename(hsm_secret_path, backup);
	fd = open(hsm_secret_path, O_CREAT|O_EXCL|O_WRONLY, 0400);
	if (fd < 0)
		err(EXITCODE_ERROR_HSM_FILE, "Could not open new hsm_secret");

	/* Write the encrypted hsm_secret. */
	if (!write_all(fd, encrypted_hsm_secret,
		       ENCRYPTED_HSM_SECRET_LEN)) {
		unlink_noerr(hsm_secret_path);
		close(fd);
		rename(backup, hsm_secret_path);
		err(EXITCODE_ERROR_HSM_FILE, "Failure writing cipher to hsm_secret.");
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
}

/* Taken from hsmd. */
static void get_channel_seed(struct secret *channel_seed, const struct node_id *peer_id,
                             u64 dbid, struct secret *hsm_secret)
{
	struct secret channel_base;
	u8 input[sizeof(peer_id->k) + sizeof(dbid)];
	const char *info = "per-peer seed";

	hkdf_sha256(&channel_base, sizeof(struct secret), NULL, 0,
	            hsm_secret, sizeof(*hsm_secret),
	             "peer seed", strlen("peer seed"));
	memcpy(input, peer_id->k, sizeof(peer_id->k));
	BUILD_ASSERT(sizeof(peer_id->k) == PUBKEY_CMPR_LEN);
	memcpy(input + PUBKEY_CMPR_LEN, &dbid, sizeof(dbid));

	hkdf_sha256(channel_seed, sizeof(*channel_seed),
	            input, sizeof(input),
	            &channel_base, sizeof(channel_base),
	            info, strlen(info));
}

static void print_codexsecret(const char *hsm_secret_path, const char *id)
{
	struct secret hsm_secret;
	char *bip93;
	const char *err;
	struct hsm_secret *hsms = load_hsm_secret(tmpctx, hsm_secret_path);
	/* Extract first 32 bytes for legacy compatibility */
	memcpy(hsm_secret.data, hsms->secret_data, 32);

	err = codex32_secret_encode(tmpctx, "cl", id, 0, hsm_secret.data, 32, &bip93);
	if (err)
		errx(ERROR_USAGE, "%s", err);

	printf("%s\n", bip93);
}

static void print_emergencyrecover(const char *emer_rec_path)
{
	u8 *scb = grab_file_raw(tmpctx, emer_rec_path);
	char *output, *hrp = "clnemerg";
	if (!scb) {
		err(EXITCODE_ERROR_HSM_FILE, "Reading emergency.recover");
	}
	u5 *data = tal_arr(tmpctx, u5, 0);

	bech32_push_bits(&data, scb, tal_bytelen(scb) * 8);
	output = tal_arr(tmpctx, char, strlen(hrp) + tal_count(data) + 8);

	bech32_encode(output, hrp, data, tal_count(data), (size_t)-1,
			   BECH32_ENCODING_BECH32);

	printf("%s\n", output);
}

static void dump_commitments_infos(struct node_id *node_id, u64 channel_id,
                                   u64 depth, char *hsm_secret_path)
{
	struct sha256 shaseed;
	struct secret hsm_secret, channel_seed, per_commitment_secret;
	struct pubkey per_commitment_point;
	struct hsm_secret *hsms = load_hsm_secret(tmpctx, hsm_secret_path);
	/* Extract first 32 bytes for legacy compatibility */
	memcpy(hsm_secret.data, hsms->secret_data, 32);
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
}

static void guess_to_remote(const char *address, struct node_id *node_id,
                            u64 tries, char *hsm_secret_path)
{
	struct secret hsm_secret, channel_seed, basepoint_secret;
	struct pubkey basepoint;
	struct ripemd160 pubkeyhash;
	u8 goal_pubkeyhash[20];
	char hrp[strlen(address) - 6];
	int witver;
	size_t witlen;

	/* Get the hrp to accept addresses from any network. */
	if (bech32_decode(hrp, goal_pubkeyhash, &witlen, address, 90) != BECH32_ENCODING_BECH32)
		errx(ERROR_USAGE, "Could not get address' network");
	if (segwit_addr_decode(&witver, goal_pubkeyhash, &witlen, hrp, address) != 1)
		errx(ERROR_USAGE, "Wrong bech32 address");

	struct hsm_secret *hsms = load_hsm_secret(tmpctx, hsm_secret_path);
	memcpy(hsm_secret.data, hsms->secret_data, 32);

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
		return;
		}
	}

	errx(ERROR_USAGE, "Could not find any basepoint matching the provided witness programm.\n"
	                  "Are you sure that the channel used `option_static_remotekey` ?");
}

static void generate_hsm(const char *hsm_secret_path)
{
	const char *mnemonic, *passphrase;
	enum hsm_secret_error error;

	/* Get mnemonic from user using consistent interface */
	mnemonic = read_stdin_mnemonic(tmpctx, &error);
	if (!mnemonic)
		errx(EXITCODE_ERROR_HSM_FILE, "Could not read mnemonic: %s", hsm_secret_error_str(error));

	/* Get optional passphrase */
	printf("Warning: remember that different passphrases yield different "
	       "bitcoin wallets.\n");
	printf("If left empty, no password is used (echo is disabled).\n");
	printf("Enter your passphrase: \n");
	fflush(stdout);
	passphrase = read_stdin_pass(tmpctx, &error);
	if (!passphrase)
		errx(EXITCODE_ERROR_HSM_FILE, "Could not read passphrase: %s", hsm_secret_error_str(error));
	if (streq(passphrase, "")) {
		passphrase = NULL;
	}

	/* Write to file using your new mnemonic format */
	int fd = open(hsm_secret_path, O_CREAT|O_EXCL|O_WRONLY, 0400);
	if (fd < 0) {
		err(ERROR_USAGE, "Unable to create hsm_secret file");
	}

	/* Hash the derived seed for validation */
	struct sha256 seed_hash;
	if (!derive_seed_hash(mnemonic, passphrase, &seed_hash))
		errx(ERROR_USAGE, "Error deriving seed from mnemonic");

	/* Write seed hash (32 bytes) + mnemonic */
	if (!write_all(fd, &seed_hash, sizeof(seed_hash)))
		err(ERROR_USAGE, "Error writing seed hash to hsm_secret file");

	/* Write the mnemonic */
	if (!write_all(fd, mnemonic, strlen(mnemonic)))
		err(ERROR_USAGE, "Error writing mnemonic to hsm_secret file");

	if (fsync(fd) != 0)
		err(ERROR_USAGE, "Error fsyncing hsm_secret file");

	if (close(fd) != 0)
		err(ERROR_USAGE, "Error closing hsm_secret file");

	printf("New hsm_secret file created at %s\n", hsm_secret_path);
	printf("Format: %s\n", passphrase ? "mnemonic with passphrase" : "mnemonic without passphrase");
	if (passphrase) {
		printf("Remember your passphrase - it's required to use this hsm_secret!\n");
	}

	/* passphrase and mnemonic will be automatically cleaned up by tmpctx */
}

static void derive_to_remote(const struct unilateral_close_info *info, const char *hsm_secret_path)
{
	struct secret hsm_secret, channel_seed, basepoint_secret;
	struct pubkey basepoint;
	struct privkey privkey;

	secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY
						 | SECP256K1_CONTEXT_SIGN);

	struct hsm_secret *hsms = load_hsm_secret(tmpctx, hsm_secret_path);
	/* Copy first 32 bytes of secret_data to the local secret struct */
	memcpy(hsm_secret.data, hsms->secret_data, sizeof(hsm_secret.data));
	get_channel_seed(&channel_seed, &info->peer_id, info->channel_id, &hsm_secret);
	if (!derive_payment_basepoint(&channel_seed, &basepoint, &basepoint_secret))
		errx(ERROR_KEYDERIV, "Could not derive basepoints for dbid %"PRIu64
				     " and channel seed %s.", info->channel_id,
				     fmt_secret(tmpctx, &channel_seed));
	if (!info->commitment_point)
		privkey.secret = basepoint_secret;
	else if (!derive_simple_privkey(&basepoint_secret, &basepoint, info->commitment_point, &privkey))
		errx(ERROR_KEYDERIV, "Could not derive simple privkey for dbid %"PRIu64
				     ", channel seed %s, and commitment point %s.", info->channel_id,
				     fmt_secret(tmpctx, &channel_seed),
				     fmt_pubkey(tmpctx, info->commitment_point));
	printf("privkey : %s\n", fmt_secret(tmpctx, &privkey.secret));
}
static void dumponchaindescriptors(const char *hsm_secret_path,
				   const u32 version, bool show_secrets)
{
	struct secret hsm_secret;
	u8 bip32_seed[BIP32_ENTROPY_LEN_256];
	u32 salt = 0;
	struct ext_key master_extkey;
	char *enc_xkey, *descriptor;
	struct descriptor_checksum checksum;
	struct hsm_secret *hsms = load_hsm_secret(tmpctx, hsm_secret_path);
	/* Extract first 32 bytes for legacy compatibility */
	memcpy(hsm_secret.data, hsms->secret_data, 32);

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
}

/* Check HSM secret by comparing with backup mnemonic */
static void check_hsm(const char *hsm_secret_path)
{
	struct secret file_secret, derived_secret;
	u8 bip32_seed[BIP39_SEED_LEN_512];
	size_t bip32_seed_len;
	const char *mnemonic_passphrase, *mnemonic;
	enum hsm_secret_error err;

	/* Load the hsm_secret (handles decryption automatically if needed) */
	struct hsm_secret *hsms = load_hsm_secret(tmpctx, hsm_secret_path);
	/* Extract first 32 bytes for legacy compatibility */
	memcpy(file_secret.data, hsms->secret_data, 32);

	/* Ask user for their backup mnemonic passphrase */
	printf("Warning: remember that different passphrases yield different "
	       "bitcoin wallets.\n");
	printf("If left empty, no password is used (echo is disabled).\n");
	printf("Enter your mnemonic passphrase: \n");
	fflush(stdout);
	mnemonic_passphrase = read_stdin_pass(tmpctx, &err);
	if (!mnemonic_passphrase)
		errx(EXITCODE_ERROR_HSM_FILE, "Could not read passphrase: %s", hsm_secret_error_str(err));
	if (streq(mnemonic_passphrase, "")) {
		mnemonic_passphrase = NULL;
	}

	/* Ask user for their backup mnemonic using consistent interface */
	mnemonic = read_stdin_mnemonic(tmpctx, &err);
	if (!mnemonic)
		errx(EXITCODE_ERROR_HSM_FILE, "Could not read mnemonic: %s", hsm_secret_error_str(err));

	/* Derive seed from user's backup mnemonic + passphrase */
	if (bip39_mnemonic_to_seed(mnemonic, mnemonic_passphrase, bip32_seed, sizeof(bip32_seed), &bip32_seed_len) != WALLY_OK)
		errx(ERROR_LIBWALLY, "Unable to derive BIP32 seed from BIP39 mnemonic");

	/* Copy first 32 bytes to our secret for comparison */
	memcpy(derived_secret.data, bip32_seed, sizeof(derived_secret.data));

	/* Compare the seeds */
	if (memcmp(derived_secret.data, file_secret.data, sizeof(file_secret.data)) != 0)
		errx(ERROR_KEYDERIV, "resulting hsm_secret did not match");

	printf("OK\n");
}

static void make_rune(const char *hsm_secret_path)
{
	struct secret hsm_secret, derived_secret, rune_secret;
	struct rune *master_rune, *rune;
	struct hsm_secret *hsms = load_hsm_secret(tmpctx, hsm_secret_path);
	/* Extract first 32 bytes for legacy compatibility */
	memcpy(hsm_secret.data, hsms->secret_data, 32);

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
}

static void print_node_id(const char *hsm_secret_path)
{
	u32 salt = 0;
	struct secret hsm_secret;
	struct privkey node_privkey;
	struct pubkey node_id;
	struct hsm_secret *hsms = load_hsm_secret(tmpctx, hsm_secret_path);
	/* Extract first 32 bytes for legacy compatibility */
	memcpy(hsm_secret.data, hsms->secret_data, 32);

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
		decrypt_hsm(argv[2]);
	} else if (streq(method, "encrypt")) {
		if (argc < 3)
			show_usage(argv[0]);
		encrypt_hsm(argv[2]);

	} else if (streq(method, "dumpcommitments")) {
		/*   node_id    channel_id   depth    hsm_secret  */
		if (argc < 6)
			show_usage(argv[0]);
		struct node_id node_id;
		if (!node_id_from_hexstr(argv[2], strlen(argv[2]), &node_id))
			errx(ERROR_USAGE, "Bad node id");
		dump_commitments_infos(&node_id, atol(argv[3]), atol(argv[4]),
		                       argv[5]);

	} else if (streq(method, "guesstoremote")) {
		/*   address    node_id    depth    hsm_secret */
		if (argc < 6)
			show_usage(argv[0]);
		struct node_id node_id;
		if (!node_id_from_hexstr(argv[3], strlen(argv[3]), &node_id))
			errx(ERROR_USAGE, "Bad node id");
		guess_to_remote(argv[2], &node_id, atol(argv[4]),
		                argv[5]);

	} else if (streq(method, "derivetoremote")) {
		/*  node_id    channel_id    [commitment_point]    hsm_secret  */
		if (argc < 5 || argc > 6)
			show_usage(argv[0]);
		struct unilateral_close_info info = { };
		struct pubkey commitment_point;
		if (!node_id_from_hexstr(argv[2], strlen(argv[2]), &info.peer_id))
			errx(ERROR_USAGE, "Bad node id");
		info.channel_id = atoll(argv[3]);
		if (argc == 6) {
			if (!pubkey_from_hexstr(argv[4], strlen(argv[4]), &commitment_point))
				errx(ERROR_USAGE, "Bad commitment point");
			info.commitment_point = &commitment_point;
		}
		derive_to_remote(&info, argv[argc - 1]);

	} else if (streq(method, "generatehsm")) {
		if (argc != 3)
			show_usage(argv[0]);

		char *hsm_secret_path = argv[2];

		/* if hsm_secret already exists we abort the process
		 * we do not want to lose someone else's funds */
		struct stat st;
		if (stat(hsm_secret_path, &st) == 0)
			errx(ERROR_USAGE, "hsm_secret file at %s already exists", hsm_secret_path);

		generate_hsm(hsm_secret_path);
	} else if (streq(method, "dumponchaindescriptors")) {
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

		if (net && (streq(net, "testnet") || streq(net, "testnet4") || streq(net, "signet")))
			version = BIP32_VER_TEST_PRIVATE;
		else if (net && !streq(net, "bitcoin"))
			errx(ERROR_USAGE, "Network '%s' not supported."
					  " Supported networks: bitcoin (default),"
					  " testnet and signet", net);
		else
			version = BIP32_VER_MAIN_PRIVATE;

		dumponchaindescriptors(fname, version, show_secrets);
	} else if (streq(method, "checkhsm")) {
		if (argc < 3)
			show_usage(argv[0]);
		check_hsm(argv[2]);
	} else if (streq(method, "makerune")) {
		if (argc < 3)
			show_usage(argv[0]);
		make_rune(argv[2]);
	} else if(streq(method, "getcodexsecret")) {
		if (argc < 4)
			show_usage(argv[0]);
		print_codexsecret(argv[2], argv[3]);
	} else if(streq(method, "getemergencyrecover")) {
		if (argc < 3)
			show_usage(argv[0]);
		print_emergencyrecover(argv[2]);
	} else if (streq(method, "getnodeid")) {
		if (argc < 3)
			show_usage(argv[0]);
		print_node_id(argv[2]);
	} else {
		show_usage(argv[0]);
	}

	return 0;
}
