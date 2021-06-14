#include <bitcoin/privkey.h>
#include <ccan/array_size/array_size.h>
#include <ccan/crypto/hkdf_sha256/hkdf_sha256.h>
#include <ccan/err/err.h>
#include <ccan/noerr/noerr.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/str/str.h>
#include <ccan/tal/path/path.h>
#include <ccan/tal/str/str.h>
#include <common/bech32.h>
#include <common/configdir.h>
#include <common/derive_basepoints.h>
#include <common/descriptor_checksum.h>
#include <common/hsm_encryption.h>
#include <common/node_id.h>
#include <common/type_to_string.h>
#include <common/utils.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>
#include <wally_bip39.h>

#define ERROR_HSM_FILE errno
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
	printf("	- generatehsm <path/to/new/hsm_secret>\n");
	printf("	- dumponchaindescriptors <path/to/hsm_secret> [network]\n");
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

static void get_hsm_secret(struct secret *hsm_secret,
                           const char *hsm_secret_path)
{
	int fd;

	fd = open(hsm_secret_path, O_RDONLY);
	if (fd < 0)
		errx(ERROR_HSM_FILE, "Could not open hsm_secret");
	if (!read_all(fd, hsm_secret, sizeof(*hsm_secret)))
		errx(ERROR_HSM_FILE, "Could not read hsm_secret");
	close(fd);
}

/* Derive the encryption key from the password provided, and try to decrypt
 * the cipher. */
static void get_encrypted_hsm_secret(struct secret *hsm_secret,
                                     const char *hsm_secret_path,
                                     const char *passwd)
{
	int fd;
	struct secret key;
	struct encrypted_hsm_secret encrypted_secret;
	char *err;

	fd = open(hsm_secret_path, O_RDONLY);
	if (fd < 0)
		errx(ERROR_HSM_FILE, "Could not open hsm_secret");

	if (!read_all(fd, encrypted_secret.data, ENCRYPTED_HSM_SECRET_LEN))
		errx(ERROR_HSM_FILE, "Could not read encrypted hsm_secret");

	err = hsm_secret_encryption_key(passwd, &key);
	if (err)
		errx(ERROR_LIBSODIUM, "%s", err);
	if (!decrypt_hsm_secret(&key, &encrypted_secret, hsm_secret))
		errx(ERROR_LIBSODIUM, "Could not retrieve the seed. Wrong password ?");

	close(fd);
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
	struct stat st;

	if (stat(hsm_secret_path, &st) != 0)
		errx(ERROR_HSM_FILE, "Could not stat hsm_secret");

	if (st.st_size != 32 && st.st_size != ENCRYPTED_HSM_SECRET_LEN)
		errx(ERROR_HSM_FILE, "Invalid hsm_secret (neither plaintext "
				     "nor encrypted).");

	return st.st_size == ENCRYPTED_HSM_SECRET_LEN;
}

static int decrypt_hsm(const char *hsm_secret_path)
{
	int fd;
	struct secret hsm_secret;
	char *passwd, *err;
	const char *dir, *backup;

	/* This checks the file existence, too. */
	if (!hsm_secret_is_encrypted(hsm_secret_path))
		errx(ERROR_USAGE, "hsm_secret is not encrypted");
	printf("Enter hsm_secret password:\n");
	fflush(stdout);
	passwd = read_stdin_pass(&err);
	if (!passwd)
		errx(ERROR_TERM, "%s", err);

	if (sodium_init() == -1)
		errx(ERROR_LIBSODIUM,
		    "Could not initialize libsodium. Not enough entropy ?");

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
		errx(ERROR_HSM_FILE, "Could not open new hsm_secret");

	if (!write_all(fd, &hsm_secret, sizeof(hsm_secret))) {
		unlink_noerr(hsm_secret_path);
		close(fd);
		rename("hsm_secret.backup", hsm_secret_path);
		errx(ERROR_HSM_FILE,
		    "Failure writing plaintext seed to hsm_secret.");
	}

	/* Be as paranoïd as in hsmd with the file state on disk. */
	if (!ensure_hsm_secret_exists(fd, hsm_secret_path)) {
		unlink_noerr(hsm_secret_path);
		rename(backup, hsm_secret_path);
		errx(ERROR_HSM_FILE,
		    "Could not ensure hsm_secret existence.");
	}
	unlink_noerr(backup);
	tal_free(dir);

	printf("Successfully decrypted hsm_secret, be careful now :-).\n");
	return 0;
}

static int encrypt_hsm(const char *hsm_secret_path)
{
	int fd;
	struct secret key, hsm_secret;
	struct encrypted_hsm_secret encrypted_hsm_secret;
	char *passwd, *passwd_confirmation, *err;
	const char *dir, *backup;

	/* This checks the file existence, too. */
	if (hsm_secret_is_encrypted(hsm_secret_path))
		errx(ERROR_USAGE, "hsm_secret is already encrypted");

	printf("Enter hsm_secret password:\n");
	fflush(stdout);
	passwd = read_stdin_pass(&err);
	if (!passwd)
		errx(ERROR_TERM, "%s", err);
	printf("Confirm hsm_secret password:\n");
	fflush(stdout);
	passwd_confirmation = read_stdin_pass(&err);
	if (!passwd_confirmation)
		errx(ERROR_TERM, "%s", err);
	if (!streq(passwd, passwd_confirmation))
		errx(ERROR_USAGE, "Passwords confirmation mismatch.");
	get_hsm_secret(&hsm_secret, hsm_secret_path);

	dir = path_dirname(NULL, hsm_secret_path);
	backup = path_join(dir, dir, "hsm_secret.backup");

	if (sodium_init() == -1)
		errx(ERROR_LIBSODIUM,
		    "Could not initialize libsodium. Not enough entropy ?");

	/* Derive the encryption key from the password provided, and try to encrypt
	 * the seed. */
	err = hsm_secret_encryption_key(passwd, &key);
	if (err)
		errx(ERROR_LIBSODIUM, "%s", err);
	if (!encrypt_hsm_secret(&key, &hsm_secret, &encrypted_hsm_secret))
		errx(ERROR_LIBSODIUM, "Could not encrypt the hsm_secret seed.");

	/* Once the encryption key derived, we don't need it anymore. */
	free(passwd);
	free(passwd_confirmation);

	/* Create a backup file, "just in case". */
	rename(hsm_secret_path, backup);
	fd = open(hsm_secret_path, O_CREAT|O_EXCL|O_WRONLY, 0400);
	if (fd < 0)
		errx(ERROR_HSM_FILE, "Could not open new hsm_secret");

	/* Write the encrypted hsm_secret. */
	if (!write_all(fd, encrypted_hsm_secret.data,
		       sizeof(encrypted_hsm_secret.data))) {
		unlink_noerr(hsm_secret_path);
		close(fd);
		rename(backup, hsm_secret_path);
		errx(ERROR_HSM_FILE, "Failure writing cipher to hsm_secret.");
	}

	/* Be as paranoïd as in hsmd with the file state on disk. */
	if (!ensure_hsm_secret_exists(fd, hsm_secret_path)) {
		unlink_noerr(hsm_secret_path);
		rename(backup, hsm_secret_path);
		errx(ERROR_HSM_FILE, "Could not ensure hsm_secret existence.");
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
	char *passwd, *err;

	secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY
	                                         | SECP256K1_CONTEXT_SIGN);

	/* This checks the file existence, too. */
	if (hsm_secret_is_encrypted(hsm_secret_path)) {
		printf("Enter hsm_secret password:\n");
		fflush(stdout);
		passwd = read_stdin_pass(&err);
		if (!passwd)
			errx(ERROR_TERM, "%s", err);
		get_encrypted_hsm_secret(&hsm_secret, hsm_secret_path, passwd);
		free(passwd);
	} else
		get_hsm_secret(&hsm_secret, hsm_secret_path);

	get_channel_seed(&channel_seed, node_id, channel_id, &hsm_secret);

	derive_shaseed(&channel_seed, &shaseed);
	printf("shaseed: %s\n", type_to_string(tmpctx, struct sha256, &shaseed));
	for (u64 i = 0; i < depth; i++) {
		if (!per_commit_secret(&shaseed, &per_commitment_secret, i))
			errx(ERROR_KEYDERIV, "Could not derive secret #%"PRIu64, i);
		printf("commit secret #%"PRIu64": %s\n",
		       i, tal_hexstr(tmpctx, per_commitment_secret.data,
		                     sizeof(per_commitment_secret.data)));
		if (!per_commit_point(&shaseed, &per_commitment_point, i))
			errx(ERROR_KEYDERIV, "Could not derive point #%"PRIu64, i);
		printf("commit point #%"PRIu64": %s\n",
		       i, type_to_string(tmpctx, struct pubkey, &per_commitment_point));
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
	char *passwd, *err;
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

	secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY
	                                         | SECP256K1_CONTEXT_SIGN);

	/* This checks the file existence, too. */
	if (hsm_secret_is_encrypted(hsm_secret_path)) {
		printf("Enter hsm_secret password:\n");
		fflush(stdout);
		passwd = read_stdin_pass(&err);
		if (!passwd)
			errx(ERROR_TERM, "%s", err);
		get_encrypted_hsm_secret(&hsm_secret, hsm_secret_path, passwd);
		free(passwd);
	} else
		get_hsm_secret(&hsm_secret, hsm_secret_path);

	for (u64 dbid = 1; dbid < tries ; dbid++) {
		get_channel_seed(&channel_seed, node_id, dbid, &hsm_secret);
		if (!derive_payment_basepoint(&channel_seed,
		                              &basepoint, &basepoint_secret))
			errx(ERROR_KEYDERIV, "Could not derive basepoints for dbid %"PRIu64
			                     " and channel seed %s.", dbid,
			                     type_to_string(tmpctx,
			                                    struct secret, &channel_seed));

		pubkey_to_hash160(&basepoint, &pubkeyhash);
		if (memcmp(pubkeyhash.u.u8, goal_pubkeyhash, 20) == 0) {
			printf("bech32      : %s\n", address);
			printf("pubkey hash : %s\n",
			       tal_hexstr(tmpctx, pubkeyhash.u.u8, 20));
			printf("pubkey      : %s \n",
			       type_to_string(tmpctx, struct pubkey, &basepoint));
			printf("privkey     : %s \n",
			       type_to_string(tmpctx, struct secret, &basepoint_secret));
			return 0;
		}
	}

	printf("Could not find any basepoint matching the provided witness programm.\n"
	       "Are you sure that the channel used `option_static_remotekey` ?\n");
	return 1;
}

static void get_words(struct words **words) {
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

	printf("Select your language:\n");
	for (size_t i = 0; i < ARRAY_SIZE(languages); i++) {
		printf("  %zu) %s (%s)\n", i, languages[i].name, languages[i].abbr);
	}
	printf("Select [0-%zu]: ", ARRAY_SIZE(languages));
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

	bip39_get_wordlist(languages[val].abbr, words);
}

static void get_mnemonic(char *mnemonic) {
	char *line = NULL;
	size_t line_size = 0;

	printf("Introduce your BIP39 word list separated by space:\n");
	fflush(stdout);
	size_t characters = getline(&line, &line_size, stdin);
	if (characters < 0)
		errx(ERROR_USAGE, "Could not read line from stdin.");
	line[characters-1] = '\0';
	strcpy(mnemonic, line);
	free(line);
}

static void read_mnemonic(char *mnemonic) {
	/* Get words for the mnemonic language */
	struct words *words;
	get_words(&words);

	/* Get mnemonic */
	get_mnemonic(mnemonic);

	if (bip39_mnemonic_validate(words, mnemonic) != 0) {
		errx(ERROR_USAGE, "Invalid mnemonic: \"%s\"", mnemonic);
	}
}

static int generate_hsm(const char *hsm_secret_path)
{
	char mnemonic[BIP39_WORDLIST_LEN];
	char *passphrase, *err;

	read_mnemonic(mnemonic);
	printf("Warning: remember that different passphrases yield different "
	       "bitcoin wallets.\n");
	printf("If left empty, no password is used (echo is disabled).\n");
	printf("Enter your passphrase: \n");
	fflush(stdout);
	passphrase = read_stdin_pass(&err);
	if (!passphrase)
		errx(ERROR_TERM, "%s", err);
	if (strlen(passphrase) == 0) {
		free(passphrase);
		passphrase = NULL;
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

	free(passphrase);
	return 0;
}

static int dumponchaindescriptors(const char *hsm_secret_path, const char *old_passwd UNUSED,
				  const bool is_testnet)
{
	struct secret hsm_secret;
	char *passwd, *err;
	u8 bip32_seed[BIP32_ENTROPY_LEN_256];
	u32 salt = 0;
	u32 version = is_testnet ?
		BIP32_VER_TEST_PRIVATE : BIP32_VER_MAIN_PRIVATE;
	struct ext_key master_extkey;
	char *enc_xpub, *descriptor;
	struct descriptor_checksum checksum;

	/* This checks the file existence, too. */
	if (hsm_secret_is_encrypted(hsm_secret_path)) {
		printf("Enter hsm_secret password:\n");
		fflush(stdout);
		passwd = read_stdin_pass(&err);
		if (!passwd)
			errx(ERROR_TERM, "%s", err);
		get_encrypted_hsm_secret(&hsm_secret, hsm_secret_path, passwd);
		free(passwd);
	} else
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

	if (bip32_key_to_base58(&master_extkey, BIP32_FLAG_KEY_PUBLIC, &enc_xpub) != WALLY_OK)
		errx(ERROR_LIBWALLY, "Can't encode xpub");

	/* Now we format the descriptor strings (we only ever create P2WPKH and
	 * P2SH-P2WPKH outputs). */

	descriptor = tal_fmt(NULL, "wpkh(%s/0/0/*)", enc_xpub);
	if (!descriptor_checksum(descriptor, strlen(descriptor), &checksum))
		errx(ERROR_LIBWALLY, "Can't derive descriptor checksum for wpkh");
	printf("%s#%s\n", descriptor, checksum.csum);
	tal_free(descriptor);

	descriptor = tal_fmt(NULL, "sh(wpkh(%s/0/0/*))", enc_xpub);
	if (!descriptor_checksum(descriptor, strlen(descriptor), &checksum))
		errx(ERROR_LIBWALLY, "Can't derive descriptor checksum for sh(wpkh)");
	printf("%s#%s\n", descriptor, checksum.csum);
	tal_free(descriptor);

	wally_free_string(enc_xpub);

	return 0;
}

int main(int argc, char *argv[])
{
	const char *method;

	setup_locale();
	err_set_progname(argv[0]);

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
		if (argc != 3)
			show_usage(argv[0]);

		char *hsm_secret_path = argv[2];

		/* if hsm_secret already exists we abort the process
		 * we do not want to lose someone else's funds */
		struct stat st;
		if (stat(hsm_secret_path, &st) == 0)
			errx(ERROR_USAGE, "hsm_secret file at %s already exists", hsm_secret_path);

		return generate_hsm(hsm_secret_path);
	}

	if (streq(method, "dumponchaindescriptors")) {
		char *net = NULL;
		bool is_testnet;

		if (argc < 3)
			show_usage(argv[0]);

		if (argc > 3)
			net = argv[3];
		/* Previously, we accepted hsm_secret passwords on the command line.
		 * This shifted the location of the network parameter.
		 * TODO: remove this 3 releases after v0.9.3 */
		if (deprecated_apis && argc > 4)
			net = argv[4];

		if (net && streq(net, "testnet"))
			is_testnet = true;
		else if (net && !streq(net, "bitcoin"))
			errx(ERROR_USAGE, "Network '%s' not supported."
					  " Supported networks: bitcoin (default),"
					  " testnet", net);
		else
			is_testnet = false;

		return dumponchaindescriptors(argv[2], NULL, is_testnet);
	}

	show_usage(argv[0]);
}
