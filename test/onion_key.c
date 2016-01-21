#define _GNU_SOURCE 1
#include "secp256k1.h"
#include "secp256k1_ecdh.h"
#include "onion_key.h"
#include "version.h"
#include <time.h>
#include <ccan/str/hex/hex.h>
#include <ccan/opt/opt.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

/* Not really! */
static void random_bytes(void *dst, size_t n)
{
	size_t i;
	unsigned char *d = dst;

	for (i = 0; i < n; i++)
		d[i] = random() % 256;
}

static void random_key(secp256k1_context *ctx,
		       struct seckey *seckey, secp256k1_pubkey *pkey)
{
	do {
		random_bytes(seckey->u.u8, sizeof(seckey->u));
	} while (!secp256k1_ec_pubkey_create(ctx, pkey, seckey->u.u8));
}

/* We don't want to spend a byte encoding sign, so make sure it's 0x2 */
static void gen_keys(secp256k1_context *ctx,
		     struct seckey *seckey, struct compressed_pubkey *pubkey)
{
	secp256k1_pubkey pkey;
	size_t len;

	random_key(ctx, seckey, &pkey);

	secp256k1_ec_pubkey_serialize(ctx, pubkey->u8, &len, &pkey,
				      SECP256K1_EC_COMPRESSED);
	assert(len == sizeof(pubkey->u8));
}

static void print_keypair(bool pub, bool priv)
{
	secp256k1_context *ctx;
	struct seckey seckey;
	struct compressed_pubkey pubkey;
	char sechex[hex_str_size(sizeof(seckey))];
	char pubhex[hex_str_size(sizeof(pubkey))];

	assert(pub || priv);

	ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
	gen_keys(ctx, &seckey, &pubkey);

	hex_encode(&seckey, sizeof(seckey), sechex, sizeof(sechex));
	hex_encode(&pubkey, sizeof(pubkey), pubhex, sizeof(pubhex));

	if (pub && priv) {
		printf("%s:%s\n", sechex, pubhex);
	} else {
		printf("%s\n", (priv ? sechex : pubhex));
	}
}

int main(int argc, char *argv[])
{
	bool pub = true, priv = true;

	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "[<seeds>...]\n"
			   "Generate (deterministic if seed) secp256k1 keys",
			   "Print this message.");
	opt_register_noarg("--pub",
			   opt_set_invbool, &priv,
			   "Generate only the public key");
	opt_register_noarg("--priv",
			   opt_set_invbool, &pub,
			   "Generate only the private key");
	opt_register_version();

 	opt_parse(&argc, argv, opt_log_stderr_exit);
	if (!priv && !pub)
		opt_usage_exit_fail("Can't use --pub and --priv");
	
	if (argc == 1) {
		srandom(time(NULL) + getpid());
		print_keypair(pub, priv);
	} else {
		int i;
		for (i = 1; i < argc; i++) {
			srandom(atoi(argv[i]));
			print_keypair(pub, priv);
		}
	}

	return 0;
}
