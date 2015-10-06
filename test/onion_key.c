#define _GNU_SOURCE 1
#include "secp256k1.h"
#include "secp256k1_ecdh.h"
#include "onion_key.h"
#include <time.h>
#include <ccan/str/hex/hex.h>
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

/* Compressed key would start with 0x3?  Subtract from group.  Thanks
 * Greg Maxwell. */
static void flip_key(struct seckey *seckey)
{
	int i;
	bool carry = 0;

	const int64_t group[] = {
		0xFFFFFFFFFFFFFFFFULL,
		0xFFFFFFFFFFFFFFFEULL,
		0xBAAEDCE6AF48A03BULL,
		0xBFD25E8CD0364141ULL
	};

	for (i = 3; i >= 0; i--) {
		uint64_t v = be64_to_cpu(seckey->u.be64[i]);
		if (carry) {
			/* Beware wrap if v == 0xFFFF.... */
			carry = (group[i] <= v);
			v++;
		} else
			carry = (group[i] < v);

		v = group[i] - v;
		seckey->u.be64[i] = cpu_to_be64(v);
	}
}

#if 0
int main(int argc, char *argv[])
{
	struct seckey k;

	k.u.be64[0] = cpu_to_be64(0xFFFFFFFFFFFFFFFFULL);
	k.u.be64[1] = cpu_to_be64(0xFFFFFFFFFFFFFFFEULL);
	k.u.be64[2] = cpu_to_be64(0xBAAEDCE6AF48A03BULL);
	k.u.be64[3] = cpu_to_be64(0xBFD25E8CD0364141ULL);
	flip_key(&k);
	assert(k.u.be64[0] == 0);
	assert(k.u.be64[1] == 0);
	assert(k.u.be64[2] == 0);
	assert(k.u.be64[3] == 0);
	flip_key(&k);
	assert(k.u.be64[0] == cpu_to_be64(0xFFFFFFFFFFFFFFFFULL));
	assert(k.u.be64[1] == cpu_to_be64(0xFFFFFFFFFFFFFFFEULL));
	assert(k.u.be64[2] == cpu_to_be64(0xBAAEDCE6AF48A03BULL));
	assert(k.u.be64[3] == cpu_to_be64(0xBFD25E8CD0364141ULL));

	k.u.be64[0] = cpu_to_be64(0xFFFFFFFFFFFFFFFFULL);
	k.u.be64[1] = cpu_to_be64(0xFFFFFFFFFFFFFFFEULL);
	k.u.be64[2] = cpu_to_be64(0xBAAEDCE6AF48A03BULL);
	k.u.be64[3] = cpu_to_be64(0xBFD25E8CD0364142ULL);
	flip_key(&k);
	assert(k.u.be64[0] == 0xFFFFFFFFFFFFFFFFULL);
	assert(k.u.be64[1] == 0xFFFFFFFFFFFFFFFFULL);
	assert(k.u.be64[2] == 0xFFFFFFFFFFFFFFFFULL);
	assert(k.u.be64[3] == 0xFFFFFFFFFFFFFFFFULL);
	flip_key(&k);
	assert(k.u.be64[0] == cpu_to_be64(0xFFFFFFFFFFFFFFFFULL));
	assert(k.u.be64[1] == cpu_to_be64(0xFFFFFFFFFFFFFFFEULL));
	assert(k.u.be64[2] == cpu_to_be64(0xBAAEDCE6AF48A03BULL));
	assert(k.u.be64[3] == cpu_to_be64(0xBFD25E8CD0364142ULL));

	return 0;
}
#endif

static void random_key(secp256k1_context *ctx,
		       struct seckey *seckey, secp256k1_pubkey *pkey)
{
	do {
		random_bytes(seckey->u.u8, sizeof(seckey->u));
	} while (!secp256k1_ec_pubkey_create(ctx, pkey, seckey->u.u8));
}

/* We don't want to spend a byte encoding sign, so make sure it's 0x2 */
static void gen_keys(secp256k1_context *ctx,
		     struct seckey *seckey, struct onion_pubkey *pubkey)
{
	unsigned char tmp[33];
	secp256k1_pubkey pkey;
	size_t len;

	random_key(ctx, seckey, &pkey);

	secp256k1_ec_pubkey_serialize(ctx, tmp, &len, &pkey,
				      SECP256K1_EC_COMPRESSED);
	assert(len == sizeof(tmp));
	if (tmp[0] == 0x3)
		flip_key(seckey);
	memcpy(pubkey, tmp+1, sizeof(*pubkey));
}

int main(int argc, char *argv[])
{
	secp256k1_context *ctx;
	struct seckey seckey;
	struct onion_pubkey pubkey;
	char sechex[hex_str_size(sizeof(seckey))];
	char pubhex[hex_str_size(sizeof(pubkey))];

	if (argv[1])
		srandom(atoi(argv[1]));
	else
		srandom(time(NULL) + getpid());

	ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
	gen_keys(ctx, &seckey, &pubkey);

	hex_encode(&seckey, sizeof(seckey), sechex, sizeof(sechex));
	hex_encode(&pubkey, sizeof(pubkey), pubhex, sizeof(pubhex));
	printf("%s:%s\n", sechex, pubhex);
	return 0;
}
