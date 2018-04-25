#define SUPERVERBOSE

#include <assert.h>
#include <ccan/str/hex/hex.h>
#include <common/type_to_string.h>
#include <common/utils.h>
#include <stdio.h>
#include "../../common/key_derive.c"

static struct secret secret_from_hex(const char *hex)
{
	struct secret s;
	hex += 2;
	if (!hex_decode(hex, strlen(hex), &s, sizeof(s)))
		abort();
	return s;
}

int main(void)
{
	setup_locale();

	struct privkey privkey;
	struct secret base_secret, per_commitment_secret;
	struct pubkey base_point, per_commitment_point, pubkey, pubkey2;

	setup_tmpctx();
	secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY
						 | SECP256K1_CONTEXT_SIGN);

	base_secret = secret_from_hex("0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
	per_commitment_secret = secret_from_hex("0x1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100");

	printf("base_secret: 0x%s\n",
	       tal_hexstr(tmpctx, &base_secret, sizeof(base_secret)));
	printf("per_commitment_secret: 0x%s\n",
	       tal_hexstr(tmpctx, &per_commitment_secret,
			  sizeof(per_commitment_secret)));
	if (!secp256k1_ec_pubkey_create(secp256k1_ctx,
					&per_commitment_point.pubkey,
					per_commitment_secret.data))
		abort();
	if (!secp256k1_ec_pubkey_create(secp256k1_ctx,
					&base_point.pubkey,
					base_secret.data))
		abort();
	printf("base_point: 0x%s\n",
	       type_to_string(tmpctx, struct pubkey, &base_point));
	printf("per_commitment_point: 0x%s\n",
	       type_to_string(tmpctx, struct pubkey, &per_commitment_point));

	/* FIXME: Annotate internal steps. */
	if (!derive_simple_key(&base_point, &per_commitment_point, &pubkey))
		abort();
	printf("localkey: 0x%s\n",
	       type_to_string(tmpctx, struct pubkey, &pubkey));
	if (!derive_simple_privkey(&base_secret, &base_point,
				   &per_commitment_point, &privkey))
		abort();
	printf("localprivkey: 0x%s\n",
	       tal_hexstr(tmpctx, &privkey, sizeof(privkey)));
	pubkey_from_privkey(&privkey, &pubkey2);
	assert(pubkey_eq(&pubkey, &pubkey2));

	/* FIXME: Annotate internal steps. */
	if (!derive_revocation_key(&base_point, &per_commitment_point, &pubkey))
		abort();
	printf("revocationkey: 0x%s\n",
	       type_to_string(tmpctx, struct pubkey, &pubkey));
	if (!derive_revocation_privkey(&base_secret, &per_commitment_secret,
				       &base_point, &per_commitment_point,
				       &privkey))
		abort();
	printf("revocationprivkey: 0x%s\n",
	       tal_hexstr(tmpctx, &privkey, sizeof(privkey)));
	pubkey_from_privkey(&privkey, &pubkey2);
	assert(pubkey_eq(&pubkey, &pubkey2));

	/* No memory leaks please */
	secp256k1_context_destroy(secp256k1_ctx);
	tal_free(tmpctx);
	return 0;
}
