#include "config.h"
#include <bitcoin/privkey.h>
#include <bitcoin/pubkey.h>
#include <common/blinding.h>
#include <common/utils.h>

void blinding_hash_e_and_ss(const struct pubkey *e,
			    const struct secret *ss,
			    struct sha256 *sha)
{
	u8 der[PUBKEY_CMPR_LEN];
	struct sha256_ctx shactx;

	pubkey_to_der(der, e);
	sha256_init(&shactx);
	sha256_update(&shactx, der, sizeof(der));
	sha256_update(&shactx, ss->data, sizeof(ss->data));
	sha256_done(&shactx, sha);
}

/* E(i+1) = H(E(i) || ss(i)) * E(i) */
bool blinding_next_pubkey(const struct pubkey *pk,
			  const struct sha256 *h,
			  struct pubkey *next)
{

	*next = *pk;
	return secp256k1_ec_pubkey_tweak_mul(secp256k1_ctx, &next->pubkey,
					     h->u.u8) == 1;
}

/* e(i+1) = H(E(i) || ss(i)) * e(i) */
bool blinding_next_privkey(const struct privkey *e,
			   const struct sha256 *h,
			   struct privkey *next)
{
	*next = *e;
	return secp256k1_ec_privkey_tweak_mul(secp256k1_ctx, next->secret.data,
					      h->u.u8) == 1;
}
