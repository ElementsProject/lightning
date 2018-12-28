#include <common/crypto_state.h>
#include <wire/wire.h>

void towire_crypto_state(u8 **ptr, const struct crypto_state *cs)
{
	towire_u64(ptr, cs->rn);
	towire_u64(ptr, cs->sn);
	towire_secret(ptr, &cs->sk);
	towire_secret(ptr, &cs->rk);
	towire_secret(ptr, &cs->s_ck);
	towire_secret(ptr, &cs->r_ck);
}

void fromwire_crypto_state(const u8 **ptr, size_t *max, struct crypto_state *cs)
{
	cs->rn = fromwire_u64(ptr, max);
	cs->sn = fromwire_u64(ptr, max);
	fromwire_secret(ptr, max, &cs->sk);
	fromwire_secret(ptr, max, &cs->rk);
	fromwire_secret(ptr, max, &cs->s_ck);
	fromwire_secret(ptr, max, &cs->r_ck);
}
