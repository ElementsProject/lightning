#include <common/bip32.h>
#include <wally_bip32.h>
#include <wire/wire.h>

/* We only ever send out the public seed. */
void towire_ext_key(u8 **pptr, const struct ext_key *bip32)
{
	unsigned char out[BIP32_SERIALIZED_LEN];

	if (bip32_key_serialize(bip32, BIP32_FLAG_KEY_PUBLIC, out,
				sizeof(out)))
		abort();

	towire(pptr, out, sizeof(out));
}

void fromwire_ext_key(const u8 **cursor, size_t *max, struct ext_key *bip32)
{
	const u8 *in = fromwire(cursor, max, NULL, BIP32_SERIALIZED_LEN);
	if (!in)
		return;

	if (bip32_key_unserialize(in, BIP32_SERIALIZED_LEN, bip32) != WALLY_OK)
		fromwire_fail(cursor, max);
}
