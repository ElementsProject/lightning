#include "config.h"
#include <tests/fuzz/libfuzz.h>

#include <common/bip32.h>
#include <wally_bip32.h>

void init(int *argc, char ***argv)
{
}

void run(const uint8_t *data, size_t size)
{
	struct ext_key xkey;
	struct bip32_key_version version;
	u8 *wire_buff;
	const uint8_t **xkey_chunks, **ver_chunks, *wire_ptr;
	size_t wire_max;

	if (size < BIP32_SERIALIZED_LEN)
		return;

	xkey_chunks = get_chunks(NULL, data, size, BIP32_SERIALIZED_LEN);
	for (size_t i = 0; i < tal_count(xkey_chunks); i++) {
		wire_max = tal_bytelen(xkey_chunks[i]);
		wire_ptr = xkey_chunks[i];

		fromwire_ext_key(&wire_ptr, &wire_max, &xkey);
		if (wire_ptr) {
			wire_buff = tal_arr(NULL, uint8_t, BIP32_SERIALIZED_LEN);
			towire_ext_key(&wire_buff, &xkey);
			tal_free(wire_buff);
		}
	}
	tal_free(xkey_chunks);

	ver_chunks = get_chunks(NULL, data, size, 4);
	for (size_t i = 0; i < tal_count(ver_chunks); i++) {
		wire_max = tal_bytelen(ver_chunks[i]);
		wire_ptr = ver_chunks[i];

		fromwire_bip32_key_version(&wire_ptr, &wire_max, &version);
		if (wire_ptr) {
			wire_buff = tal_arr(NULL, uint8_t, 4);
			towire_bip32_key_version(&wire_buff, &version);
			tal_free(wire_buff);
		}
	}
	tal_free(ver_chunks);
}
