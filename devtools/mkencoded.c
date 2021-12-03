/* Simple wrapper to create zlib or raw encodings of hex. */
#include "config.h"
#include <bitcoin/short_channel_id.h>
#include <ccan/err/err.h>
#include <ccan/str/hex/hex.h>
#include <common/decode_array.h>
#include <stdio.h>
#include <zlib.h>

static NORETURN void usage(void)
{
	errx(1, "Usage: mkencoded <encoding> <hexstr>, OR\n"
	     "mkencoded --scids <encoding> <scid>...");
}

int main(int argc, char *argv[])
{
	u8 encoding, *data;

	setup_locale();

	if (argv[1] && streq(argv[1], "--scids")) {
		argv++;
		argc--;
		if (argc < 2)
			usage();
		data = tal_arr(NULL, u8, 0);
		for (size_t i = 2; i < argc; i++) {
			struct short_channel_id scid;
			if (!short_channel_id_from_str(argv[i], strlen(argv[i]),
						       &scid))
				errx(1, "Invalid short_channel_id %s", argv[i]);
			towire_short_channel_id(&data, &scid);
		}
	} else {
		data = tal_hexdata(NULL, argv[2], strlen(argv[2]));
		if (!data)
			errx(1, "Invalid hex string %s", argv[2]);
	}
	if (!hex_decode(argv[1], strlen(argv[1]), &encoding, sizeof(encoding)))
		errx(1, "Expected single hex byte not %s", argv[1]);

	if (encoding == ARR_UNCOMPRESSED)
		printf("%02x%s\n", encoding, tal_hex(NULL, data));
	else if (encoding == ARR_ZLIB) {
		/* https://www.zlib.net/zlib_tech.html:
		 *   the only expansion is an overhead of five bytes per 16 KB
		 *   block (about 0.03%), plus a one-time overhead of six bytes
		 *   for the entire stream.
		 */
		unsigned long compressed_len = tal_bytelen(data)
			+ 6 + 5*(tal_bytelen(data) + 16384)/16384;
		u8 *z = tal_arr(NULL, u8, compressed_len);
		if (compress2(z, &compressed_len, data, tal_bytelen(data),
			      Z_DEFAULT_COMPRESSION) != Z_OK)
			errx(1, "Error compressing stream?");

		printf("%02x%s\n", encoding,
		       tal_hexstr(NULL, z, compressed_len));
	} else {
		errx(1, "Unknown encoding %u", encoding);
	}

	return 0;
}
