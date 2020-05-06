/* Generate various query messages. */
#include "config.h"
#include <assert.h>
#include <bitcoin/address.h>
#include <bitcoin/script.h>
#include <bitcoin/short_channel_id.h>
#include <bitcoin/tx.h>
#include <ccan/crc32c/crc32c.h>
#include <ccan/err/err.h>
#include <ccan/str/hex/hex.h>
#include <common/gossip_constants.h>
#include <common/utils.h>
#include <inttypes.h>
#include <wire/gen_peer_wire.h>
#include <stdio.h>

static void usage(void)
{
	errx(1, "Usage: mkquery gossip_timestamp_filter <chain_hash> <first_timestamp> <timestamp_range> OR\n"
	     " mkquery query_channel_range <chain_hash> <first_blocknum> <number_of_blocks> [<query_option_flags>] OR\n"
	     " mkquery query_short_channel_ids <chain_hash> <encoded-scids> [query-flags-encoding query-flags]");
}

int main(int argc, char *argv[])
{
	struct bitcoin_blkid chainhash;
	const tal_t *ctx = tal(NULL, char);
	const u8 *msg;

	setup_locale();
	secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY |
						 SECP256K1_CONTEXT_SIGN);

	if (argc < 3)
		usage();

	if (!hex_decode(argv[2], strlen(argv[2]), &chainhash, sizeof(chainhash)))
		errx(1, "Parsing chainhash");

	if (streq(argv[1], "gossip_timestamp_filter")) {
		if (argc != 5)
			usage();
		msg = towire_gossip_timestamp_filter(ctx, &chainhash,
						     strtol(argv[3], NULL, 0),
						     strtol(argv[4], NULL, 0));
	} else if (streq(argv[1], "query_channel_range")) {
		struct tlv_query_channel_range_tlvs *tlvs;
		if (argc == 5)
			tlvs = NULL;
		else if (argc == 6) {
			tlvs = tlv_query_channel_range_tlvs_new(ctx);
			tlvs->query_option = tal(tlvs, varint);
			*tlvs->query_option = strtol(argv[5], NULL, 0);
		} else
			usage();
		msg = towire_query_channel_range(ctx, &chainhash,
						 strtol(argv[3], NULL, 0),
						 strtol(argv[4], NULL, 0),
						 tlvs);
	} else if (streq(argv[1], "query_short_channel_ids")) {
		struct tlv_query_short_channel_ids_tlvs *tlvs;
		u8 *encoded;

		if (argc == 4)
			tlvs = NULL;
		else if (argc == 6) {
			tlvs = tlv_query_short_channel_ids_tlvs_new(ctx);
			tlvs->query_flags = tal(tlvs, struct tlv_query_short_channel_ids_tlvs_query_flags);
			tlvs->query_flags->encoding_type = strtol(argv[4], NULL, 0);
			tlvs->query_flags->encoded_query_flags = tal_hexdata(tlvs->query_flags,
									     argv[5], strlen(argv[5]));
			if (!tlvs->query_flags->encoded_query_flags)
				usage();
		} else
			usage();

		encoded = tal_hexdata(ctx, argv[3], strlen(argv[3]));
		if (!encoded)
			usage();

		msg = towire_query_short_channel_ids(ctx, &chainhash, encoded, tlvs);
	} else
		usage();

	printf("%s\n", tal_hex(ctx, msg));
	tal_free(msg);
	return 0;
}
