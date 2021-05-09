#include "config.h"
#include <assert.h>
#include <stdint.h>
#include <tests/fuzz/libfuzz.h>

#include <ccan/ccan/str/hex/hex.h>
#include <ccan/ccan/tal/tal.h>
#include <common/setup.h>
#include <common/utils.h>
#include <hsmd/libhsmd.h>
#include <wire/wire.h>

/* These are mocks of the functions libhsmd instructs the user to implement.
 * Obviously we are feeding garbage so we don't want to fail here, neither do
 * we want to take time to spam so just do nothing. */
u8 *hsmd_status_bad_request(struct hsmd_client *client, const u8 *msg,
			    const char *error)
{
	return NULL;
}

void hsmd_status_fmt(enum log_level level,
		const struct node_id *peer,
		const char *fmt, ...)
{
}

void hsmd_status_failed(enum status_failreason code,
			const char *fmt, ...)
{
}

void init(int *argc, char ***argv)
{
	struct secret hsm_secret;
	struct bip32_key_version key_version;

	common_setup("fuzzer");
	chainparams = chainparams_for_network("bitcoin");

	/* We use a static hsm secret (block 682824 coinbase txid) as the goal
	 * isn't to fuzz the `hsmd_init` and taking the 32 bytes from the stream
	 * could just confuse the fuzzer. */
	hex_decode("c5426839b8b2410ad417b9ec3288f69d40ca11d806cd93dd9191a023578bb174",
		   64, &hsm_secret.data, 32);
	key_version.bip32_pubkey_version = BIP32_VER_MAIN_PUBLIC;
	key_version.bip32_privkey_version = BIP32_VER_MAIN_PRIVATE;
	hsmd_init(hsm_secret, key_version);
}

void run(const uint8_t *data, size_t size)
{
	struct hsmd_client *client;
	size_t max;
	u64 capabilities;
	const u8 *msg;

	/* We take the capabilities from the stream, which is a u64 */
	if (size < 8)
		return;

	max = size;
	capabilities = fromwire_u64(&data, &max);
	client = hsmd_client_new_main(tmpctx, capabilities, NULL);

	/* We should never crash when handling a message */
	msg = tal_dup_arr(client, const u8, data, max, 0);
	hsmd_handle_client_message(client, client, msg);

	clean_tmpctx();
}
