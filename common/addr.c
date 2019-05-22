#include "addr.h"
#include <bitcoin/script.h>
#include <common/bech32.h>

/* Returns NULL if the script is not a P2WPKH or P2WSH */
char *encode_scriptpubkey_to_addr(const tal_t *ctx,
				   const char *hrp,
				   const u8 *scriptPubkey)
{
	char *out;
	size_t scriptLen = tal_bytelen(scriptPubkey);

        /* Check that scriptPubkey is P2WSH or P2WPKH */
	if (!is_p2wsh(scriptPubkey, NULL) && !is_p2wpkh(scriptPubkey, NULL))
                return NULL;

	out = tal_arr(ctx, char, 73 + strlen(hrp));
	if (!segwit_addr_encode(out, hrp, 0, scriptPubkey + 2, scriptLen - 2))
		return tal_free(out);

	return out;
}
