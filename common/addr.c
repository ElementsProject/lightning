#include "config.h"
#include <bitcoin/address.h>
#include <bitcoin/base58.h>
#include <bitcoin/script.h>
#include <common/addr.h>
#include <common/bech32.h>

char *encode_scriptpubkey_to_addr(const tal_t *ctx,
				  const struct chainparams *chainparams,
				  const u8 *scriptpubkey)
{
	char *out;
	const size_t script_len = tal_bytelen(scriptpubkey);
	struct bitcoin_address pkh;
	struct ripemd160 sh;
	int witver;

	if (is_p2pkh(scriptpubkey, script_len, &pkh))
		return bitcoin_to_base58(ctx, chainparams, &pkh);

	if (is_p2sh(scriptpubkey, script_len, &sh))
		return p2sh_to_base58(ctx, chainparams, &sh);

	if (is_p2tr(scriptpubkey, script_len, NULL))
		witver = 1;
	else if (is_p2wpkh(scriptpubkey, script_len, NULL)
		 || is_p2wsh(scriptpubkey, script_len, NULL))
		witver = 0;
	else {
		return NULL;
	}
	out = tal_arr(ctx, char, 73 + strlen(chainparams->onchain_hrp));
	if (!segwit_addr_encode(out, chainparams->onchain_hrp, witver,
				scriptpubkey + 2, script_len - 2))
		return tal_free(out);

	return out;
}
