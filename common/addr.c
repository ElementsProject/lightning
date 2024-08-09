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

static const char *segwit_addr_net_decode(int *witness_version,
					  uint8_t *witness_program,
					  size_t *witness_program_len,
					  const char *addrz,
					  const struct chainparams *chainparams)
{
	if (segwit_addr_decode(witness_version, witness_program,
			       witness_program_len, chainparams->onchain_hrp,
			       addrz))
		return chainparams->onchain_hrp;
	else
		return NULL;
}

bool decode_scriptpubkey_from_addr(const tal_t *ctx,
				   const struct chainparams *chainparams,
				   const char *address,
				   u8 **scriptpubkey)
{
	struct bitcoin_address destination;
	int witness_version;
	/* segwit_addr_net_decode requires a buffer of size 40, and will
	 * not write to the buffer if the address is too long, so a buffer
	 * of fixed size 40 will not overflow. */
	uint8_t witness_program[40];
	size_t witness_program_len;
	const char *bech32;
	u8 addr_version;

	if (ripemd160_from_base58(&addr_version, &destination.addr,
				  address, strlen(address))) {
		if (addr_version == chainparams->p2pkh_version) {
			*scriptpubkey = scriptpubkey_p2pkh(ctx, &destination);
			return true;
		} else if (addr_version == chainparams->p2sh_version) {
			*scriptpubkey =
			    scriptpubkey_p2sh_hash(ctx, &destination.addr);
			return true;
		} else {
			return false;
		}
		/* Insert other parsers that accept pointer+len here. */
		return false;
	}

	bech32 = segwit_addr_net_decode(&witness_version, witness_program,
					&witness_program_len, address,
					chainparams);
	if (bech32) {
		bool witness_ok;

		if (witness_version == 0) {
			witness_ok = (witness_program_len == 20 ||
				       witness_program_len == 32);
		} else if (witness_version == 1) {
			witness_ok = (witness_program_len == 32);
		} else {
			witness_ok = true;
		}

		if (!witness_ok)
			return false;

		if (!streq(bech32, chainparams->onchain_hrp))
			return false;

		*scriptpubkey = scriptpubkey_witness_raw(ctx, witness_version,
							 witness_program,
							 witness_program_len);
		return true;
	}

	/* Insert other parsers that accept null-terminated string here. */
	return false;
}
