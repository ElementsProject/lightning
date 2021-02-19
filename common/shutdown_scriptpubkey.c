#include <bitcoin/script.h>
#include <common/shutdown_scriptpubkey.h>

bool valid_shutdown_scriptpubkey(const u8 *scriptpubkey)
{
	return is_p2pkh(scriptpubkey, NULL)
		|| is_p2sh(scriptpubkey, NULL)
		|| is_p2wpkh(scriptpubkey, NULL)
		|| is_p2wsh(scriptpubkey, NULL);
}
