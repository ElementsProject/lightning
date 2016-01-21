#include "bitcoin/script.h"
#include "bitcoin/tx.h"
#include "find_p2sh_out.h"
#include <ccan/err/err.h>
#include <ccan/tal/tal.h>
#include <string.h>

u32 find_p2sh_out(const struct bitcoin_tx *tx, u8 *redeemscript)
{
	/* This is the scriptPubKey commit tx will have */
	u8 *p2sh = scriptpubkey_p2sh(NULL, redeemscript);
	u32 i;

	for (i = 0; i < tx->output_count; i++) {
		if (tx->output[i].script_length != tal_count(p2sh))
			continue;
		if (memcmp(tx->output[i].script, p2sh, tal_count(p2sh)) == 0)
			break;
	}
	if (i == tx->output_count)
		errx(1, "No matching output in tx");
	tal_free(p2sh);
	return i;
}
