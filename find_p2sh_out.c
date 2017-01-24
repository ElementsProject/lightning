#include "bitcoin/script.h"
#include "bitcoin/tx.h"
#include "find_p2sh_out.h"
#include <ccan/err/err.h>
#include <ccan/tal/tal.h>
#include <string.h>

static u32 find_output(const struct bitcoin_tx *tx, const u8 *scriptpubkey)
{
	u32 i;

	for (i = 0; i < tal_count(tx->output); i++) {
		if (scripteq(tx->output[i].script, scriptpubkey))
			break;
	}
	/* FIXME: Return failure! */
	if (i == tal_count(tx->output))
		errx(1, "No matching output in tx");
	return i;
}

u32 find_p2wsh_out(const struct bitcoin_tx *tx, const u8 *witnessscript)
{
	/* This is the scriptPubKey commit tx will have */
	u8 *p2wsh = scriptpubkey_p2wsh(NULL, witnessscript);
	u32 i;

	i = find_output(tx, p2wsh);
	tal_free(p2wsh);
	return i;
}
