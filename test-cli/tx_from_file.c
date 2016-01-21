#include "tx_from_file.h"
#include "bitcoin/tx.h"
#include <ccan/err/err.h>
#include <ccan/tal/grab_file/grab_file.h>

struct bitcoin_tx *bitcoin_tx_from_file(const tal_t *ctx, const char *filename)
{
	char *hex;
	struct bitcoin_tx *tx;

	/* Grabs file, add nul at end. */
	hex = grab_file(ctx, filename);
	if (!hex)
		err(1, "Opening %s", filename);

	tx = bitcoin_tx_from_hex(ctx, hex);
	if (!tx)
		err(1, "Failed to decode tx '%s'", hex);
	tal_free(hex);
	return tx;
}
