#include "wallet.h"

struct wallet *wallet_new(const tal_t *ctx, struct log *log)
{
	struct wallet *wallet = tal(ctx, struct wallet);
	wallet->db = db_setup(wallet);
	wallet->log = log;
	if (!wallet->db) {
		fatal("Unable to setup the wallet database");
	}
	return wallet;
}

bool wallet_add_utxo(struct wallet *w, struct utxo *utxo,
		     enum wallet_output_type type)
{
	tal_t *tmpctx = tal_tmpctx(w);
	char *hextxid = tal_hexstr(tmpctx, &utxo->txid, 32);
	bool result = db_exec(
	    __func__, w->db,
	    "INSERT INTO outputs (prev_out_tx, prev_out_index, value, type, "
	    "status, keyindex) VALUES ('%s', %d, %zu, %d, %d, %d);",
	    hextxid, utxo->outnum, utxo->amount, type, output_state_available,
	    utxo->keyindex);
	tal_free(tmpctx);
	return result;
}
