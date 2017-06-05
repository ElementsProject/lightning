#include "wallet.h"

#include <ccan/str/hex/hex.h>

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

/**
 * wallet_stmt2output - Extract data from stmt and fill a utxo
 *
 * Returns true on success.
 */
static bool wallet_stmt2output(sqlite3_stmt *stmt, struct utxo *utxo)
{
	const unsigned char *hextxid = sqlite3_column_text(stmt, 0);
	hex_decode((const char*)hextxid, sizeof(utxo->txid) * 2, &utxo->txid, sizeof(utxo->txid));
	utxo->outnum = sqlite3_column_int(stmt, 1);
	utxo->amount = sqlite3_column_int(stmt, 2);
	utxo->is_p2sh = sqlite3_column_int(stmt, 3) == p2sh_wpkh;
	utxo->status = sqlite3_column_int(stmt, 4);
	utxo->keyindex = sqlite3_column_int(stmt, 5);
	return true;
}

bool wallet_update_output_status(struct wallet *w,
				 const struct sha256_double *txid,
				 const u32 outnum, enum output_status oldstatus,
				 enum output_status newstatus)
{
	tal_t *tmpctx = tal_tmpctx(w);
	char *hextxid = tal_hexstr(tmpctx, txid, sizeof(*txid));
	if (oldstatus != output_state_any) {
		db_exec(__func__, w->db,
			"UPDATE outputs SET status=%d WHERE status=%d "
			"AND prev_out_tx = '%s' AND prev_out_index = "
			"%d;",
			newstatus, oldstatus, hextxid, outnum);
	} else {
		db_exec(__func__, w->db,
			"UPDATE outputs SET status=%d WHERE "
			"AND prev_out_tx = '%s' AND prev_out_index = "
			"%d;",
			newstatus, hextxid, outnum);
	}
	tal_free(tmpctx);
	return sqlite3_changes(w->db->sql) > 0;
}

struct utxo **wallet_get_utxos(const tal_t *ctx, struct wallet *w, const enum output_status state)
{
	struct utxo **results;
	int i;
	sqlite3_stmt *stmt =
	    db_query(__func__, w->db, "SELECT prev_out_tx, prev_out_index, "
				      "value, type, status, keyindex FROM "
				      "outputs WHERE status=%d OR %d=255",
		     state, state);

	if (!stmt)
		return NULL;

	results = tal_arr(ctx, struct utxo*, 0);
	for (i=0; sqlite3_step(stmt) == SQLITE_ROW; i++) {
		tal_resize(&results, i+1);
		results[i] = tal(results, struct utxo);
		wallet_stmt2output(stmt, results[i]);
	}
	sqlite3_finalize(stmt);

	return results;
}
