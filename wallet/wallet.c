#include "wallet.h"

#include <bitcoin/script.h>
#include <ccan/str/hex/hex.h>
#include <inttypes.h>
#include <lightningd/lightningd.h>
#include <lightningd/peer_control.h>
#include <lightningd/peer_htlcs.h>

#define SQLITE_MAX_UINT 0x7FFFFFFFFFFFFFFF

struct wallet *wallet_new(const tal_t *ctx, struct log *log)
{
	struct wallet *wallet = tal(ctx, struct wallet);
	wallet->db = db_setup(wallet);
	wallet->log = log;
	wallet->bip32_base = NULL;
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

/**
 * unreserve_utxo - Mark a reserved UTXO as available again
 */
static void unreserve_utxo(struct wallet *w, const struct utxo *unres)
{
	if (!wallet_update_output_status(w, &unres->txid, unres->outnum,
					 output_state_reserved,
					 output_state_available)) {
		fatal("Unable to unreserve output: %s", w->db->err);
	}
}

/**
 * destroy_utxos - Destructor for an array of pointers to utxo
 */
static void destroy_utxos(const struct utxo **utxos, struct wallet *w)
{
	for (size_t i = 0; i < tal_count(utxos); i++)
		unreserve_utxo(w, utxos[i]);
}

void wallet_confirm_utxos(struct wallet *w, const struct utxo **utxos)
{
	tal_del_destructor2(utxos, destroy_utxos, w);
	for (size_t i = 0; i < tal_count(utxos); i++) {
		if (!wallet_update_output_status(
			w, &utxos[i]->txid, utxos[i]->outnum,
			output_state_reserved, output_state_spent)) {
			fatal("Unable to mark output as spent: %s", w->db->err);
		}
	}
}

const struct utxo **wallet_select_coins(const tal_t *ctx, struct wallet *w,
					const u64 value,
					const u32 feerate_per_kw,
					u64 *fee_estimate, u64 *changesatoshi)
{
	size_t i = 0;
	struct utxo **available;
	const struct utxo **utxos = tal_arr(ctx, const struct utxo *, 0);
	*fee_estimate = 0;

	/* We assume two outputs for the weight. */
	u64 satoshi_in = 0, weight = (4 + (8 + 22) * 2 + 4) * 4;
	tal_add_destructor2(utxos, destroy_utxos, w);

	if (!db_begin_transaction(w->db)) {
		fatal("Unable to begin transaction: %s", w->db->err);
	}
	available = wallet_get_utxos(ctx, w, output_state_available);

	for (i = 0; i < tal_count(available); i++) {
		tal_resize(&utxos, i + 1);
		utxos[i] = tal_steal(utxos, available[i]);

		if (!wallet_update_output_status(
			w, &available[i]->txid, available[i]->outnum,
			output_state_available, output_state_reserved))
			fatal("Unable to reserve output: %s", w->db->err);

		weight += (32 + 4 + 4) * 4;
		if (utxos[i]->is_p2sh)
			weight += 22 * 4;

		/* Account for witness (1 byte count + sig + key */
		weight += 1 + (1 + 73 + 1 + 33);
		*fee_estimate = weight * feerate_per_kw / 1000;
		satoshi_in += utxos[i]->amount;
		if (satoshi_in >= *fee_estimate + value)
			break;
	}
	tal_free(available);

	if (satoshi_in < *fee_estimate + value) {
		/* Could not collect enough inputs, cleanup and bail */
		utxos = tal_free(utxos);
		db_rollback_transaction(w->db);
	} else {
		/* Commit the db transaction to persist markings */
		db_commit_transaction(w->db);
		*changesatoshi = satoshi_in - value - *fee_estimate;

	}
	return utxos;
}

bool wallet_can_spend(struct wallet *w, const u8 *script,
		      u32 *index, bool *output_is_p2sh)
{
	struct ext_key ext;
	u64 bip32_max_index = db_get_intvar(w->db, "bip32_max_index", 0);
	u32 i;

	/* If not one of these, can't be for us. */
	if (is_p2sh(script))
		*output_is_p2sh = true;
	else if (is_p2wpkh(script))
		*output_is_p2sh = false;
	else
		return false;

	for (i = 0; i <= bip32_max_index; i++) {
		u8 *s;

		if (bip32_key_from_parent(w->bip32_base, i,
					  BIP32_FLAG_KEY_PUBLIC, &ext)
		    != WALLY_OK) {
			abort();
		}
		s = scriptpubkey_p2wpkh_derkey(w, ext.pub_key);
		if (*output_is_p2sh) {
			u8 *p2sh = scriptpubkey_p2sh(w, s);
			tal_free(s);
			s = p2sh;
		}
		if (scripteq(s, script)) {
			tal_free(s);
			*index = i;
			return true;
		}
		tal_free(s);
	}
	return false;
}

s64 wallet_get_newindex(struct lightningd *ld)
{
	u64 newidx = db_get_intvar(ld->wallet->db, "bip32_max_index", 0) + 1;

	if (newidx == BIP32_INITIAL_HARDENED_CHILD)
		return -1;

	db_set_intvar(ld->wallet->db, "bip32_max_index", newidx);
	return newidx;
}

bool wallet_shachain_init(struct wallet *wallet, struct wallet_shachain *chain)
{
	/* Create shachain */
	shachain_init(&chain->chain);
	if (!db_exec(__func__, wallet->db,
		     "INSERT INTO shachains (min_index, num_valid) VALUES (0,0);")) {
		return false;
	}
	chain->id = sqlite3_last_insert_rowid(wallet->db->sql);
	return true;
}

/* TODO(cdecker) Stolen from shachain, move to some appropriate location */
static unsigned int count_trailing_zeroes(shachain_index_t index)
{
#if HAVE_BUILTIN_CTZLL
	return index ? (unsigned int)__builtin_ctzll(index) : SHACHAIN_BITS;
#else
	unsigned int i;

	for (i = 0; i < SHACHAIN_BITS; i++) {
		if (index & (1ULL << i))
			break;
	}
	return i;
#endif
}

bool wallet_shachain_add_hash(struct wallet *wallet,
			      struct wallet_shachain *chain,
			      shachain_index_t index,
			      const struct sha256 *hash)
{
	tal_t *tmpctx = tal_tmpctx(wallet);
	bool ok = true;
	u32 pos = count_trailing_zeroes(index);
	assert(index < SQLITE_MAX_UINT);
	char *hexhash = tal_hexstr(tmpctx, hash, sizeof(struct sha256));
	if (!shachain_add_hash(&chain->chain, index, hash)) {
		tal_free(tmpctx);
		return false;
	}

	db_begin_transaction(wallet->db);

	ok &= db_exec(__func__, wallet->db,
		      "UPDATE shachains SET num_valid=%d, min_index=%" PRIu64
		      " WHERE id=%" PRIu64,
		      chain->chain.num_valid, index, chain->id);

	ok &= db_exec(__func__, wallet->db,
		      "REPLACE INTO shachain_known "
		      "(shachain_id, pos, idx, hash) VALUES "
		      "(%" PRIu64 ", %d, %" PRIu64 ", '%s');",
		      chain->id, pos, index, hexhash);

	if (ok)
		ok &= db_commit_transaction(wallet->db);
	else
		db_rollback_transaction(wallet->db);
	tal_free(tmpctx);
	return ok;
}

bool wallet_shachain_load(struct wallet *wallet, u64 id,
			  struct wallet_shachain *chain)
{
	int err;
	sqlite3_stmt *stmt;
	chain->id = id;
	shachain_init(&chain->chain);

	/* Load shachain metadata */
	stmt = db_query(
	    __func__, wallet->db,
	    "SELECT min_index, num_valid FROM shachains WHERE id=%" PRIu64, id);
	if (!stmt)
		return false;
	err = sqlite3_step(stmt);
	if (err != SQLITE_ROW) {
		sqlite3_finalize(stmt);
		return false;
	}

	chain->chain.min_index = sqlite3_column_int64(stmt, 0);
	chain->chain.num_valid = sqlite3_column_int64(stmt, 1);
	sqlite3_finalize(stmt);

	/* Load shachain known entries */
	stmt = db_query(
	    __func__, wallet->db,
	    "SELECT idx, hash, pos FROM shachain_known WHERE shachain_id=%" PRIu64,
	    id);

	if (!stmt)
		return false;
	while (sqlite3_step(stmt) == SQLITE_ROW) {
		int pos = sqlite3_column_int(stmt, 2);
		chain->chain.known[pos].index = sqlite3_column_int64(stmt, 0);
		sqlite3_column_hexval(stmt, 1, &chain->chain.known[pos].hash,
				      sizeof(struct sha256));
	}
	sqlite3_finalize(stmt);

	return true;
}

static bool sqlite3_column_short_channel_id(sqlite3_stmt *stmt, int col,
					    struct short_channel_id *dest)
{
	const char *source = sqlite3_column_blob(stmt, col);
	size_t sourcelen = sqlite3_column_bytes(stmt, col);
	return short_channel_id_from_str(source, sourcelen, dest);
}

static bool sqlite3_column_sig(sqlite3_stmt *stmt, int col, secp256k1_ecdsa_signature *sig)
{
	u8 buf[64];
	if (!sqlite3_column_hexval(stmt, col, buf, sizeof(buf)))
		return false;
	return secp256k1_ecdsa_signature_parse_compact(secp256k1_ctx, sig, buf) == 1;
}

static bool sqlite3_column_pubkey(sqlite3_stmt *stmt, int col,  struct pubkey *dest)
{
	u8 buf[PUBKEY_DER_LEN];
	if (!sqlite3_column_hexval(stmt, col, buf, sizeof(buf)))
		return false;
	return pubkey_from_der(buf, sizeof(buf), dest);
}

static u8 *sqlite3_column_varhexblob(tal_t *ctx, sqlite3_stmt *stmt, int col)
{
	const u8 *source = sqlite3_column_blob(stmt, col);
	size_t sourcelen = sqlite3_column_bytes(stmt, col);
	return tal_hexdata(ctx, source, sourcelen);
}

static bool wallet_peer_load(struct wallet *w, const u64 id, struct peer *peer)
{
	bool ok = true;
	sqlite3_stmt *stmt = db_query(__func__, w->db, "SELECT id, node_id FROM peers WHERE id=%"PRIu64";", id);
	if (!stmt || sqlite3_step(stmt) != SQLITE_ROW) {
		sqlite3_finalize(stmt);
		return false;
	}
	peer->unique_id = sqlite3_column_int64(stmt, 0);
	ok &= sqlite3_column_pubkey(stmt, 1, &peer->id);
	sqlite3_finalize(stmt);
	return ok;
}

/**
 * wallet_stmt2channel - Helper to populate a wallet_channel from a sqlite3_stmt
 *
 * Returns true on success.
 */
static bool wallet_stmt2channel(struct wallet *w, sqlite3_stmt *stmt,
				struct wallet_channel *chan)
{
	bool ok = true;
	int col = 0;
	struct channel_info *channel_info;
	struct sha256_double temphash;
	struct short_channel_id scid;

	if (!chan->peer) {
		chan->peer = talz(chan, struct peer);
	}
	chan->peer->unique_id = sqlite3_column_int64(stmt, col++);
	chan->peer_id = sqlite3_column_int64(stmt, col++);
	wallet_peer_load(w, chan->peer_id, chan->peer);

	if (sqlite3_column_short_channel_id(stmt, col++, &scid)) {
		chan->peer->scid = tal(chan->peer, struct short_channel_id);
		*chan->peer->scid = scid;
	} else {
		chan->peer->scid = NULL;
	}

	/* TODO(cdecker) Load channel configs into chan */
	col += 2;

	chan->peer->state = sqlite3_column_int(stmt, col++);
	chan->peer->funder = sqlite3_column_int(stmt, col++);
	chan->peer->channel_flags = sqlite3_column_int(stmt, col++);
	chan->peer->minimum_depth = sqlite3_column_int(stmt, col++);
	chan->peer->next_index[LOCAL] = sqlite3_column_int64(stmt, col++);
	chan->peer->next_index[REMOTE] = sqlite3_column_int64(stmt, col++);
	chan->peer->num_revocations_received =
	    sqlite3_column_int64(stmt, col++);
	chan->peer->next_htlc_id = sqlite3_column_int64(stmt, col++);

	if (sqlite3_column_hexval(stmt, col++, &temphash, sizeof(temphash))) {
		chan->peer->funding_txid = tal(chan->peer, struct sha256_double);
		*chan->peer->funding_txid = temphash;
	} else {
		chan->peer->funding_txid = NULL;
	}

	chan->peer->funding_outnum = sqlite3_column_int(stmt, col++);
	chan->peer->funding_satoshi = sqlite3_column_int64(stmt, col++);
	chan->peer->remote_funding_locked =
	    sqlite3_column_int(stmt, col++) != 0;
	chan->peer->push_msat = sqlite3_column_int64(stmt, col++);

	if (sqlite3_column_type(stmt, col) != SQLITE_NULL) {
		chan->peer->our_msatoshi = tal(chan->peer, u64);
		*chan->peer->our_msatoshi = sqlite3_column_int64(stmt, col);
	}else {
		chan->peer->our_msatoshi = tal_free(chan->peer->our_msatoshi);
	}
	col++;

	/* See if we have a valid commit_sig indicating the presence
	 * of channel_info */
	if (sqlite3_column_type(stmt, col) != SQLITE_NULL) {
		/* OK, so we have a valid sig, instantiate and/or fill
		 * in channel_info */
		if (!chan->peer->channel_info)
			chan->peer->channel_info = tal(chan->peer, struct channel_info);
		channel_info = chan->peer->channel_info;

		/* Populate channel_info */
		ok &= sqlite3_column_sig(stmt, col++, &chan->peer->channel_info->commit_sig);
		ok &= sqlite3_column_pubkey(stmt, col++, &chan->peer->channel_info->remote_fundingkey);
		ok &= sqlite3_column_pubkey(stmt, col++, &channel_info->theirbase.revocation);
		ok &= sqlite3_column_pubkey(stmt, col++, &channel_info->theirbase.payment);
		ok &= sqlite3_column_pubkey(stmt, col++, &channel_info->theirbase.delayed_payment);
		ok &= sqlite3_column_pubkey(stmt, col++, &channel_info->remote_per_commit);
		ok &= sqlite3_column_pubkey(stmt, col++, &channel_info->old_remote_per_commit);
		channel_info->feerate_per_kw = sqlite3_column_int64(stmt, col++);
	} else {
		/* No channel_info, skip positions in the result */
		col += 8;
	}

	/* Load shachain */
	u64 shachain_id = sqlite3_column_int64(stmt, col++);
	ok &= wallet_shachain_load(w, shachain_id, &chan->peer->their_shachain);

	/* Do we have a non-null remote_shutdown_scriptpubkey? */
	if (sqlite3_column_type(stmt, col) != SQLITE_NULL) {
		chan->peer->remote_shutdown_scriptpubkey = sqlite3_column_varhexblob(chan->peer, stmt, col++);
		chan->peer->local_shutdown_idx = sqlite3_column_int64(stmt, col++);
	} else {
		chan->peer->remote_shutdown_scriptpubkey = tal_free(chan->peer->remote_shutdown_scriptpubkey);
		chan->peer->local_shutdown_idx = 0;
		col += 2;
	}

	/* Do we have a last_sent_commit, if yes, populate */
	if (sqlite3_column_type(stmt, col) != SQLITE_NULL) {
		if (!chan->peer->last_sent_commit) {
			chan->peer->last_sent_commit = tal(chan->peer, struct changed_htlc);
		}
		chan->peer->last_sent_commit->newstate = sqlite3_column_int64(stmt, col++);
		chan->peer->last_sent_commit->id = sqlite3_column_int64(stmt, col++);
	} else {
		chan->peer->last_sent_commit = tal_free(chan->peer->last_sent_commit);
		col += 2;
	}
	assert(col == 32);

	return ok;
}

bool wallet_channel_load(struct wallet *w, const u64 id,
			 struct wallet_channel *chan)
{
	bool ok;
	/* The explicit query that matches the columns and their order in
	 * wallet_stmt2channel. */
	const char *channel_query =
	    "SELECT id, peer_id, short_channel_id, channel_config_local, "
	    "channel_config_remote, state, funder, channel_flags, "
	    "minimum_depth, "
	    "next_index_local, next_index_remote, num_revocations_received, "
	    "next_htlc_id, funding_tx_id, funding_tx_outnum, funding_satoshi, "
	    "funding_locked_remote, push_msatoshi, msatoshi_local, "
	    "commit_sig_remote, "
	    "fundingkey_remote, revocation_basepoint_remote, "
	    "payment_basepoint_remote, "
	    "delayed_payment_basepoint_remote, per_commit_remote, "
	    "old_per_commit_remote, feerate_per_kw, shachain_remote_id, "
	    "shutdown_scriptpubkey_remote, shutdown_keyidx_local, "
	    "last_sent_commit_state, last_sent_commit_id FROM channels WHERE "
	    "id=%" PRIu64 ";";

	sqlite3_stmt *stmt = db_query(__func__, w->db, channel_query, id);
	if (!stmt || sqlite3_step(stmt) != SQLITE_ROW) {
		sqlite3_finalize(stmt);
		return false;
	}
	ok = wallet_stmt2channel(w, stmt, chan);
	chan->id = id;

	sqlite3_finalize(stmt);
	return ok;
}

/**
 * wallet_shachain_delete - Drop the shachain from the database
 *
 * Deletes the shachain from the database, including dependent
 * shachain_known items.
 */
/* TOOD(cdecker) Uncomment once we have implemented channel delete
static bool wallet_shachain_delete(struct wallet *w,
				   struct wallet_shachain *chain)
{
	return db_exec(__func__, w->db,
		       "DELETE FROM shachains WHERE id=%" PRIu64, chain->id);
}
*/
