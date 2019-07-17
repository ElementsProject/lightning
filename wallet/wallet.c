#include "invoices.h"
#include "wallet.h"

#include <bitcoin/script.h>
#include <ccan/mem/mem.h>
#include <ccan/tal/str/str.h>
#include <common/key_derive.h>
#include <common/memleak.h>
#include <common/wireaddr.h>
#include <inttypes.h>
#include <lightningd/lightningd.h>
#include <lightningd/notification.h>
#include <lightningd/peer_control.h>
#include <lightningd/peer_htlcs.h>
#include <onchaind/gen_onchain_wire.h>
#include <string.h>

#define SQLITE_MAX_UINT 0x7FFFFFFFFFFFFFFF
#define DIRECTION_INCOMING 0
#define DIRECTION_OUTGOING 1
/* How many blocks must a UTXO entry be buried under to be considered old enough
 * to prune? */
#define UTXO_PRUNE_DEPTH 144

static void outpointfilters_init(struct wallet *w)
{
	sqlite3_stmt *stmt;
	struct utxo **utxos = wallet_get_utxos(NULL, w, output_state_any);
	struct bitcoin_txid txid;
	u32 outnum;

	w->owned_outpoints = outpointfilter_new(w);
	for (size_t i = 0; i < tal_count(utxos); i++)
		outpointfilter_add(w->owned_outpoints, &utxos[i]->txid, utxos[i]->outnum);

	tal_free(utxos);

	w->utxoset_outpoints = outpointfilter_new(w);
	stmt = db_select_prepare(w->db, "SELECT txid, outnum FROM utxoset WHERE spendheight is NULL");

	while (db_select_step(w->db, stmt)) {
		sqlite3_column_sha256_double(stmt, 0, &txid.shad);
		outnum = sqlite3_column_int(stmt, 1);
		outpointfilter_add(w->utxoset_outpoints, &txid, outnum);
	}
}

struct wallet *wallet_new(struct lightningd *ld,
			  struct log *log, struct timers *timers)
{
	struct wallet *wallet = tal(ld, struct wallet);
	wallet->ld = ld;
	wallet->db = db_setup(wallet, ld, log);
	wallet->log = log;
	wallet->bip32_base = NULL;
	list_head_init(&wallet->unstored_payments);
	list_head_init(&wallet->unreleased_txs);

	db_begin_transaction(wallet->db);
	wallet->invoices = invoices_new(wallet, wallet->db, log, timers);
	outpointfilters_init(wallet);
	db_commit_transaction(wallet->db);
	return wallet;
}

/* This can fail if we've already seen UTXO. */
bool wallet_add_utxo(struct wallet *w, struct utxo *utxo,
		     enum wallet_output_type type)
{
	sqlite3_stmt *stmt;

	stmt = db_select_prepare(w->db,
				 "SELECT * from outputs WHERE prev_out_tx=? AND prev_out_index=?");
	sqlite3_bind_blob(stmt, 1, &utxo->txid, sizeof(utxo->txid), SQLITE_TRANSIENT);
	sqlite3_bind_int(stmt, 2, utxo->outnum);

	/* If we get a result, that means a clash. */
	if (db_select_step(w->db, stmt)) {
		db_stmt_done(stmt);
		return false;
	}

	stmt = db_prepare(w->db,
			  "INSERT INTO outputs ("
			  "  prev_out_tx"
			  ", prev_out_index"
			  ", value"
			  ", type"
			  ", status"
			  ", keyindex"
			  ", channel_id"
			  ", peer_id"
			  ", commitment_point"
			  ", confirmation_height"
			  ", spend_height"
			  ", scriptpubkey"
			  ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);");
	sqlite3_bind_blob(stmt, 1, &utxo->txid, sizeof(utxo->txid), SQLITE_TRANSIENT);
	sqlite3_bind_int(stmt, 2, utxo->outnum);
	sqlite3_bind_amount_sat(stmt, 3, utxo->amount);
	sqlite3_bind_int(stmt, 4, wallet_output_type_in_db(type));
	sqlite3_bind_int(stmt, 5, output_state_available);
	sqlite3_bind_int(stmt, 6, utxo->keyindex);
	if (utxo->close_info) {
		sqlite3_bind_int64(stmt, 7, utxo->close_info->channel_id);
		sqlite3_bind_node_id(stmt, 8, &utxo->close_info->peer_id);
		sqlite3_bind_pubkey(stmt, 9, &utxo->close_info->commitment_point);
	} else {
		sqlite3_bind_null(stmt, 7);
		sqlite3_bind_null(stmt, 8);
		sqlite3_bind_null(stmt, 9);
	}

	if (utxo->blockheight) {
		sqlite3_bind_int(stmt, 10, *utxo->blockheight);
	} else
		sqlite3_bind_null(stmt, 10);

	if (utxo->spendheight)
		sqlite3_bind_int(stmt, 11, *utxo->spendheight);
	else
		sqlite3_bind_null(stmt, 11);

	if (utxo->scriptPubkey)
		sqlite3_bind_blob(stmt, 12, utxo->scriptPubkey,
				  tal_bytelen(utxo->scriptPubkey),
				  SQLITE_TRANSIENT);
	else
		sqlite3_bind_null(stmt, 12);

	db_exec_prepared(w->db, stmt);
	return true;
}

/**
 * wallet_stmt2output - Extract data from stmt and fill an UTXO
 */
static struct utxo *wallet_stmt2output(const tal_t *ctx, sqlite3_stmt *stmt)
{
	struct utxo *utxo = tal(ctx, struct utxo);
	u32 *blockheight, *spendheight;
	sqlite3_column_sha256_double(stmt, 0, &utxo->txid.shad);
	utxo->outnum = sqlite3_column_int(stmt, 1);
	utxo->amount = sqlite3_column_amount_sat(stmt, 2);
	utxo->is_p2sh = sqlite3_column_int(stmt, 3) == p2sh_wpkh;
	utxo->status = sqlite3_column_int(stmt, 4);
	utxo->keyindex = sqlite3_column_int(stmt, 5);
	if (sqlite3_column_type(stmt, 6) != SQLITE_NULL) {
		utxo->close_info = tal(utxo, struct unilateral_close_info);
		utxo->close_info->channel_id = sqlite3_column_int64(stmt, 6);
		sqlite3_column_node_id(stmt, 7, &utxo->close_info->peer_id);
		sqlite3_column_pubkey(stmt, 8, &utxo->close_info->commitment_point);
	} else {
		utxo->close_info = NULL;
	}

	utxo->blockheight = NULL;
	utxo->spendheight = NULL;
	utxo->scriptPubkey = NULL;

	if (sqlite3_column_type(stmt, 9) != SQLITE_NULL) {
		blockheight = tal(utxo, u32);
		*blockheight = sqlite3_column_int(stmt, 9);
		utxo->blockheight = blockheight;
	}

	if (sqlite3_column_type(stmt, 10) != SQLITE_NULL) {
		spendheight = tal(utxo, u32);
		*spendheight = sqlite3_column_int(stmt, 10);
		utxo->spendheight = spendheight;
	}

	if (sqlite3_column_type(stmt, 11) != SQLITE_NULL) {
		utxo->scriptPubkey =
		    tal_dup_arr(utxo, u8, sqlite3_column_blob(stmt, 11),
				sqlite3_column_bytes(stmt, 11), 0);
	}

	return utxo;
}

bool wallet_update_output_status(struct wallet *w,
				 const struct bitcoin_txid *txid,
				 const u32 outnum, enum output_status oldstatus,
				 enum output_status newstatus)
{
	sqlite3_stmt *stmt;
	if (oldstatus != output_state_any) {
		stmt = db_prepare(
			w->db, "UPDATE outputs SET status=? WHERE status=? AND prev_out_tx=? AND prev_out_index=?");
		sqlite3_bind_int(stmt, 1, output_status_in_db(newstatus));
		sqlite3_bind_int(stmt, 2, output_status_in_db(oldstatus));
		sqlite3_bind_blob(stmt, 3, txid, sizeof(*txid), SQLITE_TRANSIENT);
		sqlite3_bind_int(stmt, 4, outnum);
	} else {
		stmt = db_prepare(
			w->db, "UPDATE outputs SET status=? WHERE prev_out_tx=? AND prev_out_index=?");
		sqlite3_bind_int(stmt, 1, output_status_in_db(newstatus));
		sqlite3_bind_blob(stmt, 2, txid, sizeof(*txid), SQLITE_TRANSIENT);
		sqlite3_bind_int(stmt, 3, outnum);
	}
	db_exec_prepared(w->db, stmt);
	return sqlite3_changes(w->db->sql) > 0;
}

struct utxo **wallet_get_utxos(const tal_t *ctx, struct wallet *w, const enum output_status state)
{
	struct utxo **results;
	int i;
	sqlite3_stmt *stmt;

	if (state == output_state_any)
		stmt = db_select_prepare(w->db,
					 "SELECT"
					 "  prev_out_tx"
					 ", prev_out_index"
					 ", value"
					 ", type"
					 ", status"
					 ", keyindex"
					 ", channel_id"
					 ", peer_id"
					 ", commitment_point"
					 ", confirmation_height"
					 ", spend_height"
					 ", scriptpubkey "
					 "FROM outputs");
	else {
		stmt = db_select_prepare(w->db,
					 "SELECT"
					 "  prev_out_tx"
					 ", prev_out_index"
					 ", value"
					 ", type"
					 ", status"
					 ", keyindex"
					 ", channel_id"
					 ", peer_id"
					 ", commitment_point"
					 ", confirmation_height"
					 ", spend_height"
					 ", scriptpubkey "
					 "FROM outputs "
					 "WHERE status=?1");
		sqlite3_bind_int(stmt, 1, output_status_in_db(state));
	}

	results = tal_arr(ctx, struct utxo*, 0);
	for (i=0; db_select_step(w->db, stmt); i++) {
		struct utxo *u = wallet_stmt2output(results, stmt);
		tal_arr_expand(&results, u);
	}

	return results;
}

struct utxo **wallet_get_unconfirmed_closeinfo_utxos(const tal_t *ctx, struct wallet *w)
{
	struct utxo **results;
	int i;

	sqlite3_stmt *stmt = db_select_prepare(w->db,
					       "SELECT"
					       "  prev_out_tx"
					       ", prev_out_index"
					       ", value"
					       ", type"
					       ", status"
					       ", keyindex"
					       ", channel_id"
					       ", peer_id"
					       ", commitment_point"
					       ", confirmation_height"
					       ", spend_height"
					       ", scriptpubkey"
					       " FROM outputs"
					       " WHERE channel_id IS NOT NULL AND confirmation_height IS NULL");

       	results = tal_arr(ctx, struct utxo*, 0);
	for (i=0; db_select_step(w->db, stmt); i++) {
		struct utxo *u = wallet_stmt2output(results, stmt);
		tal_arr_expand(&results, u);
	}

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
		fatal("Unable to unreserve output");
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
			fatal("Unable to mark output as spent");
		}
	}
}

static const struct utxo **wallet_select(const tal_t *ctx, struct wallet *w,
					 struct amount_sat sat,
					 const u32 feerate_per_kw,
					 size_t outscriptlen,
					 bool may_have_change,
					 u32 maxheight,
					 struct amount_sat *satoshi_in,
					 struct amount_sat *fee_estimate)
{
	size_t i = 0;
	struct utxo **available;
	u64 weight;
	const struct utxo **utxos = tal_arr(ctx, const struct utxo *, 0);
	tal_add_destructor2(utxos, destroy_utxos, w);

	/* version, input count, output count, locktime */
	weight = (4 + 1 + 1 + 4) * 4;

	/* Add segwit fields: marker + flag */
	weight += 1 + 1;

	/* The main output: amount, len, scriptpubkey */
	weight += (8 + 1 + outscriptlen) * 4;

	/* Change output will be P2WPKH */
	if (may_have_change)
		weight += (8 + 1 + BITCOIN_SCRIPTPUBKEY_P2WPKH_LEN) * 4;

	*fee_estimate = AMOUNT_SAT(0);
	*satoshi_in = AMOUNT_SAT(0);

	available = wallet_get_utxos(ctx, w, output_state_available);

	for (i = 0; i < tal_count(available); i++) {
		size_t input_weight;
		struct amount_sat needed;
		struct utxo *u = tal_steal(utxos, available[i]);

		/* If we require confirmations check that we have a
		 * confirmation height and that it is below the required
		 * maxheight (current_height - minconf */
		if (maxheight != 0 &&
		    (!u->blockheight || *u->blockheight > maxheight))
			continue;

		tal_arr_expand(&utxos, u);

		if (!wallet_update_output_status(
			w, &available[i]->txid, available[i]->outnum,
			output_state_available, output_state_reserved))
			fatal("Unable to reserve output");

		/* Input weight: txid + index + sequence */
		input_weight = (32 + 4 + 4) * 4;

		/* We always encode the length of the script, even if empty */
		input_weight += 1 * 4;

		/* P2SH variants include push of <0 <20-byte-key-hash>> */
		if (u->is_p2sh)
			input_weight += 23 * 4;

		/* Account for witness (1 byte count + sig + key) */
		input_weight += 1 + (1 + 73 + 1 + 33);

		weight += input_weight;

		if (!amount_sat_add(satoshi_in, *satoshi_in, u->amount))
			fatal("Overflow in available satoshis %zu/%zu %s + %s",
			      i, tal_count(available),
			      type_to_string(tmpctx, struct amount_sat,
					     satoshi_in),
			      type_to_string(tmpctx, struct amount_sat,
					     &u->amount));

		*fee_estimate = amount_tx_fee(feerate_per_kw, weight);
		if (!amount_sat_add(&needed, sat, *fee_estimate))
			fatal("Overflow in fee estimate %zu/%zu %s + %s",
			      i, tal_count(available),
			      type_to_string(tmpctx, struct amount_sat, &sat),
			      type_to_string(tmpctx, struct amount_sat,
					     fee_estimate));
		if (amount_sat_greater_eq(*satoshi_in, needed))
			break;
	}
	tal_free(available);

	return utxos;
}

const struct utxo **wallet_select_coins(const tal_t *ctx, struct wallet *w,
					struct amount_sat sat,
					const u32 feerate_per_kw,
					size_t outscriptlen,
					u32 maxheight,
					struct amount_sat *fee_estimate,
					struct amount_sat *change)
{
	struct amount_sat satoshi_in;
	const struct utxo **utxo;

	utxo = wallet_select(ctx, w, sat, feerate_per_kw,
			     outscriptlen, true, maxheight,
			     &satoshi_in, fee_estimate);

	/* Couldn't afford it? */
	if (!amount_sat_sub(change, satoshi_in, sat)
	    || !amount_sat_sub(change, *change, *fee_estimate))
		return tal_free(utxo);

	return utxo;
}

const struct utxo **wallet_select_specific(const tal_t *ctx, struct wallet *w,
					struct bitcoin_txid **txids,
                    u32 **outnums)
{
	size_t i, j;
	struct utxo **available;
	const struct utxo **utxos = tal_arr(ctx, const struct utxo*, 0);
	tal_add_destructor2(utxos, destroy_utxos, w);

	available = wallet_get_utxos(ctx, w, output_state_available);
	for (i = 0; i < tal_count(txids); i++) {
		for (j = 0; j < tal_count(available); j++) {

			if (bitcoin_txid_eq(&available[j]->txid, txids[i])
					&& available[j]->outnum == *outnums[i]) {
				struct utxo *u = tal_steal(utxos, available[j]);
				tal_arr_expand(&utxos, u);

				if (!wallet_update_output_status(
					w, &available[j]->txid, available[j]->outnum,
					output_state_available, output_state_reserved))
					fatal("Unable to reserve output");
			}
		}
	}
	tal_free(available);

	return utxos;
}

const struct utxo **wallet_select_all(const tal_t *ctx, struct wallet *w,
				      const u32 feerate_per_kw,
				      size_t outscriptlen,
				      u32 maxheight,
				      struct amount_sat *value,
				      struct amount_sat *fee_estimate)
{
	struct amount_sat satoshi_in;
	const struct utxo **utxo;

	/* Huge value, but won't overflow on addition */
	utxo = wallet_select(ctx, w, AMOUNT_SAT(1ULL << 56), feerate_per_kw,
			     outscriptlen, false, maxheight,
			     &satoshi_in, fee_estimate);

	/* Can't afford fees? */
	if (!amount_sat_sub(value, satoshi_in, *fee_estimate))
		return tal_free(utxo);

	return utxo;
}

bool wallet_can_spend(struct wallet *w, const u8 *script,
		      u32 *index, bool *output_is_p2sh)
{
	struct ext_key ext;
	u64 bip32_max_index = db_get_intvar(w->db, "bip32_max_index", 0);
	u32 i;

	/* If not one of these, can't be for us. */
	if (is_p2sh(script, NULL))
		*output_is_p2sh = true;
	else if (is_p2wpkh(script, NULL))
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

static void wallet_shachain_init(struct wallet *wallet,
				 struct wallet_shachain *chain)
{
	sqlite3_stmt *stmt;

	assert(chain->id == 0);

	/* Create shachain */
	shachain_init(&chain->chain);
	stmt = db_prepare(wallet->db, "INSERT INTO shachains (min_index, num_valid) VALUES (?, 0);");
	sqlite3_bind_int64(stmt, 1, chain->chain.min_index);
	db_exec_prepared(wallet->db, stmt);

	chain->id = sqlite3_last_insert_rowid(wallet->db->sql);
}

/* TODO(cdecker) Stolen from shachain, move to some appropriate location */
static unsigned int count_trailing_zeroes(uint64_t index)
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
			      uint64_t index,
			      const struct secret *hash)
{
	sqlite3_stmt *stmt;
	u32 pos = count_trailing_zeroes(index);
	struct sha256 s;

	BUILD_ASSERT(sizeof(s) == sizeof(*hash));
	memcpy(&s, hash, sizeof(s));

	assert(index < SQLITE_MAX_UINT);
	if (!shachain_add_hash(&chain->chain, index, &s)) {
		return false;
	}

	stmt = db_prepare(wallet->db, "UPDATE shachains SET num_valid=?, min_index=? WHERE id=?");
	sqlite3_bind_int(stmt, 1, chain->chain.num_valid);
	sqlite3_bind_int64(stmt, 2, index);
	sqlite3_bind_int64(stmt, 3, chain->id);
	db_exec_prepared(wallet->db, stmt);

	stmt = db_prepare(
		wallet->db,
		"REPLACE INTO shachain_known (shachain_id, pos, idx, hash) VALUES (?, ?, ?, ?);");
	sqlite3_bind_int64(stmt, 1, chain->id);
	sqlite3_bind_int(stmt, 2, pos);
	sqlite3_bind_int64(stmt, 3, index);
	sqlite3_bind_blob(stmt, 4, hash, sizeof(*hash), SQLITE_TRANSIENT);
	db_exec_prepared(wallet->db, stmt);

	return true;
}

bool wallet_shachain_load(struct wallet *wallet, u64 id,
			  struct wallet_shachain *chain)
{
	sqlite3_stmt *stmt;
	chain->id = id;
	shachain_init(&chain->chain);

	/* Load shachain metadata */
	stmt = db_select_prepare(wallet->db, "SELECT min_index, num_valid FROM shachains WHERE id=?");
	sqlite3_bind_int64(stmt, 1, id);

	if (!db_select_step(wallet->db, stmt))
		return false;

	chain->chain.min_index = sqlite3_column_int64(stmt, 0);
	chain->chain.num_valid = sqlite3_column_int64(stmt, 1);
	db_stmt_done(stmt);

	/* Load shachain known entries */
	stmt = db_select_prepare(wallet->db, "SELECT idx, hash, pos FROM shachain_known WHERE shachain_id=?");
	sqlite3_bind_int64(stmt, 1, id);

	while (db_select_step(wallet->db, stmt)) {
		int pos = sqlite3_column_int(stmt, 2);
		chain->chain.known[pos].index = sqlite3_column_int64(stmt, 0);
		memcpy(&chain->chain.known[pos].hash, sqlite3_column_blob(stmt, 1), sqlite3_column_bytes(stmt, 1));
	}
	return true;
}

static struct peer *wallet_peer_load(struct wallet *w, const u64 dbid)
{
	const unsigned char *addrstr;
	struct peer *peer;
	struct node_id id;
	struct wireaddr_internal addr;

	sqlite3_stmt *stmt = db_select_prepare(
	    w->db, "SELECT id, node_id, address FROM peers WHERE id=?;");
	sqlite3_bind_int64(stmt, 1, dbid);

	if (!db_select_step(w->db, stmt))
		return NULL;

	if (!sqlite3_column_node_id(stmt, 1, &id)) {
		db_stmt_done(stmt);
		return NULL;
	}
	addrstr = sqlite3_column_text(stmt, 2);
	if (!parse_wireaddr_internal((const char*)addrstr, &addr, DEFAULT_PORT, false, false, true, NULL)) {
		db_stmt_done(stmt);
		return NULL;
	}

	peer = new_peer(w->ld, sqlite3_column_int64(stmt, 0),
			&id, &addr);
	db_stmt_done(stmt);

	return peer;
}

static secp256k1_ecdsa_signature *
wallet_htlc_sigs_load(const tal_t *ctx, struct wallet *w, u64 channelid)
{
	sqlite3_stmt *stmt = db_select_prepare(w->db, "SELECT signature FROM htlc_sigs WHERE channelid = ?");
	secp256k1_ecdsa_signature *htlc_sigs = tal_arr(ctx, secp256k1_ecdsa_signature, 0);
	sqlite3_bind_int64(stmt, 1, channelid);

	while (db_select_step(w->db, stmt)) {
		secp256k1_ecdsa_signature sig;
		sqlite3_column_signature(stmt, 0, &sig);
		tal_arr_expand(&htlc_sigs, sig);
	}

	log_debug(w->log, "Loaded %zu HTLC signatures from DB",
		  tal_count(htlc_sigs));
	return htlc_sigs;
}

bool wallet_remote_ann_sigs_load(const tal_t *ctx, struct wallet *w, u64 id,
				 secp256k1_ecdsa_signature **remote_ann_node_sig,
				 secp256k1_ecdsa_signature **remote_ann_bitcoin_sig)
{
	sqlite3_stmt *stmt;
	int res;
	stmt = db_select_prepare(w->db,
				 "SELECT remote_ann_node_sig, remote_ann_bitcoin_sig"
				 " FROM channels WHERE id = ?");
	sqlite3_bind_int64(stmt, 1, id);

	res = sqlite3_step(stmt);

	/* This must succeed, since we know the channel exists */
	assert(res == SQLITE_ROW);

	/* if only one sig exists, forget the sig and hope peer send new ones*/
	if(sqlite3_column_type(stmt, 0) == SQLITE_NULL ||
			sqlite3_column_type(stmt, 1) == SQLITE_NULL) {
		*remote_ann_node_sig = *remote_ann_bitcoin_sig = NULL;
		db_stmt_done(stmt);
		return true;
	}

	/* the case left over is both sigs exist */
	*remote_ann_node_sig = tal(ctx, secp256k1_ecdsa_signature);
	*remote_ann_bitcoin_sig = tal(ctx, secp256k1_ecdsa_signature);

	if (!sqlite3_column_signature(stmt, 0, *remote_ann_node_sig))
		goto fail;

	if (!sqlite3_column_signature(stmt, 1, *remote_ann_bitcoin_sig))
		goto fail;

	db_stmt_done(stmt);
	return true;

fail:
	*remote_ann_node_sig = tal_free(*remote_ann_node_sig);
	*remote_ann_bitcoin_sig = tal_free(*remote_ann_bitcoin_sig);
	db_stmt_done(stmt);
	return false;
}

/**
 * wallet_stmt2channel - Helper to populate a wallet_channel from a sqlite3_stmt
 */
static struct channel *wallet_stmt2channel(struct wallet *w, sqlite3_stmt *stmt)
{
	bool ok = true;
	struct channel_info channel_info;
	struct short_channel_id *scid;
	struct channel *chan;
	u64 peer_dbid;
	struct peer *peer;
	struct wallet_shachain wshachain;
	struct channel_config our_config;
	struct bitcoin_txid funding_txid;
	struct bitcoin_signature last_sig;
	u8 *remote_shutdown_scriptpubkey;
	struct changed_htlc *last_sent_commit;
	s64 final_key_idx;
	struct basepoints local_basepoints;
	struct pubkey local_funding_pubkey;
	struct pubkey *future_per_commitment_point;

	peer_dbid = sqlite3_column_int64(stmt, 1);
	peer = find_peer_by_dbid(w->ld, peer_dbid);
	if (!peer) {
		peer = wallet_peer_load(w, peer_dbid);
		if (!peer) {
			return NULL;
		}
	}

	if (sqlite3_column_type(stmt, 2) != SQLITE_NULL) {
		scid = tal(tmpctx, struct short_channel_id);
		if (!sqlite3_column_short_channel_id(stmt, 2, scid))
			return NULL;
	} else {
		scid = NULL;
	}

	ok &= wallet_shachain_load(w, sqlite3_column_int64(stmt, 27),
				   &wshachain);

	remote_shutdown_scriptpubkey = sqlite3_column_arr(tmpctx, stmt, 28, u8);

	/* Do we have a last_sent_commit, if yes, populate */
	if (sqlite3_column_type(stmt, 41) != SQLITE_NULL) {
		const u8 *cursor = sqlite3_column_blob(stmt, 41);
		size_t len = sqlite3_column_bytes(stmt, 41);
		size_t n = 0;
		last_sent_commit = tal_arr(tmpctx, struct changed_htlc, n);
		while (len) {
			tal_resize(&last_sent_commit, n+1);
			fromwire_changed_htlc(&cursor, &len,
					      &last_sent_commit[n++]);
		}
	} else
		last_sent_commit = NULL;

#ifdef COMPAT_V060
	if (!last_sent_commit && sqlite3_column_type(stmt, 30) != SQLITE_NULL) {
		last_sent_commit = tal(tmpctx, struct changed_htlc);
		last_sent_commit->newstate = sqlite3_column_int64(stmt, 30);
		last_sent_commit->id = sqlite3_column_int64(stmt, 31);
	}
#endif

	if (sqlite3_column_type(stmt, 40) != SQLITE_NULL) {
		future_per_commitment_point = tal(tmpctx, struct pubkey);
		ok &= sqlite3_column_pubkey(stmt, 40,
					    future_per_commitment_point);
	} else
		future_per_commitment_point = NULL;

	ok &= wallet_channel_config_load(w, sqlite3_column_int64(stmt, 3),
					 &our_config);
	ok &= sqlite3_column_sha256_double(stmt, 12, &funding_txid.shad);

	ok &= sqlite3_column_signature(stmt, 33, &last_sig.s);
	last_sig.sighash_type = SIGHASH_ALL;

	/* Populate channel_info */
	ok &= sqlite3_column_pubkey(stmt, 18, &channel_info.remote_fundingkey);
	ok &= sqlite3_column_pubkey(stmt, 19, &channel_info.theirbase.revocation);
	ok &= sqlite3_column_pubkey(stmt, 20, &channel_info.theirbase.payment);
	ok &= sqlite3_column_pubkey(stmt, 21, &channel_info.theirbase.htlc);
	ok &= sqlite3_column_pubkey(stmt, 22, &channel_info.theirbase.delayed_payment);
	ok &= sqlite3_column_pubkey(stmt, 23, &channel_info.remote_per_commit);
	ok &= sqlite3_column_pubkey(stmt, 24, &channel_info.old_remote_per_commit);
	channel_info.feerate_per_kw[LOCAL] = sqlite3_column_int(stmt, 25);
	channel_info.feerate_per_kw[REMOTE] = sqlite3_column_int(stmt, 26);

	wallet_channel_config_load(w, sqlite3_column_int64(stmt, 4),
				   &channel_info.their_config);

	if (!ok) {
		return NULL;
	}

	final_key_idx = sqlite3_column_int64(stmt, 29);
	if (final_key_idx < 0) {
		log_broken(w->log, "%s: Final key < 0", __func__);
		return NULL;
	}

	get_channel_basepoints(w->ld, &peer->id, sqlite3_column_int64(stmt, 0),
			       &local_basepoints, &local_funding_pubkey);
	chan = new_channel(peer, sqlite3_column_int64(stmt, 0),
			   &wshachain,
			   sqlite3_column_int(stmt, 5),
			   sqlite3_column_int(stmt, 6),
			   NULL, /* Set up fresh log */
			   "Loaded from database",
			   sqlite3_column_int(stmt, 7),
			   &our_config,
			   sqlite3_column_int(stmt, 8),
			   sqlite3_column_int64(stmt, 9),
			   sqlite3_column_int64(stmt, 10),
			   sqlite3_column_int64(stmt, 11),
			   &funding_txid,
			   sqlite3_column_int(stmt, 13),
			   sqlite3_column_amount_sat(stmt, 14),
			   sqlite3_column_amount_msat(stmt, 16),
			   sqlite3_column_int(stmt, 15) != 0,
			   scid,
			   sqlite3_column_amount_msat(stmt, 17),
			   sqlite3_column_amount_msat(stmt, 38), /* msatoshi_to_us_min */
			   sqlite3_column_amount_msat(stmt, 39), /* msatoshi_to_us_max */
			   sqlite3_column_tx(tmpctx, stmt, 32),
			   &last_sig,
			   wallet_htlc_sigs_load(tmpctx, w,
						 sqlite3_column_int64(stmt, 0)),
			   &channel_info,
			   remote_shutdown_scriptpubkey,
			   final_key_idx,
			   sqlite3_column_int(stmt, 34) != 0,
			   last_sent_commit,
			   sqlite3_column_int64(stmt, 35),
			   sqlite3_column_int(stmt, 36),
			   sqlite3_column_int(stmt, 37),
			   /* Not connected */
			   false,
			   &local_basepoints, &local_funding_pubkey,
			   future_per_commitment_point,
			   sqlite3_column_int(stmt, 42),
			   sqlite3_column_int(stmt, 43),
			   sqlite3_column_arr(tmpctx, stmt, 44, u8));
	return chan;
}

static void set_max_channel_dbid(struct wallet *w)
{
	sqlite3_stmt *stmt;
	int result;

	stmt = db_select(w->db, "SELECT id FROM channels ORDER BY id DESC LIMIT 1;");
	w->max_channel_dbid = 0;

	result = sqlite3_step(stmt);
	if (result == SQLITE_ROW)
		w->max_channel_dbid = sqlite3_column_int64(stmt, 0);

	db_stmt_done(stmt);
}

static bool wallet_channels_load_active(struct wallet *w)
{
	bool ok = true;
	sqlite3_stmt *stmt;
	int count = 0;

	/* We load all channels */
	stmt = db_select(w->db, "SELECT"
				"  id"
				", peer_id"
				", short_channel_id"
				", channel_config_local"
				", channel_config_remote"
				", state"
				", funder"
				", channel_flags"
				", minimum_depth"
				", next_index_local"
				", next_index_remote"
				", next_htlc_id"
				", funding_tx_id"
				", funding_tx_outnum"
				", funding_satoshi"
				", funding_locked_remote"
				", push_msatoshi"
				", msatoshi_local"
				", fundingkey_remote"
				", revocation_basepoint_remote"
				", payment_basepoint_remote"
				", htlc_basepoint_remote"
				", delayed_payment_basepoint_remote"
				", per_commit_remote"
				", old_per_commit_remote"
				", local_feerate_per_kw"
				", remote_feerate_per_kw"
				", shachain_remote_id"
				", shutdown_scriptpubkey_remote"
				", shutdown_keyidx_local"
				", last_sent_commit_state"
				", last_sent_commit_id"
				", last_tx"
				", last_sig"
				", last_was_revoke"
				", first_blocknum"
				", min_possible_feerate"
				", max_possible_feerate"
				", msatoshi_to_us_min"
				", msatoshi_to_us_max"
				", future_per_commitment_point"
				", last_sent_commit"
				", feerate_base"
				", feerate_ppm"
				", remote_upfront_shutdown_script"
				" FROM channels WHERE state < ?;");
	sqlite3_bind_int(stmt, 1, CLOSED);

	while (db_select_step(w->db, stmt)) {
		struct channel *c = wallet_stmt2channel(w, stmt);
		if (!c) {
			ok = false;
			db_stmt_done(stmt);
			break;
		}
		count++;
	}
	log_debug(w->log, "Loaded %d channels from DB", count);

	return ok;
}

bool wallet_init_channels(struct wallet *w)
{
	/* We set the max channel database id separately */
	set_max_channel_dbid(w);
	return wallet_channels_load_active(w);
}


static
void wallet_channel_stats_incr_x(struct wallet *w,
				 char const *dir,
				 char const *typ,
				 u64 cdbid,
				 struct amount_msat msat)
{
	char const *payments_stat = tal_fmt(tmpctx, "%s_payments_%s",
					    dir, typ);
	char const *msatoshi_stat = tal_fmt(tmpctx, "%s_msatoshi_%s",
					    dir, typ);
	char const *qry = tal_fmt(tmpctx,
				  "UPDATE channels"
				  "   SET %s = COALESCE(%s, 0) + 1"
				  "     , %s = COALESCE(%s, 0) + %"PRIu64""
				  " WHERE id = %"PRIu64";",
				  payments_stat, payments_stat,
				  msatoshi_stat, msatoshi_stat, msat.millisatoshis, /* Raw: db access */
				  cdbid);
	sqlite3_stmt *stmt = db_prepare(w->db, qry);
	db_exec_prepared(w->db, stmt);
}
void wallet_channel_stats_incr_in_offered(struct wallet *w, u64 id,
					  struct amount_msat m)
{
	wallet_channel_stats_incr_x(w, "in", "offered", id, m);
}
void wallet_channel_stats_incr_in_fulfilled(struct wallet *w, u64 id,
					    struct amount_msat m)
{
	wallet_channel_stats_incr_x(w, "in", "fulfilled", id, m);
}
void wallet_channel_stats_incr_out_offered(struct wallet *w, u64 id,
					    struct amount_msat m)
{
	wallet_channel_stats_incr_x(w, "out", "offered", id, m);
}
void wallet_channel_stats_incr_out_fulfilled(struct wallet *w, u64 id,
					    struct amount_msat m)
{
	wallet_channel_stats_incr_x(w, "out", "fulfilled", id, m);
}

void wallet_channel_stats_load(struct wallet *w,
			       u64 id,
			       struct channel_stats *stats)
{
	sqlite3_stmt *stmt;
	int res;
	stmt = db_select_prepare(w->db,
				 "SELECT"
			  "   in_payments_offered,  in_payments_fulfilled"
			  ",  in_msatoshi_offered,  in_msatoshi_fulfilled"
			  ", out_payments_offered, out_payments_fulfilled"
			  ", out_msatoshi_offered, out_msatoshi_fulfilled"
			  "  FROM channels"
			  " WHERE id = ?");
	sqlite3_bind_int64(stmt, 1, id);

	res = sqlite3_step(stmt);

	/* This must succeed, since we know the channel exists */
	assert(res == SQLITE_ROW);

	stats->in_payments_offered = sqlite3_column_int64(stmt, 0);
	stats->in_payments_fulfilled = sqlite3_column_int64(stmt, 1);
	stats->in_msatoshi_offered = sqlite3_column_amount_msat(stmt, 2);
	stats->in_msatoshi_fulfilled = sqlite3_column_amount_msat(stmt, 3);
	stats->out_payments_offered = sqlite3_column_int64(stmt, 4);
	stats->out_payments_fulfilled = sqlite3_column_int64(stmt, 5);
	stats->out_msatoshi_offered = sqlite3_column_amount_msat(stmt, 6);
	stats->out_msatoshi_fulfilled = sqlite3_column_amount_msat(stmt, 7);
	db_stmt_done(stmt);
}

void wallet_blocks_heights(struct wallet *w, u32 def, u32 *min, u32 *max)
{
	assert(min != NULL && max != NULL);
	sqlite3_stmt *stmt = db_select_prepare(w->db, "SELECT MIN(height), MAX(height) FROM blocks;");

	*min = def;
	*max = def;

	/* If we ever processed a block we'll get the latest block in the chain */
	if (db_select_step(w->db, stmt)) {
		if (sqlite3_column_type(stmt, 0) != SQLITE_NULL) {
			*min = sqlite3_column_int(stmt, 0);
			*max = sqlite3_column_int(stmt, 1);
		}
		db_stmt_done(stmt);
	}
}

static void wallet_channel_config_insert(struct wallet *w,
					 struct channel_config *cc)
{
	sqlite3_stmt *stmt;

	assert(cc->id == 0);

	stmt = db_prepare(w->db, "INSERT INTO channel_configs DEFAULT VALUES;");
	db_exec_prepared(w->db, stmt);
	cc->id = sqlite3_last_insert_rowid(w->db->sql);
}

static void wallet_channel_config_save(struct wallet *w,
				       const struct channel_config *cc)
{
	sqlite3_stmt *stmt;

	assert(cc->id != 0);
	stmt = db_prepare(w->db, "UPDATE channel_configs SET"
			  "  dust_limit_satoshis=?,"
			  "  max_htlc_value_in_flight_msat=?,"
			  "  channel_reserve_satoshis=?,"
			  "  htlc_minimum_msat=?,"
			  "  to_self_delay=?,"
			  "  max_accepted_htlcs=?"
			  " WHERE id=?;");
	sqlite3_bind_amount_sat(stmt, 1, cc->dust_limit);
	sqlite3_bind_amount_msat(stmt, 2, cc->max_htlc_value_in_flight);
	sqlite3_bind_amount_sat(stmt, 3, cc->channel_reserve);
	sqlite3_bind_amount_msat(stmt, 4, cc->htlc_minimum);
	sqlite3_bind_int(stmt, 5, cc->to_self_delay);
	sqlite3_bind_int(stmt, 6, cc->max_accepted_htlcs);
	sqlite3_bind_int64(stmt, 7, cc->id);
	db_exec_prepared(w->db, stmt);
}

bool wallet_channel_config_load(struct wallet *w, const u64 id,
				struct channel_config *cc)
{
	bool ok = true;
	int col = 1;
	const char *query =
	    "SELECT id, dust_limit_satoshis, max_htlc_value_in_flight_msat, "
	    "channel_reserve_satoshis, htlc_minimum_msat, to_self_delay, "
	    "max_accepted_htlcs FROM channel_configs WHERE id= ? ;";
	sqlite3_stmt *stmt = db_select_prepare(w->db, query);
	sqlite3_bind_int64(stmt, 1, id);

	if (!db_select_step(w->db, stmt))
		return false;

	cc->id = id;
	cc->dust_limit = sqlite3_column_amount_sat(stmt, col++);
	cc->max_htlc_value_in_flight = sqlite3_column_amount_msat(stmt, col++);
	cc->channel_reserve = sqlite3_column_amount_sat(stmt, col++);
	cc->htlc_minimum = sqlite3_column_amount_msat(stmt, col++);
	cc->to_self_delay = sqlite3_column_int(stmt, col++);
	cc->max_accepted_htlcs = sqlite3_column_int(stmt, col++);
	assert(col == 7);
	db_stmt_done(stmt);
	return ok;
}

u64 wallet_get_channel_dbid(struct wallet *wallet)
{
	return ++wallet->max_channel_dbid;
}

/* When we receive the remote announcement message, we will also call this function */
void wallet_announcement_save(struct wallet *w, u64 id,
			      secp256k1_ecdsa_signature *remote_ann_node_sig,
			      secp256k1_ecdsa_signature *remote_ann_bitcoin_sig)
{
	sqlite3_stmt *stmt;

	stmt = db_prepare(w->db, "UPDATE channels SET"
			  "  remote_ann_node_sig=?,"
			  "  remote_ann_bitcoin_sig=?"
			  " WHERE id=?");

	sqlite3_bind_signature(stmt, 1, remote_ann_node_sig);
	sqlite3_bind_signature(stmt, 2, remote_ann_bitcoin_sig);
	sqlite3_bind_int64(stmt, 3, id);
	db_exec_prepared(w->db, stmt);
}

void wallet_channel_save(struct wallet *w, struct channel *chan)
{
	sqlite3_stmt *stmt;
	u8 *last_sent_commit;
	assert(chan->first_blocknum);

	wallet_channel_config_save(w, &chan->our_config);

	stmt = db_prepare(w->db, "UPDATE channels SET"
			  "  shachain_remote_id=?,"
			  "  short_channel_id=?,"
			  "  state=?,"
			  "  funder=?,"
			  "  channel_flags=?,"
			  "  minimum_depth=?,"
			  "  next_index_local=?,"
			  "  next_index_remote=?,"
			  "  next_htlc_id=?,"
			  "  funding_tx_id=?,"
			  "  funding_tx_outnum=?,"
			  "  funding_satoshi=?,"
			  "  funding_locked_remote=?,"
			  "  push_msatoshi=?,"
			  "  msatoshi_local=?,"
			  "  shutdown_scriptpubkey_remote=?,"
			  "  shutdown_keyidx_local=?,"
			  "  channel_config_local=?,"
			  "  last_tx=?, last_sig=?,"
			  "  last_was_revoke=?,"
			  "  min_possible_feerate=?,"
			  "  max_possible_feerate=?,"
			  "  msatoshi_to_us_min=?,"
			  "  msatoshi_to_us_max=?,"
			  "  feerate_base=?,"
			  "  feerate_ppm=?,"
			  "  remote_upfront_shutdown_script=?"
			  " WHERE id=?");
	sqlite3_bind_int64(stmt, 1, chan->their_shachain.id);
	if (chan->scid)
		sqlite3_bind_short_channel_id(stmt, 2, chan->scid);
	else
		sqlite3_bind_null(stmt, 2);
	sqlite3_bind_int(stmt, 3, chan->state);
	sqlite3_bind_int(stmt, 4, chan->funder);
	sqlite3_bind_int(stmt, 5, chan->channel_flags);
	sqlite3_bind_int(stmt, 6, chan->minimum_depth);

	sqlite3_bind_int64(stmt, 7, chan->next_index[LOCAL]);
	sqlite3_bind_int64(stmt, 8, chan->next_index[REMOTE]);
	sqlite3_bind_int64(stmt, 9, chan->next_htlc_id);

	sqlite3_bind_sha256_double(stmt, 10, &chan->funding_txid.shad);

	sqlite3_bind_int(stmt, 11, chan->funding_outnum);
	sqlite3_bind_amount_sat(stmt, 12, chan->funding);
	sqlite3_bind_int(stmt, 13, chan->remote_funding_locked);
	sqlite3_bind_amount_msat(stmt, 14, chan->push);
	sqlite3_bind_amount_msat(stmt, 15, chan->our_msat);

	if (chan->remote_shutdown_scriptpubkey)
		sqlite3_bind_blob(stmt, 16, chan->remote_shutdown_scriptpubkey,
				  tal_count(chan->remote_shutdown_scriptpubkey),
				  SQLITE_TRANSIENT);
	else
		sqlite3_bind_null(stmt, 16);

	sqlite3_bind_int64(stmt, 17, chan->final_key_idx);
	sqlite3_bind_int64(stmt, 18, chan->our_config.id);
	sqlite3_bind_tx(stmt, 19, chan->last_tx);
	sqlite3_bind_signature(stmt, 20, &chan->last_sig.s);
	sqlite3_bind_int(stmt, 21, chan->last_was_revoke);
	sqlite3_bind_int(stmt, 22, chan->min_possible_feerate);
	sqlite3_bind_int(stmt, 23, chan->max_possible_feerate);
	sqlite3_bind_amount_msat(stmt, 24, chan->msat_to_us_min);
	sqlite3_bind_amount_msat(stmt, 25, chan->msat_to_us_max);
	sqlite3_bind_int(stmt, 26, chan->feerate_base);
	sqlite3_bind_int(stmt, 27, chan->feerate_ppm);
	if (chan->remote_upfront_shutdown_script)
		sqlite3_bind_blob(stmt, 28, chan->remote_upfront_shutdown_script,
				  tal_count(chan->remote_upfront_shutdown_script),
				  SQLITE_TRANSIENT);
	else
		sqlite3_bind_null(stmt, 28);
	sqlite3_bind_int64(stmt, 29, chan->dbid);
	db_exec_prepared(w->db, stmt);

	wallet_channel_config_save(w, &chan->channel_info.their_config);
	stmt = db_prepare(w->db, "UPDATE channels SET"
			  "  fundingkey_remote=?,"
			  "  revocation_basepoint_remote=?,"
			  "  payment_basepoint_remote=?,"
			  "  htlc_basepoint_remote=?,"
			  "  delayed_payment_basepoint_remote=?,"
			  "  per_commit_remote=?,"
			  "  old_per_commit_remote=?,"
			  "  local_feerate_per_kw=?,"
			  "  remote_feerate_per_kw=?,"
			  "  channel_config_remote=?,"
			  "  future_per_commitment_point=?"
			  " WHERE id=?");
	sqlite3_bind_pubkey(stmt, 1,  &chan->channel_info.remote_fundingkey);
	sqlite3_bind_pubkey(stmt, 2,  &chan->channel_info.theirbase.revocation);
	sqlite3_bind_pubkey(stmt, 3,  &chan->channel_info.theirbase.payment);
	sqlite3_bind_pubkey(stmt, 4,  &chan->channel_info.theirbase.htlc);
	sqlite3_bind_pubkey(stmt, 5,  &chan->channel_info.theirbase.delayed_payment);
	sqlite3_bind_pubkey(stmt, 6,  &chan->channel_info.remote_per_commit);
	sqlite3_bind_pubkey(stmt, 7,  &chan->channel_info.old_remote_per_commit);
	sqlite3_bind_int(stmt, 8, chan->channel_info.feerate_per_kw[LOCAL]);
	sqlite3_bind_int(stmt, 9, chan->channel_info.feerate_per_kw[REMOTE]);
	sqlite3_bind_int64(stmt, 10, chan->channel_info.their_config.id);
	if (chan->future_per_commitment_point)
		sqlite3_bind_pubkey(stmt, 11, chan->future_per_commitment_point);
	else
		sqlite3_bind_null(stmt, 11);
	sqlite3_bind_int64(stmt, 12, chan->dbid);
	db_exec_prepared(w->db, stmt);

	/* If we have a last_sent_commit, store it */
	last_sent_commit = tal_arr(tmpctx, u8, 0);
	for (size_t i = 0; i < tal_count(chan->last_sent_commit); i++)
		towire_changed_htlc(&last_sent_commit,
				    &chan->last_sent_commit[i]);

	stmt = db_prepare(w->db,
			  "UPDATE channels SET"
			  "  last_sent_commit=?"
			  " WHERE id=?");
	if (tal_count(last_sent_commit))
		sqlite3_bind_blob(stmt, 1,
				  last_sent_commit, tal_count(last_sent_commit),
				  SQLITE_TRANSIENT);
	else
		sqlite3_bind_null(stmt, 1);
	sqlite3_bind_int64(stmt, 2, chan->dbid);
	db_exec_prepared(w->db, stmt);
}

void wallet_channel_insert(struct wallet *w, struct channel *chan)
{
	sqlite3_stmt *stmt;

	if (chan->peer->dbid == 0) {
		/* Need to create the peer first */
		stmt = db_prepare(w->db, "INSERT INTO peers (node_id, address) VALUES (?, ?);");
		sqlite3_bind_node_id(stmt, 1, &chan->peer->id);
		sqlite3_bind_text(stmt, 2,
				  type_to_string(tmpctx, struct wireaddr_internal, &chan->peer->addr),
				  -1, SQLITE_TRANSIENT);
		db_exec_prepared(w->db, stmt);
		chan->peer->dbid = sqlite3_last_insert_rowid(w->db->sql);
	}

	/* Insert a stub, that we update, unifies INSERT and UPDATE paths */
	stmt = db_prepare(w->db, "INSERT INTO channels ("
			  "peer_id, first_blocknum, id) VALUES (?, ?, ?);");
	sqlite3_bind_int64(stmt, 1, chan->peer->dbid);
	sqlite3_bind_int(stmt, 2, chan->first_blocknum);
	sqlite3_bind_int(stmt, 3, chan->dbid);
	db_exec_prepared(w->db, stmt);

	wallet_channel_config_insert(w, &chan->our_config);
	wallet_channel_config_insert(w, &chan->channel_info.their_config);
	wallet_shachain_init(w, &chan->their_shachain);

	/* Now save path as normal */
	wallet_channel_save(w, chan);
}

void wallet_channel_close(struct wallet *w, u64 wallet_id)
{
	/* We keep a couple of dependent tables around as well, such as the
	 * channel_configs table, since that might help us debug some issues,
	 * and it is rather limited in size. Tables that can grow quite
	 * considerably and that are of limited use after channel closure will
	 * be pruned as well. */

	sqlite3_stmt *stmt;

	/* Delete entries from `channel_htlcs` */
	stmt = db_prepare(w->db,
			  "DELETE FROM channel_htlcs "
			  "WHERE channel_id=?");
	sqlite3_bind_int64(stmt, 1, wallet_id);
	db_exec_prepared(w->db, stmt);

	/* Delete entries from `htlc_sigs` */
	stmt = db_prepare(w->db,
			  "DELETE FROM htlc_sigs "
			  "WHERE channelid=?");
	sqlite3_bind_int64(stmt, 1, wallet_id);
	db_exec_prepared(w->db, stmt);

	/* Delete entries from `htlc_sigs` */
	stmt = db_prepare(w->db,
			  "DELETE FROM channeltxs "
			  "WHERE channel_id=?");
	sqlite3_bind_int64(stmt, 1, wallet_id);
	db_exec_prepared(w->db, stmt);

	/* Delete shachains */
	stmt = db_prepare(w->db,
			  "DELETE FROM shachains "
			  "WHERE id IN ("
			  "  SELECT shachain_remote_id "
			  "  FROM channels "
			  "  WHERE channels.id=?"
			  ")");
	sqlite3_bind_int64(stmt, 1, wallet_id);
	db_exec_prepared(w->db, stmt);

	/* Set the channel to closed and disassociate with peer */
	stmt = db_prepare(w->db,
			  "UPDATE channels "
			  "SET state=?, peer_id=?"
			  "WHERE channels.id=?");
	sqlite3_bind_int64(stmt, 1, CLOSED);
	sqlite3_bind_null(stmt, 2);
	sqlite3_bind_int64(stmt, 3, wallet_id);
	db_exec_prepared(w->db, stmt);
}

void wallet_peer_delete(struct wallet *w, u64 peer_dbid)
{
	sqlite3_stmt *stmt;

	/* Must not have any channels still using this peer */
	stmt = db_select_prepare(w->db, "SELECT * FROM channels WHERE peer_id = ?;");
	sqlite3_bind_int64(stmt, 1, peer_dbid);

	if (db_select_step(w->db, stmt))
		fatal("We have channels using peer %"PRIu64, peer_dbid);

	stmt = db_prepare(w->db, "DELETE FROM peers WHERE id=?");
	sqlite3_bind_int64(stmt, 1, peer_dbid);
	db_exec_prepared(w->db, stmt);
}

void wallet_confirm_tx(struct wallet *w,
		       const struct bitcoin_txid *txid,
		       const u32 confirmation_height)
{
	sqlite3_stmt *stmt;
	assert(confirmation_height > 0);
	stmt = db_prepare(w->db,
			  "UPDATE outputs "
			  "SET confirmation_height = ? "
			  "WHERE prev_out_tx = ?");
	sqlite3_bind_int(stmt, 1, confirmation_height);
	sqlite3_bind_sha256_double(stmt, 2, &txid->shad);

	db_exec_prepared(w->db, stmt);
}

int wallet_extract_owned_outputs(struct wallet *w, const struct bitcoin_tx *tx,
				 const u32 *blockheight,
				 struct amount_sat *total)
{
	int num_utxos = 0;

	*total = AMOUNT_SAT(0);
	for (size_t output = 0; output < tx->wtx->num_outputs; output++) {
		struct utxo *utxo;
		u32 index;
		bool is_p2sh;
		const u8 *script = bitcoin_tx_output_get_script(tmpctx, tx, output);


		if (!wallet_can_spend(w, script, &index,
				      &is_p2sh))
			continue;

		utxo = tal(w, struct utxo);
		utxo->keyindex = index;
		utxo->is_p2sh = is_p2sh;
		utxo->amount = bitcoin_tx_output_get_amount(tx, output);
		utxo->status = output_state_available;
		bitcoin_txid(tx, &utxo->txid);
		utxo->outnum = output;
		utxo->close_info = NULL;

		utxo->blockheight = blockheight ? blockheight : NULL;
		utxo->spendheight = NULL;
		utxo->scriptPubkey = tal_dup_arr(utxo, u8, script, tal_bytelen(script), 0);

		log_debug(w->log, "Owning output %zu %s (%s) txid %s%s",
			  output,
			  type_to_string(tmpctx, struct amount_sat,
					 &utxo->amount),
			  is_p2sh ? "P2SH" : "SEGWIT",
			  type_to_string(tmpctx, struct bitcoin_txid,
					 &utxo->txid), blockheight ? " CONFIRMED" : "");

		if (!wallet_add_utxo(w, utxo, is_p2sh ? p2sh_wpkh : our_change)) {
			/* In case we already know the output, make
			 * sure we actually track its
			 * blockheight. This can happen when we grab
			 * the output from a transaction we created
			 * ourselves. */
			if (blockheight)
				wallet_confirm_tx(w, &utxo->txid, *blockheight);
			tal_free(utxo);
			continue;
		}
		outpointfilter_add(w->owned_outpoints, &utxo->txid, utxo->outnum);

		if (!amount_sat_add(total, *total, utxo->amount))
			fatal("Cannot add utxo output %zu/%zu %s + %s",
			      output, tx->wtx->num_outputs,
			      type_to_string(tmpctx, struct amount_sat, total),
			      type_to_string(tmpctx, struct amount_sat,
					     &utxo->amount));
		tal_free(utxo);
		num_utxos++;
	}
	return num_utxos;
}

void wallet_htlc_save_in(struct wallet *wallet,
			 const struct channel *chan, struct htlc_in *in)
{
	sqlite3_stmt *stmt;

	stmt = db_prepare(
		wallet->db,
		"INSERT INTO channel_htlcs ("
		" channel_id,"
		" channel_htlc_id, "
		" direction,"
		" msatoshi,"
		" cltv_expiry,"
		" payment_hash, "
		" payment_key,"
		" hstate,"
		" shared_secret,"
		" routing_onion,"
		" received_time) VALUES "
		"(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);");

	sqlite3_bind_int64(stmt, 1, chan->dbid);
	sqlite3_bind_int64(stmt, 2, in->key.id);
	sqlite3_bind_int(stmt, 3, DIRECTION_INCOMING);
	sqlite3_bind_amount_msat(stmt, 4, in->msat);
	sqlite3_bind_int(stmt, 5, in->cltv_expiry);
	sqlite3_bind_sha256(stmt, 6, &in->payment_hash);

	if (in->preimage)
		sqlite3_bind_preimage(stmt, 7, in->preimage);
	else
		sqlite3_bind_null(stmt, 7);
	sqlite3_bind_int(stmt, 8, in->hstate);

	if (!in->shared_secret)
		sqlite3_bind_null(stmt, 9);
	else
		sqlite3_bind_blob(stmt, 9, in->shared_secret,
				  sizeof(*in->shared_secret), SQLITE_TRANSIENT);

	sqlite3_bind_blob(stmt, 10, &in->onion_routing_packet,
			  sizeof(in->onion_routing_packet), SQLITE_TRANSIENT);

	sqlite3_bind_timeabs(stmt, 11, in->received_time);

	db_exec_prepared(wallet->db, stmt);
	in->dbid = sqlite3_last_insert_rowid(wallet->db->sql);
}

void wallet_htlc_save_out(struct wallet *wallet,
			  const struct channel *chan,
			  struct htlc_out *out)
{
	sqlite3_stmt *stmt;

	/* We absolutely need the incoming HTLC to be persisted before
	 * we can persist it's dependent */
	assert(out->in == NULL || out->in->dbid != 0);
	out->origin_htlc_id = out->in?out->in->dbid:0;

	stmt = db_prepare(
	    wallet->db,
	    "INSERT INTO channel_htlcs ("
	    " channel_id,"
	    " channel_htlc_id,"
	    " direction,"
	    " origin_htlc,"
	    " msatoshi,"
	    " cltv_expiry,"
	    " payment_hash,"
	    " payment_key,"
	    " hstate,"
	    " routing_onion) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);");

	sqlite3_bind_int64(stmt, 1, chan->dbid);
	sqlite3_bind_int64(stmt, 2, out->key.id);
	sqlite3_bind_int(stmt, 3, DIRECTION_OUTGOING);
	if (out->in)
		sqlite3_bind_int64(stmt, 4, out->in->dbid);
	else
		sqlite3_bind_null(stmt, 4);
	sqlite3_bind_amount_msat(stmt, 5, out->msat);
	sqlite3_bind_int(stmt, 6, out->cltv_expiry);
	sqlite3_bind_sha256(stmt, 7, &out->payment_hash);

	if (out->preimage)
		sqlite3_bind_preimage(stmt, 8,out->preimage);
	else
		sqlite3_bind_null(stmt, 8);
	sqlite3_bind_int(stmt, 9, out->hstate);

	sqlite3_bind_blob(stmt, 10, &out->onion_routing_packet,
			  sizeof(out->onion_routing_packet), SQLITE_TRANSIENT);

	db_exec_prepared(wallet->db, stmt);

	out->dbid = sqlite3_last_insert_rowid(wallet->db->sql);
}

void wallet_htlc_update(struct wallet *wallet, const u64 htlc_dbid,
			const enum htlc_state new_state,
			const struct preimage *payment_key,
			enum onion_type failcode, const u8 *failuremsg)
{
	sqlite3_stmt *stmt;

	/* The database ID must be set by a previous call to
	 * `wallet_htlc_save_*` */
	assert(htlc_dbid);
	stmt = db_prepare(
		wallet->db,
		"UPDATE channel_htlcs SET hstate=?, payment_key=?, malformed_onion=?, failuremsg=? WHERE id=?");

	/* FIXME: htlc_state_in_db */
	sqlite3_bind_int(stmt, 1, new_state);
	sqlite3_bind_int64(stmt, 5, htlc_dbid);

	if (payment_key)
		sqlite3_bind_preimage(stmt, 2, payment_key);
	else
		sqlite3_bind_null(stmt, 2);

	sqlite3_bind_int(stmt, 3, failcode);
	if (failuremsg)
		sqlite3_bind_blob(stmt, 4,
				  failuremsg, tal_bytelen(failuremsg),
				  SQLITE_TRANSIENT);
	else
		sqlite3_bind_null(stmt, 4);

	db_exec_prepared(wallet->db, stmt);
}

static bool wallet_stmt2htlc_in(struct channel *channel,
				sqlite3_stmt *stmt, struct htlc_in *in)
{
	bool ok = true;
	in->dbid = sqlite3_column_int64(stmt, 0);
	in->key.id = sqlite3_column_int64(stmt, 1);
	in->key.channel = channel;
	in->msat = sqlite3_column_amount_msat(stmt, 2);
	in->cltv_expiry = sqlite3_column_int(stmt, 3);
	in->hstate = sqlite3_column_int(stmt, 4);

	sqlite3_column_sha256(stmt, 5, &in->payment_hash);

	if (sqlite3_column_type(stmt, 6) != SQLITE_NULL) {
		in->preimage = tal(in, struct preimage);
		sqlite3_column_preimage(stmt, 6, in->preimage);
	} else {
		in->preimage = NULL;
	}

	assert(sqlite3_column_bytes(stmt, 7) == sizeof(in->onion_routing_packet));
	memcpy(&in->onion_routing_packet, sqlite3_column_blob(stmt, 7),
	       sizeof(in->onion_routing_packet));

	in->failuremsg = sqlite3_column_arr(in, stmt, 8, u8);
	in->failcode = sqlite3_column_int(stmt, 9);

	if (sqlite3_column_type(stmt, 11) == SQLITE_NULL) {
		in->shared_secret = NULL;
	} else {
		assert(sqlite3_column_bytes(stmt, 11) == sizeof(struct secret));
		in->shared_secret = tal(in, struct secret);
		memcpy(in->shared_secret, sqlite3_column_blob(stmt, 11),
		       sizeof(struct secret));
#ifdef COMPAT_V062
		if (memeqzero(in->shared_secret, sizeof(*in->shared_secret)))
			in->shared_secret = tal_free(in->shared_secret);
#endif
	}

	in->received_time = sqlite3_column_timeabs(stmt, 12);

	return ok;
}

static bool wallet_stmt2htlc_out(struct channel *channel,
				sqlite3_stmt *stmt, struct htlc_out *out)
{
	bool ok = true;
	out->dbid = sqlite3_column_int64(stmt, 0);
	out->key.id = sqlite3_column_int64(stmt, 1);
	out->key.channel = channel;
	out->msat = sqlite3_column_amount_msat(stmt, 2);
	out->cltv_expiry = sqlite3_column_int(stmt, 3);
	out->hstate = sqlite3_column_int(stmt, 4);
	sqlite3_column_sha256(stmt, 5, &out->payment_hash);

	if (sqlite3_column_type(stmt, 6) != SQLITE_NULL) {
		out->preimage = tal(out, struct preimage);
		sqlite3_column_preimage(stmt, 6, out->preimage);
	} else {
		out->preimage = NULL;
	}

	assert(sqlite3_column_bytes(stmt, 7) == sizeof(out->onion_routing_packet));
	memcpy(&out->onion_routing_packet, sqlite3_column_blob(stmt, 7),
	       sizeof(out->onion_routing_packet));

	out->failuremsg = sqlite3_column_arr(out, stmt, 8, u8);
	out->failcode = sqlite3_column_int(stmt, 9);

	if (sqlite3_column_type(stmt, 10) != SQLITE_NULL) {
		out->origin_htlc_id = sqlite3_column_int64(stmt, 10);
		out->am_origin = false;
	} else {
		out->origin_htlc_id = 0;
		out->am_origin = true;
	}

	/* Need to defer wiring until we can look up all incoming
	 * htlcs, will wire using origin_htlc_id */
	out->in = NULL;

	return ok;
}

static void fixup_hin(struct wallet *wallet, struct htlc_in *hin)
{
	/* We don't save the outgoing channel which failed; probably not worth
	 * it for this corner case.  So we can't set hin->failoutchannel to
	 * tell channeld what update to send, thus we turn those into a
	 * WIRE_TEMPORARY_NODE_FAILURE. */
	if (hin->failcode & UPDATE)
		hin->failcode = WIRE_TEMPORARY_NODE_FAILURE;

	/* We didn't used to save failcore, failuremsg... */
#ifdef COMPAT_V061
	/* We care about HTLCs being removed only, not those being added. */
	if (hin->hstate < SENT_REMOVE_HTLC)
		return;

	/* Successful ones are fine. */
	if (hin->preimage)
		return;

	/* Failed ones (only happens after db fixed!) OK. */
	if (hin->failcode || hin->failuremsg)
		return;

	hin->failcode = WIRE_TEMPORARY_NODE_FAILURE;

	log_broken(wallet->log, "HTLC #%"PRIu64" (%s) "
		   " for amount %s"
		   " from %s"
		   " is missing a resolution:"
		   " subsituting temporary node failure",
		   hin->key.id, htlc_state_name(hin->hstate),
		   type_to_string(tmpctx, struct amount_msat, &hin->msat),
		   type_to_string(tmpctx, struct node_id,
				  &hin->key.channel->peer->id));
#endif
}

bool wallet_htlcs_load_for_channel(struct wallet *wallet,
				   struct channel *chan,
				   struct htlc_in_map *htlcs_in,
				   struct htlc_out_map *htlcs_out)
{
	bool ok = true;
	int incount = 0, outcount = 0;

	log_debug(wallet->log, "Loading HTLCs for channel %"PRIu64, chan->dbid);
	sqlite3_stmt *stmt = db_select_prepare(wallet->db, "SELECT"
							   "  id"
							   ", channel_htlc_id"
							   ", msatoshi"
							   ", cltv_expiry"
							   ", hstate"
							   ", payment_hash"
							   ", payment_key"
							   ", routing_onion"
							   ", failuremsg"
							   ", malformed_onion"
							   ", origin_htlc"
							   ", shared_secret"
							   ", received_time"
							   " FROM channel_htlcs"
							   " WHERE direction= ?"
							   " AND channel_id= ?"
							   " AND hstate != ?");
	sqlite3_bind_int(stmt, 1, DIRECTION_INCOMING);
	sqlite3_bind_int64(stmt, 2, chan->dbid);
	sqlite3_bind_int(stmt, 3, SENT_REMOVE_ACK_REVOCATION);

	while (db_select_step(wallet->db, stmt)) {
		struct htlc_in *in = tal(chan, struct htlc_in);
		ok &= wallet_stmt2htlc_in(chan, stmt, in);
		connect_htlc_in(htlcs_in, in);
		fixup_hin(wallet, in);
		ok &= htlc_in_check(in, NULL) != NULL;
		incount++;
	}

	stmt = db_select_prepare(wallet->db, "SELECT"
					     "  id"
					     ", channel_htlc_id"
					     ", msatoshi"
					     ", cltv_expiry"
					     ", hstate"
					     ", payment_hash"
					     ", payment_key"
					     ", routing_onion"
					     ", failuremsg"
					     ", malformed_onion"
					     ", origin_htlc"
					     ", shared_secret"
					     ", received_time"
					     " FROM channel_htlcs"
					     " WHERE direction = ?"
					     " AND channel_id = ?"
					     " AND hstate != ?");
	sqlite3_bind_int(stmt, 1, DIRECTION_OUTGOING);
	sqlite3_bind_int64(stmt, 2, chan->dbid);
	sqlite3_bind_int(stmt, 3, RCVD_REMOVE_ACK_REVOCATION);

	while (db_select_step(wallet->db, stmt)) {
		struct htlc_out *out = tal(chan, struct htlc_out);
		ok &= wallet_stmt2htlc_out(chan, stmt, out);
		connect_htlc_out(htlcs_out, out);
		/* Cannot htlc_out_check because we haven't wired the
		 * dependencies in yet */
		outcount++;
	}

	log_debug(wallet->log, "Restored %d incoming and %d outgoing HTLCS", incount, outcount);

	return ok;
}

bool wallet_invoice_create(struct wallet *wallet,
			   struct invoice *pinvoice,
			   const struct amount_msat *msat TAKES,
			   const struct json_escape *label TAKES,
			   u64 expiry,
			   const char *b11enc,
			   const char *description,
			   const struct preimage *r,
			   const struct sha256 *rhash)
{
	return invoices_create(wallet->invoices, pinvoice, msat, label, expiry, b11enc, description, r, rhash);
}
bool wallet_invoice_find_by_label(struct wallet *wallet,
				  struct invoice *pinvoice,
				  const struct json_escape *label)
{
	return invoices_find_by_label(wallet->invoices, pinvoice, label);
}
bool wallet_invoice_find_by_rhash(struct wallet *wallet,
				  struct invoice *pinvoice,
				  const struct sha256 *rhash)
{
	return invoices_find_by_rhash(wallet->invoices, pinvoice, rhash);
}
bool wallet_invoice_find_unpaid(struct wallet *wallet,
				struct invoice *pinvoice,
				const struct sha256 *rhash)
{
	return invoices_find_unpaid(wallet->invoices, pinvoice, rhash);
}
bool wallet_invoice_delete(struct wallet *wallet,
			   struct invoice invoice)
{
	return invoices_delete(wallet->invoices, invoice);
}
void wallet_invoice_delete_expired(struct wallet *wallet, u64 e)
{
	invoices_delete_expired(wallet->invoices, e);
}
bool wallet_invoice_iterate(struct wallet *wallet,
			    struct invoice_iterator *it)
{
	return invoices_iterate(wallet->invoices, it);
}
const struct invoice_details *
wallet_invoice_iterator_deref(const tal_t *ctx, struct wallet *wallet,
			      const struct invoice_iterator *it)
{
	return invoices_iterator_deref(ctx, wallet->invoices, it);
}
void wallet_invoice_resolve(struct wallet *wallet,
			    struct invoice invoice,
			    struct amount_msat msatoshi_received)
{
	invoices_resolve(wallet->invoices, invoice, msatoshi_received);
}
void wallet_invoice_waitany(const tal_t *ctx,
			    struct wallet *wallet,
			    u64 lastpay_index,
			    void (*cb)(const struct invoice *, void*),
			    void *cbarg)
{
	invoices_waitany(ctx, wallet->invoices, lastpay_index, cb, cbarg);
}
void wallet_invoice_waitone(const tal_t *ctx,
			    struct wallet *wallet,
			    struct invoice invoice,
			    void (*cb)(const struct invoice *, void*),
			    void *cbarg)
{
	invoices_waitone(ctx, wallet->invoices, invoice, cb, cbarg);
}

const struct invoice_details *wallet_invoice_details(const tal_t *ctx,
						     struct wallet *wallet,
						     struct invoice invoice)
{
	return invoices_get_details(ctx, wallet->invoices, invoice);
}

struct htlc_stub *wallet_htlc_stubs(const tal_t *ctx, struct wallet *wallet,
				    struct channel *chan)
{
	struct htlc_stub *stubs;
	struct sha256 payment_hash;
	sqlite3_stmt *stmt = db_select_prepare(wallet->db,
		"SELECT channel_id, direction, cltv_expiry, channel_htlc_id, payment_hash "
		"FROM channel_htlcs WHERE channel_id = ?;");

	sqlite3_bind_int64(stmt, 1, chan->dbid);

	stubs = tal_arr(ctx, struct htlc_stub, 0);

	while (db_select_step(wallet->db, stmt)) {
		struct htlc_stub stub;

		assert(sqlite3_column_int64(stmt, 0) == chan->dbid);

		/* FIXME: merge these two enums */
		stub.owner = sqlite3_column_int(stmt, 1)==DIRECTION_INCOMING?REMOTE:LOCAL;
		stub.cltv_expiry = sqlite3_column_int(stmt, 2);
		stub.id = sqlite3_column_int(stmt, 3);

		sqlite3_column_sha256(stmt, 4, &payment_hash);
		ripemd160(&stub.ripemd, payment_hash.u.u8, sizeof(payment_hash.u));
		tal_arr_expand(&stubs, stub);
	}
	return stubs;
}

void wallet_local_htlc_out_delete(struct wallet *wallet,
				  struct channel *chan,
				  const struct sha256 *payment_hash)
{
	sqlite3_stmt *stmt;

	stmt = db_prepare(wallet->db,
			  "DELETE FROM channel_htlcs"
			  " WHERE direction = ?"
			  " AND origin_htlc = ?"
			  " AND payment_hash = ?");
	sqlite3_bind_int(stmt, 1, DIRECTION_OUTGOING);
	sqlite3_bind_int(stmt, 2, 0);
	sqlite3_bind_sha256(stmt, 3, payment_hash);

	db_exec_prepared(wallet->db, stmt);
}

static struct wallet_payment *
find_unstored_payment(struct wallet *wallet, const struct sha256 *payment_hash)
{
	struct wallet_payment *i;

	list_for_each(&wallet->unstored_payments, i, list) {
		if (sha256_eq(payment_hash, &i->payment_hash))
			return i;
	}
	return NULL;
}

static void destroy_unstored_payment(struct wallet_payment *payment)
{
	list_del(&payment->list);
}

void wallet_payment_setup(struct wallet *wallet, struct wallet_payment *payment)
{
	assert(!find_unstored_payment(wallet, &payment->payment_hash));

	list_add_tail(&wallet->unstored_payments, &payment->list);
	tal_add_destructor(payment, destroy_unstored_payment);
}

void wallet_payment_store(struct wallet *wallet,
			  const struct sha256 *payment_hash)
{
	sqlite3_stmt *stmt;
	struct wallet_payment *payment;

	payment = find_unstored_payment(wallet, payment_hash);
	if (!payment) {
		/* Already stored on-disk */
#if DEVELOPER
		/* Double-check that it is indeed stored to disk
		 * (catch bug, where we call this on a payment_hash
		 * we never paid to) */
		bool res;
		stmt = db_select_prepare(wallet->db,
					 "SELECT status FROM payments"
					 " WHERE payment_hash=?;");
		sqlite3_bind_sha256(stmt, 1, payment_hash);
		res = db_select_step(wallet->db, stmt);
		assert(res);
		db_stmt_done(stmt);
#endif
		return;
	}

        /* Don't attempt to add the same payment twice */
	assert(!payment->id);

	stmt = db_prepare(
		wallet->db,
		"INSERT INTO payments ("
		"  status,"
		"  payment_hash,"
		"  destination,"
		"  msatoshi,"
		"  timestamp,"
		"  path_secrets,"
		"  route_nodes,"
		"  route_channels,"
		"  msatoshi_sent,"
		"  description,"
		"  bolt11"
		") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);");

	sqlite3_bind_int(stmt, 1, payment->status);
	sqlite3_bind_sha256(stmt, 2, &payment->payment_hash);
	sqlite3_bind_node_id(stmt, 3, &payment->destination);
	sqlite3_bind_amount_msat(stmt, 4, payment->msatoshi);
	sqlite3_bind_int(stmt, 5, payment->timestamp);
	sqlite3_bind_blob(stmt, 6, payment->path_secrets,
				   tal_bytelen(payment->path_secrets),
				   SQLITE_TRANSIENT);
	sqlite3_bind_node_id_array(stmt, 7, payment->route_nodes);
	sqlite3_bind_short_channel_id_array(stmt, 8,
					    payment->route_channels);
	sqlite3_bind_amount_msat(stmt, 9, payment->msatoshi_sent);

	if (payment->label != NULL)
		sqlite3_bind_text(stmt, 10, payment->label,
				  strlen(payment->label),
				  SQLITE_TRANSIENT);
	else
		sqlite3_bind_null(stmt, 10);

	if (payment->bolt11 != NULL)
		sqlite3_bind_text(stmt, 11, payment->bolt11,
				  strlen(payment->bolt11),
				  SQLITE_TRANSIENT);
	else
		sqlite3_bind_null(stmt, 11);

	db_exec_prepared(wallet->db, stmt);

	tal_free(payment);
}

void wallet_payment_delete(struct wallet *wallet,
			   const struct sha256 *payment_hash)
{
	sqlite3_stmt *stmt;
	struct wallet_payment *payment;

	payment = find_unstored_payment(wallet, payment_hash);
	if (payment) {
		tal_free(payment);
		return;
	}

	stmt = db_prepare(
		wallet->db,
		"DELETE FROM payments WHERE payment_hash = ?");

	sqlite3_bind_sha256(stmt, 1, payment_hash);

	db_exec_prepared(wallet->db, stmt);
}

static struct wallet_payment *wallet_stmt2payment(const tal_t *ctx,
						  sqlite3_stmt *stmt)
{
	struct wallet_payment *payment = tal(ctx, struct wallet_payment);
	payment->id = sqlite3_column_int64(stmt, 0);
	payment->status = sqlite3_column_int(stmt, 1);

	sqlite3_column_node_id(stmt, 2, &payment->destination);
	payment->msatoshi = sqlite3_column_amount_msat(stmt, 3);
	sqlite3_column_sha256(stmt, 4, &payment->payment_hash);

	payment->timestamp = sqlite3_column_int(stmt, 5);
	if (sqlite3_column_type(stmt, 6) != SQLITE_NULL) {
		payment->payment_preimage = tal(payment, struct preimage);
		sqlite3_column_preimage(stmt, 6, payment->payment_preimage);
	} else
		payment->payment_preimage = NULL;

	/* Can be NULL for old db! */
	payment->path_secrets = sqlite3_column_secrets(payment, stmt, 7);

	payment->route_nodes = sqlite3_column_node_id_array(payment, stmt, 8);
	payment->route_channels
		= sqlite3_column_short_channel_id_array(payment, stmt, 9);

	payment->msatoshi_sent = sqlite3_column_amount_msat(stmt, 10);

	if (sqlite3_column_type(stmt, 11) != SQLITE_NULL)
		payment->label = tal_strdup(
		    payment, (const char *)sqlite3_column_text(stmt, 11));
	else
		payment->label = NULL;

	if (sqlite3_column_type(stmt, 12) != SQLITE_NULL)
		payment->bolt11 = tal_strdup(payment,
					     (const char *)sqlite3_column_text(stmt, 12));
	else
		payment->bolt11 = NULL;

	return payment;
}

struct wallet_payment *
wallet_payment_by_hash(const tal_t *ctx, struct wallet *wallet,
		       const struct sha256 *payment_hash)
{
	sqlite3_stmt *stmt;
	struct wallet_payment *payment;

	/* Present the illusion that it's in the db... */
	payment = find_unstored_payment(wallet, payment_hash);
	if (payment)
		return payment;

	stmt = db_select_prepare(wallet->db,
				 "SELECT"
				 "  id"
				 ", status"
				 ", destination"
				 ", msatoshi"
				 ", payment_hash"
				 ", timestamp"
				 ", payment_preimage"
				 ", path_secrets"
				 ", route_nodes"
				 ", route_channels"
				 ", msatoshi_sent"
				 ", description"
				 ", bolt11"
				 " FROM payments"
				 " WHERE payment_hash = ?");

	sqlite3_bind_sha256(stmt, 1, payment_hash);
	if (db_select_step(wallet->db, stmt)) {
		payment = wallet_stmt2payment(ctx, stmt);
		db_stmt_done(stmt);
	}
	return payment;
}

void wallet_payment_set_status(struct wallet *wallet,
			       const struct sha256 *payment_hash,
			       const enum wallet_payment_status newstatus,
			       const struct preimage *preimage)
{
	sqlite3_stmt *stmt;
	struct wallet_payment *payment;

	/* We can only fail an unstored payment! */
	payment = find_unstored_payment(wallet, payment_hash);
	if (payment) {
		assert(newstatus == PAYMENT_FAILED);
		tal_free(payment);
		return;
	}

	stmt = db_prepare(wallet->db,
			  "UPDATE payments SET status=? "
			  "WHERE payment_hash=?");

	sqlite3_bind_int(stmt, 1, wallet_payment_status_in_db(newstatus));
	sqlite3_bind_sha256(stmt, 2, payment_hash);
	db_exec_prepared(wallet->db, stmt);

	if (preimage) {
		stmt = db_prepare(wallet->db,
				  "UPDATE payments SET payment_preimage=? "
				  "WHERE payment_hash=?");

		sqlite3_bind_preimage(stmt, 1, preimage);
		sqlite3_bind_sha256(stmt, 2, payment_hash);
		db_exec_prepared(wallet->db, stmt);
	}
	if (newstatus != PAYMENT_PENDING) {
		stmt = db_prepare(wallet->db,
				  "UPDATE payments"
				  "   SET path_secrets = NULL"
				  "     , route_nodes = NULL"
				  "     , route_channels = NULL"
				  " WHERE payment_hash = ?;");
		sqlite3_bind_sha256(stmt, 1, payment_hash);
		db_exec_prepared(wallet->db, stmt);
	}
}

void wallet_payment_get_failinfo(const tal_t *ctx,
				 struct wallet *wallet,
				 const struct sha256 *payment_hash,
				 /* outputs */
				 u8 **failonionreply,
				 bool *faildestperm,
				 int *failindex,
				 enum onion_type *failcode,
				 struct node_id **failnode,
				 struct short_channel_id **failchannel,
				 u8 **failupdate,
				 char **faildetail,
				 int *faildirection)
{
	sqlite3_stmt *stmt;
	bool resb;
	size_t len;

	stmt = db_select_prepare(wallet->db,
				 "SELECT failonionreply, faildestperm"
				 ", failindex, failcode"
				 ", failnode, failchannel"
				 ", failupdate, faildetail, faildirection"
				 "  FROM payments"
				 " WHERE payment_hash=?;");
	sqlite3_bind_sha256(stmt, 1, payment_hash);
	resb = db_select_step(wallet->db, stmt);
	assert(resb);
	if (sqlite3_column_type(stmt, 0) == SQLITE_NULL)
		*failonionreply = NULL;
	else {
		len = sqlite3_column_bytes(stmt, 0);
		*failonionreply = tal_arr(ctx, u8, len);
		memcpy(*failonionreply, sqlite3_column_blob(stmt, 0), len);
	}
	*faildestperm = sqlite3_column_int(stmt, 1) != 0;
	*failindex = sqlite3_column_int(stmt, 2);
	*failcode = (enum onion_type) sqlite3_column_int(stmt, 3);
	if (sqlite3_column_type(stmt, 4) == SQLITE_NULL)
		*failnode = NULL;
	else {
		*failnode = tal(ctx, struct node_id);
		resb = sqlite3_column_node_id(stmt, 4, *failnode);
		assert(resb);
	}
	if (sqlite3_column_type(stmt, 5) == SQLITE_NULL)
		*failchannel = NULL;
	else {
		*failchannel = tal(ctx, struct short_channel_id);
		resb = sqlite3_column_short_channel_id(stmt, 5, *failchannel);
		assert(resb);

		/* For pre-0.6.2 dbs, direction will be 0 */
		*faildirection = sqlite3_column_int(stmt, 8);
	}
	if (sqlite3_column_type(stmt, 6) == SQLITE_NULL)
		*failupdate = NULL;
	else {
		len = sqlite3_column_bytes(stmt, 6);
		*failupdate = tal_arr(ctx, u8, len);
		memcpy(*failupdate, sqlite3_column_blob(stmt, 6), len);
	}
	*faildetail = tal_strndup(ctx, sqlite3_column_blob(stmt, 7),
				  sqlite3_column_bytes(stmt, 7));

	db_stmt_done(stmt);
}

void wallet_payment_set_failinfo(struct wallet *wallet,
				 const struct sha256 *payment_hash,
				 const u8 *failonionreply /*tal_arr*/,
				 bool faildestperm,
				 int failindex,
				 enum onion_type failcode,
				 const struct node_id *failnode,
				 const struct short_channel_id *failchannel,
				 const u8 *failupdate /*tal_arr*/,
				 const char *faildetail,
				 int faildirection)
{
	sqlite3_stmt *stmt;

	stmt = db_prepare(wallet->db,
			  "UPDATE payments"
			  "   SET failonionreply=?"
			  "     , faildestperm=?"
			  "     , failindex=?"
			  "     , failcode=?"
			  "     , failnode=?"
			  "     , failchannel=?"
			  "     , failupdate=?"
			  "     , faildetail=?"
			  "     , faildirection=?"
			  " WHERE payment_hash=?;");
	if (failonionreply)
		sqlite3_bind_blob(stmt, 1,
				  failonionreply, tal_count(failonionreply),
				  SQLITE_TRANSIENT);
	else
		sqlite3_bind_null(stmt, 1);
	sqlite3_bind_int(stmt, 2, faildestperm ? 1 : 0);
	sqlite3_bind_int(stmt, 3, failindex);
	sqlite3_bind_int(stmt, 4, (int) failcode);
	if (failnode)
		sqlite3_bind_node_id(stmt, 5, failnode);
	else
		sqlite3_bind_null(stmt, 5);
	if (failchannel) {
		/* sqlite3_bind_short_channel_id requires the input
		 * channel to be tal-allocated... */
		struct short_channel_id *scid = tal(tmpctx, struct short_channel_id);
		*scid = *failchannel;
		sqlite3_bind_short_channel_id(stmt, 6, scid);
		sqlite3_bind_int(stmt, 9, faildirection);
	} else {
		sqlite3_bind_null(stmt, 6);
		sqlite3_bind_null(stmt, 9);
	}
	if (failupdate)
		sqlite3_bind_blob(stmt, 7,
				  failupdate, tal_count(failupdate),
				  SQLITE_TRANSIENT);
	else
		sqlite3_bind_null(stmt, 7);
	sqlite3_bind_blob(stmt, 8,
			  faildetail, strlen(faildetail),
			  SQLITE_TRANSIENT);

	sqlite3_bind_sha256(stmt, 10, payment_hash);

	db_exec_prepared(wallet->db, stmt);
}

const struct wallet_payment **
wallet_payment_list(const tal_t *ctx,
		    struct wallet *wallet,
		    const struct sha256 *payment_hash)
{
	const struct wallet_payment **payments;
	sqlite3_stmt *stmt;
	struct wallet_payment *p;
	size_t i;

	payments = tal_arr(ctx, const struct wallet_payment *, 0);
	if (payment_hash) {
		stmt = db_select_prepare(wallet->db,
					 "SELECT"
					 "  id"
					 ", status"
					 ", destination"
					 ", msatoshi"
					 ", payment_hash"
					 ", timestamp"
					 ", payment_preimage"
					 ", path_secrets"
					 ", route_nodes"
					 ", route_channels"
					 ", msatoshi_sent"
					 ", description"
					 ", bolt11"
					 " FROM payments"
					 " WHERE payment_hash = ?;");
		sqlite3_bind_sha256(stmt, 1, payment_hash);
	} else {
		stmt = db_select_prepare(wallet->db,
					 "SELECT"
					 "  id"
					 ", status"
					 ", destination"
					 ", msatoshi"
					 ", payment_hash"
					 ", timestamp"
					 ", payment_preimage"
					 ", path_secrets"
					 ", route_nodes"
					 ", route_channels"
					 ", msatoshi_sent"
					 ", description"
					 ", bolt11"
					 " FROM payments;");
	}

	for (i = 0; db_select_step(wallet->db, stmt); i++) {
		tal_resize(&payments, i+1);
		payments[i] = wallet_stmt2payment(payments, stmt);
	}

	/* Now attach payments not yet in db. */
	list_for_each(&wallet->unstored_payments, p, list) {
		if (payment_hash && !sha256_eq(&p->payment_hash, payment_hash))
			continue;
		tal_resize(&payments, i+1);
		payments[i++] = p;
	}

	return payments;
}

void wallet_htlc_sigs_save(struct wallet *w, u64 channel_id,
			   secp256k1_ecdsa_signature *htlc_sigs)
{
	/* Clear any existing HTLC sigs for this channel */
	sqlite3_stmt *stmt =
	    db_prepare(w->db, "DELETE FROM htlc_sigs WHERE channelid = ?");
	sqlite3_bind_int64(stmt, 1, channel_id);
	db_exec_prepared(w->db, stmt);

	/* Now insert the new ones */
	for (size_t i=0; i<tal_count(htlc_sigs); i++) {
		stmt = db_prepare(w->db, "INSERT INTO htlc_sigs (channelid, signature) VALUES (?, ?)");
		sqlite3_bind_int64(stmt, 1, channel_id);
		sqlite3_bind_signature(stmt, 2, &htlc_sigs[i]);
		db_exec_prepared(w->db, stmt);
	}
}

bool wallet_network_check(struct wallet *w,
			  const struct chainparams *chainparams)
{
	sqlite3_stmt *stmt = db_select(w->db,
				      "SELECT val FROM vars WHERE name='genesis_hash'");
	struct bitcoin_blkid chainhash;

	if (db_select_step(w->db, stmt)) {
		sqlite3_column_sha256_double(stmt, 0, &chainhash.shad);
		db_stmt_done(stmt);
		if (!bitcoin_blkid_eq(&chainhash,
				      &chainparams->genesis_blockhash)) {
			log_broken(w->log, "Wallet blockchain hash does not "
					   "match network blockchain hash: %s "
					   "!= %s. "
					   "Are you on the right network? "
					   "(--network={one of %s})",
				   type_to_string(w, struct bitcoin_blkid,
						  &chainhash),
				   type_to_string(w, struct bitcoin_blkid,
						  &chainparams->genesis_blockhash),
				   chainparams_get_network_names(tmpctx));
			return false;
		}
	} else {
		/* Still a pristine wallet, claim it for the chain
		 * that we are running */
		stmt = db_prepare(w->db, "INSERT INTO vars (name, val) VALUES ('genesis_hash', ?);");
		sqlite3_bind_sha256_double(stmt, 1, &chainparams->genesis_blockhash.shad);
		db_exec_prepared(w->db, stmt);
	}
	return true;
}

/**
 * wallet_utxoset_prune -- Remove spent UTXO entries that are old
 */
static void wallet_utxoset_prune(struct wallet *w, const u32 blockheight)
{
	sqlite3_stmt *stmt;
	struct bitcoin_txid txid;

	stmt = db_select_prepare(w->db, "SELECT txid, outnum FROM utxoset WHERE spendheight < ?");
	sqlite3_bind_int(stmt, 1, blockheight - UTXO_PRUNE_DEPTH);

	while (db_select_step(w->db, stmt)) {
		sqlite3_column_sha256_double(stmt, 0, &txid.shad);
		outpointfilter_remove(w->utxoset_outpoints, &txid, sqlite3_column_int(stmt, 1));
	}

	stmt = db_prepare(w->db, "DELETE FROM utxoset WHERE spendheight < ?");
	sqlite3_bind_int(stmt, 1, blockheight - UTXO_PRUNE_DEPTH);
	db_exec_prepared(w->db, stmt);
}

void wallet_block_add(struct wallet *w, struct block *b)
{
	sqlite3_stmt *stmt = db_prepare(w->db,
					"INSERT INTO blocks "
					"(height, hash, prev_hash) "
					"VALUES (?, ?, ?);");
	sqlite3_bind_int(stmt, 1, b->height);
	sqlite3_bind_sha256_double(stmt, 2, &b->blkid.shad);
	if (b->prev) {
		sqlite3_bind_sha256_double(stmt, 3, &b->prev->blkid.shad);
	}else {
		sqlite3_bind_null(stmt, 3);
	}
	db_exec_prepared(w->db, stmt);

	/* Now cleanup UTXOs that we don't care about anymore */
	wallet_utxoset_prune(w, b->height);
}

void wallet_block_remove(struct wallet *w, struct block *b)
{
	sqlite3_stmt *stmt = db_prepare(w->db,
					"DELETE FROM blocks WHERE hash = ?");
	sqlite3_bind_sha256_double(stmt, 1, &b->blkid.shad);
	db_exec_prepared(w->db, stmt);

	/* Make sure that all descendants of the block are also deleted */
	stmt = db_select_prepare(w->db, "SELECT * FROM blocks WHERE height >= ?;");
	sqlite3_bind_int(stmt, 1, b->height);
	assert(!db_select_step(w->db, stmt));
}

void wallet_blocks_rollback(struct wallet *w, u32 height)
{
	sqlite3_stmt *stmt = db_prepare(w->db, "DELETE FROM blocks "
					"WHERE height > ?");
	sqlite3_bind_int(stmt, 1, height);
	db_exec_prepared(w->db, stmt);
}

const struct short_channel_id *
wallet_outpoint_spend(struct wallet *w, const tal_t *ctx, const u32 blockheight,
		      const struct bitcoin_txid *txid, const u32 outnum)
{
	struct short_channel_id *scid;
	sqlite3_stmt *stmt;
	bool res;
	if (outpointfilter_matches(w->owned_outpoints, txid, outnum)) {
		stmt = db_prepare(w->db,
				  "UPDATE outputs "
				  "SET spend_height = ? "
				  "WHERE prev_out_tx = ?"
				  " AND prev_out_index = ?");

		sqlite3_bind_int(stmt, 1, blockheight);
		sqlite3_bind_sha256_double(stmt, 2, &txid->shad);
		sqlite3_bind_int(stmt, 3, outnum);

		db_exec_prepared(w->db, stmt);
	}

	if (outpointfilter_matches(w->utxoset_outpoints, txid, outnum)) {
		stmt = db_prepare(w->db,
				  "UPDATE utxoset "
				  "SET spendheight = ? "
				  "WHERE txid = ?"
				  " AND outnum = ?");

		sqlite3_bind_int(stmt, 1, blockheight);
		sqlite3_bind_sha256_double(stmt, 2, &txid->shad);
		sqlite3_bind_int(stmt, 3, outnum);

		db_exec_prepared(w->db, stmt);

		if (sqlite3_changes(w->db->sql) == 0) {
			return NULL;
		}

		/* Now look for the outpoint's short_channel_id */
		stmt = db_select_prepare(w->db,
					 "SELECT "
					 "blockheight, txindex "
					 "FROM utxoset "
					 "WHERE txid = ? AND outnum = ?");
		sqlite3_bind_sha256_double(stmt, 1, &txid->shad);
		sqlite3_bind_int(stmt, 2, outnum);

		res = db_select_step(w->db, stmt);
		assert(res);

		scid = tal(ctx, struct short_channel_id);
		if (!mk_short_channel_id(scid, sqlite3_column_int(stmt, 0),
					 sqlite3_column_int(stmt, 1), outnum))
			fatal("wallet_outpoint_spend: invalid scid %u:%u:%u",
			      sqlite3_column_int(stmt, 0),
			      sqlite3_column_int(stmt, 1), outnum);
		db_stmt_done(stmt);
		return scid;
	}
	return NULL;
}

void wallet_utxoset_add(struct wallet *w, const struct bitcoin_tx *tx,
			const u32 outnum, const u32 blockheight,
			const u32 txindex, const u8 *scriptpubkey,
			struct amount_sat sat)
{
	sqlite3_stmt *stmt;
	struct bitcoin_txid txid;
	bitcoin_txid(tx, &txid);

	stmt = db_prepare(w->db, "INSERT INTO utxoset ("
			  " txid,"
			  " outnum,"
			  " blockheight,"
			  " spendheight,"
			  " txindex,"
			  " scriptpubkey,"
			  " satoshis"
			  ") VALUES(?, ?, ?, ?, ?, ?, ?);");
	sqlite3_bind_sha256_double(stmt, 1, &txid.shad);
	sqlite3_bind_int(stmt, 2, outnum);
	sqlite3_bind_int(stmt, 3, blockheight);
	sqlite3_bind_null(stmt, 4);
	sqlite3_bind_int(stmt, 5, txindex);
	sqlite3_bind_blob(stmt, 6, scriptpubkey, tal_count(scriptpubkey), SQLITE_TRANSIENT);
	sqlite3_bind_amount_sat(stmt, 7, sat);
	db_exec_prepared(w->db, stmt);

	outpointfilter_add(w->utxoset_outpoints, &txid, outnum);
}

void wallet_filteredblock_add(struct wallet *w, const struct filteredblock *fb)
{
	if (wallet_have_block(w, fb->height))
		return;
	sqlite3_stmt *stmt = db_prepare(w->db, "INSERT OR IGNORE INTO blocks "
					       "(height, hash, prev_hash) "
					       "VALUES (?, ?, ?);");
	sqlite3_bind_int(stmt, 1, fb->height);
	sqlite3_bind_sha256_double(stmt, 2, &fb->id.shad);
	sqlite3_bind_sha256_double(stmt, 3, &fb->prev_hash.shad);
	db_exec_prepared(w->db, stmt);

	for (size_t i = 0; i < tal_count(fb->outpoints); i++) {
		struct filteredblock_outpoint *o = fb->outpoints[i];
		stmt = db_prepare(w->db, "INSERT INTO utxoset ("
					 " txid,"
					 " outnum,"
					 " blockheight,"
					 " spendheight,"
					 " txindex,"
					 " scriptpubkey,"
					 " satoshis"
					 ") VALUES(?, ?, ?, ?, ?, ?, ?);");
		sqlite3_bind_sha256_double(stmt, 1, &o->txid.shad);
		sqlite3_bind_int(stmt, 2, o->outnum);
		sqlite3_bind_int(stmt, 3, fb->height);
		sqlite3_bind_null(stmt, 4);
		sqlite3_bind_int(stmt, 5, o->txindex);
		sqlite3_bind_blob(stmt, 6, o->scriptPubKey,
				  tal_count(o->scriptPubKey), SQLITE_TRANSIENT);
		sqlite3_bind_amount_sat(stmt, 7, o->amount);
		db_exec_prepared(w->db, stmt);

		outpointfilter_add(w->utxoset_outpoints, &o->txid, o->outnum);
	}
}

bool wallet_have_block(struct wallet *w, u32 blockheight)
{
	bool result;
	sqlite3_stmt *stmt = db_select_prepare(w->db, "SELECT height FROM blocks WHERE height = ?");
	sqlite3_bind_int(stmt, 1, blockheight);
	result = sqlite3_step(stmt) == SQLITE_ROW;
	db_stmt_done(stmt);
	return result;
}

struct outpoint *wallet_outpoint_for_scid(struct wallet *w, tal_t *ctx,
					  const struct short_channel_id *scid)
{
	sqlite3_stmt *stmt;
	struct outpoint *op;
	stmt = db_select_prepare(w->db, "SELECT"
					" txid,"
					" spendheight,"
					" scriptpubkey,"
					" satoshis "
					"FROM utxoset "
					"WHERE blockheight = ?"
					" AND txindex = ?"
					" AND outnum = ?"
					" AND spendheight IS NULL");
	sqlite3_bind_int(stmt, 1, short_channel_id_blocknum(scid));
	sqlite3_bind_int(stmt, 2, short_channel_id_txnum(scid));
	sqlite3_bind_int(stmt, 3, short_channel_id_outnum(scid));


	if (!db_select_step(w->db, stmt))
		return NULL;

	op = tal(ctx, struct outpoint);
	op->blockheight = short_channel_id_blocknum(scid);
	op->txindex = short_channel_id_txnum(scid);
	op->outnum = short_channel_id_outnum(scid);
	sqlite3_column_sha256_double(stmt, 0, &op->txid.shad);
	op->spendheight = sqlite3_column_int(stmt, 1);
	op->scriptpubkey = tal_arr(op, u8, sqlite3_column_bytes(stmt, 2));
	memcpy(op->scriptpubkey, sqlite3_column_blob(stmt, 2), sqlite3_column_bytes(stmt, 2));
	op->sat = sqlite3_column_amount_sat(stmt, 3);
	db_stmt_done(stmt);

	return op;
}

void wallet_transaction_add(struct wallet *w, const struct bitcoin_tx *tx,
			    const u32 blockheight, const u32 txindex)
{
	struct bitcoin_txid txid;
	sqlite3_stmt *stmt = db_select_prepare(w->db, "SELECT blockheight FROM transactions WHERE id=?");

	bitcoin_txid(tx, &txid);
	sqlite3_bind_sha256(stmt, 1, &txid.shad.sha);
	if (!db_select_step(w->db, stmt)) {
		/* This transaction is still unknown, insert */
		stmt = db_prepare(w->db,
				  "INSERT INTO transactions ("
				  "  id"
				  ", blockheight"
				  ", txindex"
				  ", rawtx) VALUES (?, ?, ?, ?);");
		sqlite3_bind_sha256(stmt, 1, &txid.shad.sha);
		if (blockheight) {
			sqlite3_bind_int(stmt, 2, blockheight);
			sqlite3_bind_int(stmt, 3, txindex);
		} else {
			sqlite3_bind_null(stmt, 2);
			sqlite3_bind_null(stmt, 3);
		}
		sqlite3_bind_tx(stmt, 4, tx);
		db_exec_prepared(w->db, stmt);
	} else {
		db_stmt_done(stmt);

		if (blockheight) {
			/* We know about the transaction, update */
			stmt = db_prepare(w->db,
					  "UPDATE transactions "
					  "SET blockheight = ?, txindex = ? "
					  "WHERE id = ?");
			sqlite3_bind_int(stmt, 1, blockheight);
			sqlite3_bind_int(stmt, 2, txindex);
			sqlite3_bind_sha256(stmt, 3, &txid.shad.sha);
			db_exec_prepared(w->db, stmt);
		}
	}
}

void wallet_transaction_annotate(struct wallet *w,
				 const struct bitcoin_txid *txid, enum wallet_tx_type type,
				 u64 channel_id)
{
	sqlite3_stmt *stmt = db_select_prepare(w->db, "SELECT type, channel_id FROM transactions WHERE id=?");
	sqlite3_bind_sha256(stmt, 1, &txid->shad.sha);
	if (!db_select_step(w->db, stmt))
		fatal("Attempting to annotate a transaction we don't have: %s",
		      type_to_string(tmpctx, struct bitcoin_txid, txid));
	type |= sqlite3_column_int(stmt, 0);
	if (channel_id == 0)
		channel_id = sqlite3_column_int64(stmt, 1);

	db_stmt_done(stmt);

	stmt = db_prepare(w->db, "UPDATE transactions "
				 "SET type = ?"
				 ", channel_id = ? "
				 "WHERE id = ?");

	sqlite3_bind_int(stmt, 1, type);
	if (channel_id)
		sqlite3_bind_int(stmt, 2, channel_id);
	else
		sqlite3_bind_null(stmt, 2);
	sqlite3_bind_sha256(stmt, 3, &txid->shad.sha);
	db_exec_prepared(w->db, stmt);
}

u32 wallet_transaction_height(struct wallet *w, const struct bitcoin_txid *txid)
{
	u32 blockheight;
	sqlite3_stmt *stmt = db_select_prepare(
		w->db, "SELECT blockheight FROM transactions WHERE id=?");
	sqlite3_bind_sha256(stmt, 1, &txid->shad.sha);

	if (!db_select_step(w->db, stmt))
		return 0;

	blockheight = sqlite3_column_int(stmt, 0);
	db_stmt_done(stmt);
	return blockheight;
}

struct txlocator *wallet_transaction_locate(const tal_t *ctx, struct wallet *w,
					    const struct bitcoin_txid *txid)
{
	struct txlocator *loc;
	sqlite3_stmt *stmt;

	stmt = db_select_prepare(
	    w->db, "SELECT blockheight, txindex FROM transactions WHERE id=?");
	sqlite3_bind_sha256(stmt, 1, &txid->shad.sha);

	if (!db_select_step(w->db, stmt))
		return NULL;

	if (sqlite3_column_type(stmt, 0) == SQLITE_NULL)
		loc = NULL;
	else {
		loc = tal(ctx, struct txlocator);
		loc->blkheight = sqlite3_column_int(stmt, 0);
		loc->index = sqlite3_column_int(stmt, 1);
	}
	db_stmt_done(stmt);
	return loc;
}

struct bitcoin_txid *wallet_transactions_by_height(const tal_t *ctx,
						   struct wallet *w,
						   const u32 blockheight)
{
	sqlite3_stmt *stmt;
	struct bitcoin_txid *txids = tal_arr(ctx, struct bitcoin_txid, 0);
	int count = 0;
	stmt = db_select_prepare(
	    w->db, "SELECT id FROM transactions WHERE blockheight=?");
	sqlite3_bind_int(stmt, 1, blockheight);

	while (db_select_step(w->db, stmt)) {
		count++;
		tal_resize(&txids, count);
		sqlite3_column_sha256(stmt, 0, &txids[count-1].shad.sha);
	}

	return txids;
}

void wallet_channeltxs_add(struct wallet *w, struct channel *chan,
			   const int type, const struct bitcoin_txid *txid,
			   const u32 input_num, const u32 blockheight)
{
	sqlite3_stmt *stmt;
	stmt = db_prepare(w->db, "INSERT INTO channeltxs ("
			  "  channel_id"
			  ", type"
			  ", transaction_id"
			  ", input_num"
			  ", blockheight"
			  ") VALUES (?, ?, ?, ?, ?);");
	sqlite3_bind_int(stmt, 1, chan->dbid);
	sqlite3_bind_int(stmt, 2, type);
	sqlite3_bind_sha256(stmt, 3, &txid->shad.sha);
	sqlite3_bind_int(stmt, 4, input_num);
	sqlite3_bind_int(stmt, 5, blockheight);

	db_exec_prepared(w->db, stmt);
}

u32 *wallet_onchaind_channels(struct wallet *w,
			      const tal_t *ctx)
{
	sqlite3_stmt *stmt;
	size_t count = 0;
	u32 *channel_ids = tal_arr(ctx, u32, 0);
	stmt = db_select_prepare(w->db, "SELECT DISTINCT(channel_id) FROM channeltxs WHERE type = ?;");
	sqlite3_bind_int(stmt, 1, WIRE_ONCHAIN_INIT);

	while (db_select_step(w->db, stmt)) {
		count++;
		tal_resize(&channel_ids, count);
			channel_ids[count-1] = sqlite3_column_int64(stmt, 0);
	}

	return channel_ids;
}

struct channeltx *wallet_channeltxs_get(struct wallet *w, const tal_t *ctx,
					u32 channel_id)
{
	sqlite3_stmt *stmt;
	size_t count = 0;
	struct channeltx *res = tal_arr(ctx, struct channeltx, 0);
	stmt = db_select_prepare(
	    w->db, "SELECT"
		   "  c.type"
		   ", c.blockheight"
		   ", t.rawtx"
		   ", c.input_num"
		   ", c.blockheight - t.blockheight + 1 AS depth"
		   ", t.id as txid "
		   "FROM channeltxs c "
		   "JOIN transactions t ON t.id == c.transaction_id "
		   "WHERE c.channel_id = ? "
		   "ORDER BY c.id ASC;");
	sqlite3_bind_int(stmt, 1, channel_id);

	while (db_select_step(w->db, stmt)) {
		count++;
		tal_resize(&res, count);

		res[count-1].channel_id = channel_id;
		res[count-1].type = sqlite3_column_int(stmt, 0);
		res[count-1].blockheight = sqlite3_column_int(stmt, 1);
		res[count-1].tx = sqlite3_column_tx(ctx, stmt, 2);
		res[count-1].input_num = sqlite3_column_int(stmt, 3);
		res[count-1].depth = sqlite3_column_int(stmt, 4);
		sqlite3_column_sha256(stmt, 5, &res[count-1].txid.shad.sha);
	}
	return res;
}

void wallet_forwarded_payment_add(struct wallet *w, const struct htlc_in *in,
				  const struct htlc_out *out,
				  enum forward_status state,
				  enum onion_type failcode)
{
	sqlite3_stmt *stmt;
	struct timeabs *resolved_time;
	stmt = db_prepare(
		w->db,
		"INSERT OR REPLACE INTO forwarded_payments ("
		"  in_htlc_id"
		", out_htlc_id"
		", in_channel_scid"
		", out_channel_scid"
		", in_msatoshi"
		", out_msatoshi"
		", state"
		", received_time"
		", resolved_time"
		", failcode"
		") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);");
	sqlite3_bind_int64(stmt, 1, in->dbid);

	if(out) {
		sqlite3_bind_int64(stmt, 2, out->dbid);
		sqlite3_bind_int64(stmt, 4, out->key.channel->scid->u64);
		sqlite3_bind_amount_msat(stmt, 6, out->msat);
	} else {
		/* FORWARD_LOCAL_FAILED may occur before we get htlc_out */
		assert(failcode != 0);
		assert(state == FORWARD_LOCAL_FAILED);
		sqlite3_bind_null(stmt, 2);
		sqlite3_bind_null(stmt, 4);
		sqlite3_bind_null(stmt, 6);
	}

	sqlite3_bind_int64(stmt, 3, in->key.channel->scid->u64);

	sqlite3_bind_amount_msat(stmt, 5, in->msat);

	sqlite3_bind_int(stmt, 7, wallet_forward_status_in_db(state));
	sqlite3_bind_timeabs(stmt, 8, in->received_time);

	if (state == FORWARD_SETTLED || state == FORWARD_FAILED) {
		resolved_time = tal(tmpctx, struct timeabs);
		*resolved_time = time_now();
		sqlite3_bind_timeabs(stmt, 9, *resolved_time);
	} else {
		resolved_time = NULL;
		sqlite3_bind_null(stmt, 9);
	}

	if(failcode != 0) {
		assert(state == FORWARD_FAILED || state == FORWARD_LOCAL_FAILED);
		sqlite3_bind_int(stmt, 10, (int)failcode);
	} else {
		sqlite3_bind_null(stmt, 10);
	}

	db_exec_prepared(w->db, stmt);

	notify_forward_event(w->ld, in, out, state, failcode, resolved_time);
}

struct amount_msat wallet_total_forward_fees(struct wallet *w)
{
	sqlite3_stmt *stmt;
	struct amount_msat total;
	bool res;

	stmt = db_select_prepare(w->db, "SELECT"
					" SUM(in_msatoshi - out_msatoshi) "
					"FROM forwarded_payments "
					"WHERE state = ?;");

	sqlite3_bind_int(stmt, 1, wallet_forward_status_in_db(FORWARD_SETTLED));

	res = db_select_step(w->db, stmt);
	assert(res);

	total = sqlite3_column_amount_msat(stmt, 0);
	db_stmt_done(stmt);

	return total;
}

const struct forwarding *wallet_forwarded_payments_get(struct wallet *w,
						       const tal_t *ctx)
{
	struct forwarding *results = tal_arr(ctx, struct forwarding, 0);
	size_t count = 0;
	sqlite3_stmt *stmt;
	stmt = db_select_prepare(
	    w->db, "SELECT"
		   "  f.state"
		   ", in_msatoshi"
		   ", out_msatoshi"
		   ", hin.payment_hash as payment_hash"
		   ", in_channel_scid"
		   ", out_channel_scid"
		   ", f.received_time"
		   ", f.resolved_time"
		   ", f.failcode "
		   "FROM forwarded_payments f "
		   "LEFT JOIN channel_htlcs hin ON (f.in_htlc_id == hin.id)");

	for (count=0; db_select_step(w->db, stmt); count++) {
		tal_resize(&results, count+1);
		struct forwarding *cur = &results[count];
		cur->status = sqlite3_column_int(stmt, 0);
		cur->msat_in = sqlite3_column_amount_msat(stmt, 1);

		if (sqlite3_column_type(stmt, 2) != SQLITE_NULL) {
			cur->msat_out = sqlite3_column_amount_msat(stmt, 2);
			if (!amount_msat_sub(&cur->fee, cur->msat_in, cur->msat_out)) {
				log_broken(w->log, "Forwarded in %s less than out %s!",
					   type_to_string(tmpctx, struct amount_msat,
							  &cur->msat_in),
					   type_to_string(tmpctx, struct amount_msat,
							  &cur->msat_out));
				cur->fee = AMOUNT_MSAT(0);
			}
		}
		else {
			assert(cur->status == FORWARD_LOCAL_FAILED);
			cur->msat_out = AMOUNT_MSAT(0);
			/* For this case, this forward_payment doesn't have out channel,
			 * so the fee should be set as 0.*/
			cur->fee =  AMOUNT_MSAT(0);
		}

		if (sqlite3_column_type(stmt, 3) != SQLITE_NULL) {
			cur->payment_hash = tal(ctx, struct sha256_double);
			sqlite3_column_sha256_double(stmt, 3, cur->payment_hash);
		} else {
			cur->payment_hash = NULL;
		}

		cur->channel_in.u64 = sqlite3_column_int64(stmt, 4);

		if (sqlite3_column_type(stmt, 5) != SQLITE_NULL) {
			cur->channel_out.u64 = sqlite3_column_int64(stmt, 5);
		} else {
			assert(cur->status == FORWARD_LOCAL_FAILED);
			cur->channel_out.u64 = 0;
		}

		cur->received_time = sqlite3_column_timeabs(stmt, 6);

		if (sqlite3_column_type(stmt, 7) != SQLITE_NULL) {
			cur->resolved_time = tal(ctx, struct timeabs);
			*cur->resolved_time = sqlite3_column_timeabs(stmt, 7);
		} else {
			cur->resolved_time = NULL;
		}

		if (sqlite3_column_type(stmt, 8) != SQLITE_NULL) {
			assert(cur->status == FORWARD_FAILED ||
			       cur->status == FORWARD_LOCAL_FAILED);
			cur->failcode = sqlite3_column_int(stmt, 8);
		} else {
			cur->failcode = 0;
		}
	}

	return results;
}

struct unreleased_tx *find_unreleased_tx(struct wallet *w,
					 const struct bitcoin_txid *txid)
{
	struct unreleased_tx *utx;

	list_for_each(&w->unreleased_txs, utx, list) {
		if (bitcoin_txid_eq(txid, &utx->txid))
			return utx;
	}
	return NULL;
}

static void destroy_unreleased_tx(struct unreleased_tx *utx)
{
	list_del(&utx->list);
}

void remove_unreleased_tx(struct unreleased_tx *utx)
{
	tal_del_destructor(utx, destroy_unreleased_tx);
	list_del(&utx->list);
}

void add_unreleased_tx(struct wallet *w, struct unreleased_tx *utx)
{
	list_add_tail(&w->unreleased_txs, &utx->list);
	tal_add_destructor(utx, destroy_unreleased_tx);
}

/* These will touch the db, so need to be explicitly freed. */
void free_unreleased_txs(struct wallet *w)
{
	struct unreleased_tx *utx;

	while ((utx = list_top(&w->unreleased_txs, struct unreleased_tx, list)))
		tal_free(utx);
}

static void process_utxo_result(struct bitcoind *bitcoind,
				const struct bitcoin_tx_output *txout,
				void *_utxos)
{
	struct utxo **utxos = _utxos;
	enum output_status newstate =
	    txout == NULL ? output_state_spent : output_state_available;

	log_unusual(bitcoind->ld->wallet->log,
		    "wallet: reserved output %s/%u reset to %s",
		    type_to_string(tmpctx, struct bitcoin_txid, &utxos[0]->txid),
		    utxos[0]->outnum,
		    newstate == output_state_spent ? "spent" : "available");
	wallet_update_output_status(bitcoind->ld->wallet,
				    &utxos[0]->txid, utxos[0]->outnum,
				    utxos[0]->status, newstate);

	/* If we have more, resolve them too. */
	tal_arr_remove(&utxos, 0);
	if (tal_count(utxos) != 0) {
		bitcoind_gettxout(bitcoind, &utxos[0]->txid, utxos[0]->outnum,
				  process_utxo_result, utxos);
	} else
		tal_free(utxos);
}

void wallet_clean_utxos(struct wallet *w, struct bitcoind *bitcoind)
{
	struct utxo **utxos = wallet_get_utxos(NULL, w, output_state_reserved);

	if (tal_count(utxos) != 0) {
		bitcoind_gettxout(bitcoind, &utxos[0]->txid, utxos[0]->outnum,
				  process_utxo_result, notleak(utxos));
	} else
		tal_free(utxos);
}

struct wallet_transaction *wallet_transactions_get(struct wallet *w, const tal_t *ctx)
{
	sqlite3_stmt *stmt;
	size_t count;
	struct wallet_transaction *cur, *txs = tal_arr(ctx, struct wallet_transaction, 0);

	stmt = db_select_prepare(w->db,
				 "SELECT id, id, rawtx, blockheight, txindex, type, channel_id "
				 "FROM transactions");
	for (count = 0; db_select_step(w->db, stmt); count++) {
		tal_resize(&txs, count + 1);
		cur = &txs[count];
		sqlite3_column_sha256_double(stmt, 1, &cur->id.shad);
		cur->rawtx = tal_dup_arr(txs, u8, sqlite3_column_blob(stmt, 2),
					 sqlite3_column_bytes(stmt, 2), 0);
		cur->blockheight = sqlite3_column_int(stmt, 3);
		cur->txindex = sqlite3_column_int(stmt, 4);
		cur->type = sqlite3_column_int(stmt, 5);
		cur->channel_id = sqlite3_column_int(stmt, 6);
	}

	return txs;
}
