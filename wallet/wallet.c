#include "invoices.h"
#include "wallet.h"

#include <bitcoin/script.h>
#include <ccan/tal/str/str.h>
#include <common/key_derive.h>
#include <common/wireaddr.h>
#include <inttypes.h>
#include <lightningd/lightningd.h>
#include <lightningd/log.h>
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
	stmt = db_prepare(w->db, "SELECT txid, outnum FROM utxoset WHERE spendheight is NULL");

	while (sqlite3_step(stmt) == SQLITE_ROW) {
		sqlite3_column_sha256_double(stmt, 0, &txid.shad);
		outnum = sqlite3_column_int(stmt, 1);
		outpointfilter_add(w->utxoset_outpoints, &txid, outnum);
	}

	db_stmt_done(stmt);
}

struct wallet *wallet_new(struct lightningd *ld,
			  struct log *log, struct timers *timers)
{
	struct wallet *wallet = tal(ld, struct wallet);
	wallet->ld = ld;
	wallet->db = db_setup(wallet, log);
	wallet->log = log;
	wallet->bip32_base = NULL;
	wallet->invoices = invoices_new(wallet, wallet->db, log, timers);
	list_head_init(&wallet->unstored_payments);

	db_begin_transaction(wallet->db);
	outpointfilters_init(wallet);
	db_commit_transaction(wallet->db);
	return wallet;
}

/* We actually use the db constraints to uniquify, so OK if this fails. */
bool wallet_add_utxo(struct wallet *w, struct utxo *utxo,
		     enum wallet_output_type type)
{
	sqlite3_stmt *stmt;

	stmt = db_prepare(w->db, "INSERT INTO outputs ("
			  "prev_out_tx, "
			  "prev_out_index, "
			  "value, "
			  "type, "
			  "status, "
			  "keyindex, "
			  "channel_id, "
			  "peer_id, "
			  "commitment_point, "
			  "confirmation_height, "
			  "spend_height) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);");
	sqlite3_bind_blob(stmt, 1, &utxo->txid, sizeof(utxo->txid), SQLITE_TRANSIENT);
	sqlite3_bind_int(stmt, 2, utxo->outnum);
	sqlite3_bind_int64(stmt, 3, utxo->amount);
	sqlite3_bind_int(stmt, 4, type);
	sqlite3_bind_int(stmt, 5, output_state_available);
	sqlite3_bind_int(stmt, 6, utxo->keyindex);
	if (utxo->close_info) {
		sqlite3_bind_int64(stmt, 7, utxo->close_info->channel_id);
		sqlite3_bind_pubkey(stmt, 8, &utxo->close_info->peer_id);
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

	/* May fail if we already know about the tx, e.g., because
	 * it's change or some internal tx. */
	return db_exec_prepared_mayfail(w->db, stmt);
}

/**
 * wallet_stmt2output - Extract data from stmt and fill an UTXO
 *
 * Returns true on success.
 */
static bool wallet_stmt2output(sqlite3_stmt *stmt, struct utxo *utxo)
{
	u32 *blockheight, *spendheight;
	sqlite3_column_sha256_double(stmt, 0, &utxo->txid.shad);
	utxo->outnum = sqlite3_column_int(stmt, 1);
	utxo->amount = sqlite3_column_int64(stmt, 2);
	utxo->is_p2sh = sqlite3_column_int(stmt, 3) == p2sh_wpkh;
	utxo->status = sqlite3_column_int(stmt, 4);
	utxo->keyindex = sqlite3_column_int(stmt, 5);
	if (sqlite3_column_type(stmt, 6) != SQLITE_NULL) {
		utxo->close_info = tal(utxo, struct unilateral_close_info);
		utxo->close_info->channel_id = sqlite3_column_int64(stmt, 6);
		sqlite3_column_pubkey(stmt, 7, &utxo->close_info->peer_id);
		sqlite3_column_pubkey(stmt, 8, &utxo->close_info->commitment_point);
	} else {
		utxo->close_info = NULL;
	}

	utxo->blockheight = NULL;
	utxo->spendheight = NULL;

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

	return true;
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
		sqlite3_bind_int(stmt, 1, newstatus);
		sqlite3_bind_int(stmt, 2, oldstatus);
		sqlite3_bind_blob(stmt, 3, txid, sizeof(*txid), SQLITE_TRANSIENT);
		sqlite3_bind_int(stmt, 4, outnum);
	} else {
		stmt = db_prepare(
			w->db, "UPDATE outputs SET status=? WHERE prev_out_tx=? AND prev_out_index=?");
		sqlite3_bind_int(stmt, 1, newstatus);
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

	sqlite3_stmt *stmt = db_prepare(
		w->db, "SELECT prev_out_tx, prev_out_index, value, type, status, keyindex, "
		"channel_id, peer_id, commitment_point, confirmation_height, spend_height "
		"FROM outputs WHERE status=?1 OR ?1=255");
	sqlite3_bind_int(stmt, 1, state);

       	results = tal_arr(ctx, struct utxo*, 0);
	for (i=0; sqlite3_step(stmt) == SQLITE_ROW; i++) {
		tal_resize(&results, i+1);
		results[i] = tal(results, struct utxo);
		wallet_stmt2output(stmt, results[i]);
	}
	db_stmt_done(stmt);

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
					 const u64 value,
					 const u32 feerate_per_kw,
					 size_t outscriptlen,
					 bool may_have_change,
					 u64 *satoshi_in,
					 u64 *fee_estimate)
{
	size_t i = 0;
	struct utxo **available;
	u64 weight;
	const struct utxo **utxos = tal_arr(ctx, const struct utxo *, 0);
	tal_add_destructor2(utxos, destroy_utxos, w);

	/* version, input count, output count, locktime */
	weight = (4 + 1 + 1 + 4) * 4;

	/* The main output: amount, len, scriptpubkey */
	weight += (8 + 1 + outscriptlen) * 4;

	/* Change output will be P2WPKH */
	if (may_have_change)
		weight += (8 + 1 + BITCOIN_SCRIPTPUBKEY_P2WPKH_LEN) * 4;

	*fee_estimate = 0;
	*satoshi_in = 0;

	available = wallet_get_utxos(ctx, w, output_state_available);

	for (i = 0; i < tal_count(available); i++) {
		size_t input_weight;

		tal_resize(&utxos, i + 1);
		utxos[i] = tal_steal(utxos, available[i]);

		if (!wallet_update_output_status(
			w, &available[i]->txid, available[i]->outnum,
			output_state_available, output_state_reserved))
			fatal("Unable to reserve output");

		/* Input weight: txid + index + sequence */
		input_weight = (32 + 4 + 4) * 4;

		/* We always encode the length of the script, even if empty */
		input_weight += 1 * 4;

		/* P2SH variants include push of <0 <20-byte-key-hash>> */
		if (utxos[i]->is_p2sh)
			input_weight += 23 * 4;

		/* Account for witness (1 byte count + sig + key) */
		input_weight += 1 + (1 + 73 + 1 + 33);

		weight += input_weight;

		*fee_estimate = weight * feerate_per_kw / 1000;
		*satoshi_in += utxos[i]->amount;
		if (*satoshi_in >= *fee_estimate + value)
			break;
	}
	tal_free(available);

	return utxos;
}

const struct utxo **wallet_select_coins(const tal_t *ctx, struct wallet *w,
					const u64 value,
					const u32 feerate_per_kw,
					size_t outscriptlen,
					u64 *fee_estimate, u64 *changesatoshi)
{
	u64 satoshi_in;
	const struct utxo **utxo;

	utxo = wallet_select(ctx, w, value, feerate_per_kw,
			     outscriptlen, true,
			     &satoshi_in, fee_estimate);

	/* Couldn't afford it? */
	if (satoshi_in < *fee_estimate + value)
		return tal_free(utxo);

	*changesatoshi = satoshi_in - value - *fee_estimate;
	return utxo;
}

const struct utxo **wallet_select_all(const tal_t *ctx, struct wallet *w,
				      const u32 feerate_per_kw,
				      size_t outscriptlen,
				      u64 *value,
				      u64 *fee_estimate)
{
	u64 satoshi_in;
	const struct utxo **utxo;

	/* Huge value, but won't overflow on addition */
	utxo = wallet_select(ctx, w, (1ULL << 56), feerate_per_kw,
			     outscriptlen, false,
			     &satoshi_in, fee_estimate);

	/* Can't afford fees? */
	if (*fee_estimate > satoshi_in)
		return tal_free(utxo);

	*value = satoshi_in - *fee_estimate;
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
	int err;
	sqlite3_stmt *stmt;
	chain->id = id;
	shachain_init(&chain->chain);

	/* Load shachain metadata */
	stmt = db_prepare(wallet->db, "SELECT min_index, num_valid FROM shachains WHERE id=?");
	sqlite3_bind_int64(stmt, 1, id);

	err = sqlite3_step(stmt);
	if (err != SQLITE_ROW) {
		db_stmt_done(stmt);
		return false;
	}

	chain->chain.min_index = sqlite3_column_int64(stmt, 0);
	chain->chain.num_valid = sqlite3_column_int64(stmt, 1);
	db_stmt_done(stmt);

	/* Load shachain known entries */
	stmt = db_prepare(wallet->db, "SELECT idx, hash, pos FROM shachain_known WHERE shachain_id=?");
	sqlite3_bind_int64(stmt, 1, id);

	while (sqlite3_step(stmt) == SQLITE_ROW) {
		int pos = sqlite3_column_int(stmt, 2);
		chain->chain.known[pos].index = sqlite3_column_int64(stmt, 0);
		memcpy(&chain->chain.known[pos].hash, sqlite3_column_blob(stmt, 1), sqlite3_column_bytes(stmt, 1));
	}

	db_stmt_done(stmt);
	return true;
}

static struct peer *wallet_peer_load(struct wallet *w, const u64 dbid)
{
	const unsigned char *addrstr;
	struct peer *peer;
	struct pubkey id;
	struct wireaddr_internal *addrp, addr;

	sqlite3_stmt *stmt =
		db_query(w->db,
			 "SELECT id, node_id, address FROM peers WHERE id=%"PRIu64";", dbid);

	if (!stmt || sqlite3_step(stmt) != SQLITE_ROW) {
		db_stmt_done(stmt);
		return NULL;
	}
	if (!sqlite3_column_pubkey(stmt, 1, &id)) {
		db_stmt_done(stmt);
		return NULL;
	}
	addrstr = sqlite3_column_text(stmt, 2);
	if (addrstr) {
		addrp = &addr;
		if (!parse_wireaddr_internal((const char*)addrstr, addrp, DEFAULT_PORT, false, false, true, NULL)) {
			db_stmt_done(stmt);
			return NULL;
		}
	} else
		addrp = NULL;

	peer = new_peer(w->ld, sqlite3_column_int64(stmt, 0),
			&id, addrp, NULL, NULL);
	db_stmt_done(stmt);

	return peer;
}

static secp256k1_ecdsa_signature *
wallet_htlc_sigs_load(const tal_t *ctx, struct wallet *w, u64 channelid)
{
	sqlite3_stmt *stmt = db_prepare(w->db, "SELECT signature FROM htlc_sigs WHERE channelid = ?");
	secp256k1_ecdsa_signature *htlc_sigs = tal_arr(ctx, secp256k1_ecdsa_signature, 0);
	sqlite3_bind_int64(stmt, 1, channelid);
	size_t n = 0;

	while (stmt && sqlite3_step(stmt) == SQLITE_ROW) {
		tal_resize(&htlc_sigs, n+1);
		sqlite3_column_signature(stmt, 0, &htlc_sigs[n]);
		n++;
	}
	db_stmt_done(stmt);
	log_debug(w->log, "Loaded %zu HTLC signatures from DB", n);
	return htlc_sigs;
}

/**
 * wallet_stmt2channel - Helper to populate a wallet_channel from a sqlite3_stmt
 */
static struct channel *wallet_stmt2channel(const tal_t *ctx, struct wallet *w, sqlite3_stmt *stmt)
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
	secp256k1_ecdsa_signature last_sig;
	u8 *remote_shutdown_scriptpubkey;
	struct changed_htlc *last_sent_commit;
	s64 final_key_idx;
	struct basepoints local_basepoints;
	struct pubkey local_funding_pubkey;

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
		sqlite3_column_short_channel_id(stmt, 2, scid);
	} else {
		scid = NULL;
	}

	ok &= wallet_shachain_load(w, sqlite3_column_int64(stmt, 27),
				   &wshachain);

	remote_shutdown_scriptpubkey = sqlite3_column_arr(tmpctx, stmt, 28, u8);

	/* Do we have a last_sent_commit, if yes, populate */
	if (sqlite3_column_type(stmt, 30) != SQLITE_NULL) {
		last_sent_commit = tal(tmpctx, struct changed_htlc);
		last_sent_commit->newstate = sqlite3_column_int64(stmt, 30);
		last_sent_commit->id = sqlite3_column_int64(stmt, 31);
	} else {
		last_sent_commit = NULL;
	}

	ok &= wallet_channel_config_load(w, sqlite3_column_int64(stmt, 3),
					 &our_config);
	ok &= sqlite3_column_sha256_double(stmt, 12, &funding_txid.shad);

	ok &= sqlite3_column_signature(stmt, 33, &last_sig);

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
			   sqlite3_column_int64(stmt, 14),
			   sqlite3_column_int64(stmt, 16),
			   sqlite3_column_int(stmt, 15) != 0,
			   scid,
			   sqlite3_column_int64(stmt, 17),
			   sqlite3_column_int64(stmt, 38), /* msatoshi_to_us_min */
			   sqlite3_column_int64(stmt, 39), /* msatoshi_to_us_max */
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
			   &local_basepoints, &local_funding_pubkey);

	return chan;
}

/* List of fields to retrieve from the channels DB table, in the order
 * that wallet_stmt2channel understands and will parse correctly */
/* Numbers below are sqlite3_column indices for the first field
 * of that line. */
static const char *channel_fields =
    /*0*/ "id, peer_id, short_channel_id, channel_config_local, "
    /*4*/ "channel_config_remote, state, funder, channel_flags, "
    /*8*/ "minimum_depth, "
    /*9*/ "next_index_local, next_index_remote, "
    /*11*/ "next_htlc_id, funding_tx_id, funding_tx_outnum, funding_satoshi, "
    /*15*/ "funding_locked_remote, push_msatoshi, msatoshi_local, "
    /*18*/ "fundingkey_remote, revocation_basepoint_remote, "
    /*20*/ "payment_basepoint_remote, htlc_basepoint_remote, "
    /*22*/ "delayed_payment_basepoint_remote, per_commit_remote, "
    /*24*/ "old_per_commit_remote, local_feerate_per_kw, remote_feerate_per_kw, shachain_remote_id, "
    /*28*/ "shutdown_scriptpubkey_remote, shutdown_keyidx_local, "
    /*30*/ "last_sent_commit_state, last_sent_commit_id, "
    /*32*/ "last_tx, last_sig, last_was_revoke, first_blocknum, "
    /*36*/ "min_possible_feerate, max_possible_feerate, "
    /*38*/ "msatoshi_to_us_min, msatoshi_to_us_max ";

bool wallet_channels_load_active(const tal_t *ctx, struct wallet *w)
{
	bool ok = true;
	sqlite3_stmt *stmt;

	/* We load all channels */
	stmt = db_query(w->db, "SELECT %s FROM channels;",
			channel_fields);

	w->max_channel_dbid = 0;

	int count = 0;
	while (ok && stmt && sqlite3_step(stmt) == SQLITE_ROW) {
		struct channel *c = wallet_stmt2channel(ctx, w, stmt);
		if (!c) {
			ok = false;
			break;
		}
		if (c->dbid > w->max_channel_dbid)
			w->max_channel_dbid = c->dbid;
		count++;
	}
	log_debug(w->log, "Loaded %d channels from DB", count);
	db_stmt_done(stmt);
	return ok;
}

static
void wallet_channel_stats_incr_x(struct wallet *w,
				 char const *dir,
				 char const *typ,
				 u64 cdbid,
				 u64 msatoshi)
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
				  msatoshi_stat, msatoshi_stat, msatoshi,
				  cdbid);
	sqlite3_stmt *stmt = db_prepare(w->db, qry);
	db_exec_prepared(w->db, stmt);
}
void wallet_channel_stats_incr_in_offered(struct wallet *w, u64 id, u64 m)
{
	wallet_channel_stats_incr_x(w, "in", "offered", id, m);
}
void wallet_channel_stats_incr_in_fulfilled(struct wallet *w, u64 id, u64 m)
{
	wallet_channel_stats_incr_x(w, "in", "fulfilled", id, m);
}
void wallet_channel_stats_incr_out_offered(struct wallet *w, u64 id, u64 m)
{
	wallet_channel_stats_incr_x(w, "out", "offered", id, m);
}
void wallet_channel_stats_incr_out_fulfilled(struct wallet *w, u64 id, u64 m)
{
	wallet_channel_stats_incr_x(w, "out", "fulfilled", id, m);
}

void wallet_channel_stats_load(struct wallet *w,
			       u64 id,
			       struct channel_stats *stats)
{
	sqlite3_stmt *stmt;
	stmt = db_prepare(w->db,
			  "SELECT  in_payments_offered,  in_payments_fulfilled"
			  "     ,  in_msatoshi_offered,  in_msatoshi_fulfilled"
			  "     , out_payments_offered, out_payments_fulfilled"
			  "     , out_msatoshi_offered, out_msatoshi_fulfilled"
			  "  FROM channels"
			  " WHERE id = ?");
	sqlite3_bind_int64(stmt, 1, id);
	stats->in_payments_offered = sqlite3_column_int64(stmt, 0);
	stats->in_payments_fulfilled = sqlite3_column_int64(stmt, 1);
	stats->in_msatoshi_offered = sqlite3_column_int64(stmt, 2);
	stats->in_msatoshi_fulfilled = sqlite3_column_int64(stmt, 3);
	stats->out_payments_offered = sqlite3_column_int64(stmt, 4);
	stats->out_payments_fulfilled = sqlite3_column_int64(stmt, 5);
	stats->out_msatoshi_offered = sqlite3_column_int64(stmt, 6);
	stats->out_msatoshi_fulfilled = sqlite3_column_int64(stmt, 7);
	db_stmt_done(stmt);
}

void wallet_blocks_heights(struct wallet *w, u32 def, u32 *min, u32 *max)
{
	assert(min != NULL && max != NULL);
	sqlite3_stmt *stmt = db_prepare(w->db, "SELECT MIN(height), MAX(height) FROM blocks;");

	/* If we ever processed a block we'll get the latest block in the chain */
	if (sqlite3_step(stmt) == SQLITE_ROW && sqlite3_column_type(stmt, 0) != SQLITE_NULL) {
		*min = sqlite3_column_int(stmt, 0);
		*max = sqlite3_column_int(stmt, 1);
	} else {
		*min = def;
		*max = def;
	}
	db_stmt_done(stmt);
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
	sqlite3_bind_int64(stmt, 1, cc->dust_limit_satoshis);
	sqlite3_bind_int64(stmt, 2, cc->max_htlc_value_in_flight_msat);
	sqlite3_bind_int64(stmt, 3, cc->channel_reserve_satoshis);
	sqlite3_bind_int64(stmt, 4, cc->htlc_minimum_msat);
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
	    "max_accepted_htlcs FROM channel_configs WHERE id=%" PRIu64 ";";
	sqlite3_stmt *stmt = db_query(w->db, query, id);
	if (!stmt || sqlite3_step(stmt) != SQLITE_ROW) {
		db_stmt_done(stmt);
		return false;
	}
	cc->id = id;
	cc->dust_limit_satoshis = sqlite3_column_int64(stmt, col++);
	cc->max_htlc_value_in_flight_msat = sqlite3_column_int64(stmt, col++);
	cc->channel_reserve_satoshis = sqlite3_column_int64(stmt, col++);
	cc->htlc_minimum_msat = sqlite3_column_int64(stmt, col++);
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

void wallet_channel_save(struct wallet *w, struct channel *chan)
{
	sqlite3_stmt *stmt;
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
			  "  msatoshi_to_us_max=?"
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
	sqlite3_bind_int64(stmt, 12, chan->funding_satoshi);
	sqlite3_bind_int(stmt, 13, chan->remote_funding_locked);
	sqlite3_bind_int64(stmt, 14, chan->push_msat);
	sqlite3_bind_int64(stmt, 15, chan->our_msatoshi);

	if (chan->remote_shutdown_scriptpubkey)
		sqlite3_bind_blob(stmt, 16, chan->remote_shutdown_scriptpubkey,
				  tal_count(chan->remote_shutdown_scriptpubkey),
				  SQLITE_TRANSIENT);
	else
		sqlite3_bind_null(stmt, 16);

	sqlite3_bind_int64(stmt, 17, chan->final_key_idx);
	sqlite3_bind_int64(stmt, 18, chan->our_config.id);
	sqlite3_bind_tx(stmt, 19, chan->last_tx);
	sqlite3_bind_signature(stmt, 20, &chan->last_sig);
	sqlite3_bind_int(stmt, 21, chan->last_was_revoke);
	sqlite3_bind_int(stmt, 22, chan->min_possible_feerate);
	sqlite3_bind_int(stmt, 23, chan->max_possible_feerate);
	sqlite3_bind_int64(stmt, 24, chan->msatoshi_to_us_min);
	sqlite3_bind_int64(stmt, 25, chan->msatoshi_to_us_max);
	sqlite3_bind_int64(stmt, 26, chan->dbid);
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
			  "  channel_config_remote=?"
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
	sqlite3_bind_int64(stmt, 11, chan->dbid);
	db_exec_prepared(w->db, stmt);

	/* If we have a last_sent_commit, store it */
	if (chan->last_sent_commit) {
		stmt = db_prepare(w->db,
				  "UPDATE channels SET"
				  "  last_sent_commit_state=?,"
				  "  last_sent_commit_id=?"
				  " WHERE id=?");
		sqlite3_bind_int(stmt, 1, chan->last_sent_commit->newstate);
		sqlite3_bind_int64(stmt, 2, chan->last_sent_commit->id);
		sqlite3_bind_int64(stmt, 3, chan->dbid);
		db_exec_prepared(w->db, stmt);
	}
}

void wallet_channel_insert(struct wallet *w, struct channel *chan)
{
	sqlite3_stmt *stmt;

	if (chan->peer->dbid == 0) {
		/* Need to create the peer first */
		stmt = db_prepare(w->db, "INSERT INTO peers (node_id, address) VALUES (?, ?);");
		sqlite3_bind_pubkey(stmt, 1, &chan->peer->id);
		if (chan->peer->addr.itype == ADDR_INTERNAL_WIREADDR
		    && chan->peer->addr.u.wireaddr.type == ADDR_TYPE_PADDING)
			sqlite3_bind_null(stmt, 2);
		else
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

void wallet_channel_delete(struct wallet *w, u64 wallet_id)
{
	sqlite3_stmt *stmt;
	stmt = db_prepare(w->db,
			  "DELETE FROM channels WHERE id=?");
	sqlite3_bind_int64(stmt, 1, wallet_id);
	db_exec_prepared(w->db, stmt);
}

void wallet_peer_delete(struct wallet *w, u64 peer_dbid)
{
	sqlite3_stmt *stmt;

	/* Must not have any channels still using this peer */
	stmt = db_query(w->db,
			"SELECT * FROM channels WHERE peer_id = %"PRIu64,
			peer_dbid);
	assert(sqlite3_step(stmt) == SQLITE_DONE);
	db_stmt_done(stmt);

	stmt = db_prepare(w->db, "DELETE FROM peers WHERE id=?");
	sqlite3_bind_int64(stmt, 1, peer_dbid);
	db_exec_prepared(w->db, stmt);
}

static void wallet_output_confirm(struct wallet *w,
				  const struct bitcoin_txid *txid,
				  const u32 outnum,
				  const u32 confirmation_height)
{
	sqlite3_stmt *stmt;
	assert(confirmation_height > 0);
	stmt = db_prepare(w->db,
			  "UPDATE outputs "
			  "SET confirmation_height = ? "
			  "WHERE prev_out_tx = ? AND prev_out_index = ?");
	sqlite3_bind_int(stmt, 1, confirmation_height);
	sqlite3_bind_sha256_double(stmt, 2, &txid->shad);
	sqlite3_bind_int(stmt, 3, outnum);

	db_exec_prepared(w->db, stmt);
}

int wallet_extract_owned_outputs(struct wallet *w, const struct bitcoin_tx *tx,
				 const u32 *blockheight, u64 *total_satoshi)
{
	int num_utxos = 0;
	for (size_t output = 0; output < tal_count(tx->output); output++) {
		struct utxo *utxo;
		u32 index;
		bool is_p2sh;

		if (!wallet_can_spend(w, tx->output[output].script, &index,
				      &is_p2sh))
			continue;

		utxo = tal(w, struct utxo);
		utxo->keyindex = index;
		utxo->is_p2sh = is_p2sh;
		utxo->amount = tx->output[output].amount;
		utxo->status = output_state_available;
		bitcoin_txid(tx, &utxo->txid);
		utxo->outnum = output;
		utxo->close_info = NULL;

		utxo->blockheight = blockheight?blockheight:NULL;
		utxo->spendheight = NULL;

		log_debug(w->log, "Owning output %zu %"PRIu64" (%s) txid %s",
			  output, tx->output[output].amount,
			  is_p2sh ? "P2SH" : "SEGWIT",
			  type_to_string(tmpctx, struct bitcoin_txid,
					 &utxo->txid));

		if (!wallet_add_utxo(w, utxo, is_p2sh ? p2sh_wpkh : our_change)) {
			/* In case we already know the output, make
			 * sure we actually track its
			 * blockheight. This can happen when we grab
			 * the output from a transaction we created
			 * ourselves. */
			if (blockheight)
				wallet_output_confirm(w, &utxo->txid, utxo->outnum, *blockheight);
			tal_free(utxo);
			continue;
		}
		outpointfilter_add(w->owned_outpoints, &utxo->txid, utxo->outnum);

		*total_satoshi += utxo->amount;
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
		" routing_onion) VALUES "
		"(?, ?, ?, ?, ?, ?, ?, ?, ?, ?);");

	sqlite3_bind_int64(stmt, 1, chan->dbid);
	sqlite3_bind_int64(stmt, 2, in->key.id);
	sqlite3_bind_int(stmt, 3, DIRECTION_INCOMING);
	sqlite3_bind_int64(stmt, 4, in->msatoshi);
	sqlite3_bind_int(stmt, 5, in->cltv_expiry);
	sqlite3_bind_sha256(stmt, 6, &in->payment_hash);

	if (in->preimage)
		sqlite3_bind_preimage(stmt, 7, in->preimage);
	else
		sqlite3_bind_null(stmt, 7);
	sqlite3_bind_int(stmt, 8, in->hstate);

	sqlite3_bind_blob(stmt, 9, &in->shared_secret,
			  sizeof(in->shared_secret), SQLITE_TRANSIENT);

	sqlite3_bind_blob(stmt, 10, &in->onion_routing_packet,
			  sizeof(in->onion_routing_packet), SQLITE_TRANSIENT);

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
	sqlite3_bind_int64(stmt, 5, out->msatoshi);
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
			const struct preimage *payment_key)
{
	sqlite3_stmt *stmt;

	/* The database ID must be set by a previous call to
	 * `wallet_htlc_save_*` */
	assert(htlc_dbid);
	stmt = db_prepare(
		wallet->db,
		"UPDATE channel_htlcs SET hstate=?, payment_key=? WHERE id=?");

	sqlite3_bind_int(stmt, 1, new_state);
	sqlite3_bind_int64(stmt, 3, htlc_dbid);

	if (payment_key)
		sqlite3_bind_preimage(stmt, 2, payment_key);
	else
		sqlite3_bind_null(stmt, 2);

	db_exec_prepared(wallet->db, stmt);
}

static bool wallet_stmt2htlc_in(struct channel *channel,
				sqlite3_stmt *stmt, struct htlc_in *in)
{
	bool ok = true;
	in->dbid = sqlite3_column_int64(stmt, 0);
	in->key.id = sqlite3_column_int64(stmt, 1);
	in->key.channel = channel;
	in->msatoshi = sqlite3_column_int64(stmt, 2);
	in->cltv_expiry = sqlite3_column_int(stmt, 3);
	in->hstate = sqlite3_column_int(stmt, 4);

	sqlite3_column_sha256(stmt, 5, &in->payment_hash);

	assert(sqlite3_column_bytes(stmt, 6) == sizeof(struct secret));
	memcpy(&in->shared_secret, sqlite3_column_blob(stmt, 6),
	       sizeof(struct secret));

	if (sqlite3_column_type(stmt, 7) != SQLITE_NULL) {
		in->preimage = tal(in, struct preimage);
		sqlite3_column_preimage(stmt, 7, in->preimage);
	} else {
		in->preimage = NULL;
	}

	assert(sqlite3_column_bytes(stmt, 8) == sizeof(in->onion_routing_packet));
	memcpy(&in->onion_routing_packet, sqlite3_column_blob(stmt, 8),
	       sizeof(in->onion_routing_packet));

	/* FIXME: These need to be saved in db! */
	in->failuremsg = NULL;
	in->failcode = 0;

	return ok;
}
static bool wallet_stmt2htlc_out(struct channel *channel,
				sqlite3_stmt *stmt, struct htlc_out *out)
{
	bool ok = true;
	out->dbid = sqlite3_column_int64(stmt, 0);
	out->key.id = sqlite3_column_int64(stmt, 1);
	out->key.channel = channel;
	out->msatoshi = sqlite3_column_int64(stmt, 2);
	out->cltv_expiry = sqlite3_column_int(stmt, 3);
	out->hstate = sqlite3_column_int(stmt, 4);
	sqlite3_column_sha256(stmt, 5, &out->payment_hash);

	if (sqlite3_column_type(stmt, 6) != SQLITE_NULL) {
		out->origin_htlc_id = sqlite3_column_int64(stmt, 6);
	} else {
		out->origin_htlc_id = 0;
	}

	if (sqlite3_column_type(stmt, 7) != SQLITE_NULL) {
		out->preimage = tal(out, struct preimage);
		sqlite3_column_preimage(stmt, 7, out->preimage);
	} else {
		out->preimage = NULL;
	}

	assert(sqlite3_column_bytes(stmt, 8) == sizeof(out->onion_routing_packet));
	memcpy(&out->onion_routing_packet, sqlite3_column_blob(stmt, 8),
	       sizeof(out->onion_routing_packet));

	out->failuremsg = NULL;
	out->failcode = 0;

	/* Need to defer wiring until we can look up all incoming
	 * htlcs, will wire using origin_htlc_id */
	out->in = NULL;

	return ok;
}

bool wallet_htlcs_load_for_channel(struct wallet *wallet,
				   struct channel *chan,
				   struct htlc_in_map *htlcs_in,
				   struct htlc_out_map *htlcs_out)
{
	bool ok = true;
	int incount = 0, outcount = 0;

	log_debug(wallet->log, "Loading HTLCs for channel %"PRIu64, chan->dbid);
	sqlite3_stmt *stmt = db_query(
	    wallet->db,
	    "SELECT id, channel_htlc_id, msatoshi, cltv_expiry, hstate, "
	    "payment_hash, shared_secret, payment_key, routing_onion FROM channel_htlcs WHERE "
	    "direction=%d AND channel_id=%" PRIu64 " AND hstate != %d",
	    DIRECTION_INCOMING, chan->dbid, SENT_REMOVE_ACK_REVOCATION);

	if (!stmt) {
		log_broken(wallet->log, "Could not select htlc_ins");
		return false;
	}

	while (ok && sqlite3_step(stmt) == SQLITE_ROW) {
		struct htlc_in *in = tal(chan, struct htlc_in);
		ok &= wallet_stmt2htlc_in(chan, stmt, in);
		connect_htlc_in(htlcs_in, in);
		ok &=  htlc_in_check(in, "wallet_htlcs_load") != NULL;
		incount++;
	}
	db_stmt_done(stmt);

	stmt = db_query(
	    wallet->db,
	    "SELECT id, channel_htlc_id, msatoshi, cltv_expiry, hstate, "
	    "payment_hash, origin_htlc, payment_key, routing_onion FROM channel_htlcs WHERE "
	    "direction=%d AND channel_id=%" PRIu64 " AND hstate != %d",
	    DIRECTION_OUTGOING, chan->dbid, RCVD_REMOVE_ACK_REVOCATION);

	if (!stmt) {
		log_broken(wallet->log, "Could not select htlc_outs");
		return false;
	}

	while (ok && sqlite3_step(stmt) == SQLITE_ROW) {
		struct htlc_out *out = tal(chan, struct htlc_out);
		ok &= wallet_stmt2htlc_out(chan, stmt, out);
		connect_htlc_out(htlcs_out, out);
		/* Cannot htlc_out_check because we haven't wired the
		 * dependencies in yet */
		outcount++;
	}
	db_stmt_done(stmt);
	log_debug(wallet->log, "Restored %d incoming and %d outgoing HTLCS", incount, outcount);

	return ok;
}

bool wallet_htlcs_reconnect(struct wallet *wallet,
			    struct htlc_in_map *htlcs_in,
			    struct htlc_out_map *htlcs_out)
{
	struct htlc_in_map_iter ini;
	struct htlc_out_map_iter outi;
	struct htlc_in *hin;
	struct htlc_out *hout;

	for (hout = htlc_out_map_first(htlcs_out, &outi); hout;
	     hout = htlc_out_map_next(htlcs_out, &outi)) {

		if (hout->origin_htlc_id == 0) {
			continue;
		}

		for (hin = htlc_in_map_first(htlcs_in, &ini); hin;
		     hin = htlc_in_map_next(htlcs_in, &ini)) {
			if (hout->origin_htlc_id == hin->dbid) {
				log_debug(wallet->log,
					  "Found corresponding htlc_in %" PRIu64
					  " for htlc_out %" PRIu64,
					  hin->dbid, hout->dbid);
				hout->in = hin;
				break;
			}
		}

		if (!hout->in) {
			log_broken(
			    wallet->log,
			    "Unable to find corresponding htlc_in %"PRIu64" for htlc_out %"PRIu64,
			    hout->origin_htlc_id, hout->dbid);
		}

	}
	return true;
}

/* Almost all wallet_invoice_* functions delegate to the
 * appropriate invoices_* function. */
bool wallet_invoice_load(struct wallet *wallet)
{
	return invoices_load(wallet->invoices);
}
bool wallet_invoice_create(struct wallet *wallet,
			   struct invoice *pinvoice,
			   u64 *msatoshi TAKES,
			   const struct json_escaped *label TAKES,
			   u64 expiry,
			   const char *b11enc,
			   const char *description,
			   const struct preimage *r,
			   const struct sha256 *rhash)
{
	return invoices_create(wallet->invoices, pinvoice, msatoshi, label, expiry, b11enc, description, r, rhash);
}
bool wallet_invoice_find_by_label(struct wallet *wallet,
				  struct invoice *pinvoice,
				  const struct json_escaped *label)
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
void wallet_invoice_autoclean(struct wallet *wallet, u64 c, u64 e)
{
	invoices_autoclean_set(wallet->invoices, c, e);
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
			    u64 msatoshi_received)
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
	sqlite3_stmt *stmt = db_prepare(wallet->db,
		"SELECT channel_id, direction, cltv_expiry, payment_hash "
		"FROM channel_htlcs WHERE channel_id = ?;");

	sqlite3_bind_int64(stmt, 1, chan->dbid);

	stubs = tal_arr(ctx, struct htlc_stub, 0);

	while (sqlite3_step(stmt) == SQLITE_ROW) {
		int n = tal_count(stubs);
		tal_resize(&stubs, n+1);

		assert(sqlite3_column_int64(stmt, 0) == chan->dbid);

		/* FIXME: merge these two enums */
		stubs[n].owner = sqlite3_column_int(stmt, 1)==DIRECTION_INCOMING?REMOTE:LOCAL;
		stubs[n].cltv_expiry = sqlite3_column_int(stmt, 2);

		sqlite3_column_sha256(stmt, 3, &payment_hash);
		ripemd160(&stubs[n].ripemd, payment_hash.u.u8, sizeof(payment_hash.u));
	}
	db_stmt_done(stmt);
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
		int res;
		stmt = db_prepare(wallet->db,
				  "SELECT status FROM payments"
				  " WHERE payment_hash=?;");
		sqlite3_bind_sha256(stmt, 1, payment_hash);
		res = sqlite3_step(stmt);
		assert(res == SQLITE_ROW);
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
		"  description"
		") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);");

	sqlite3_bind_int(stmt, 1, payment->status);
	sqlite3_bind_sha256(stmt, 2, &payment->payment_hash);
	sqlite3_bind_pubkey(stmt, 3, &payment->destination);
	sqlite3_bind_int64(stmt, 4, payment->msatoshi);
	sqlite3_bind_int(stmt, 5, payment->timestamp);
	sqlite3_bind_blob(stmt, 6, payment->path_secrets,
				   tal_bytelen(payment->path_secrets),
				   SQLITE_TRANSIENT);
	sqlite3_bind_pubkey_array(stmt, 7, payment->route_nodes);
	sqlite3_bind_short_channel_id_array(stmt, 8,
					    payment->route_channels);
	sqlite3_bind_int64(stmt, 9, payment->msatoshi_sent);

	if (payment->description != NULL)
		sqlite3_bind_text(stmt, 10, payment->description,
				  strlen(payment->description),
				  SQLITE_TRANSIENT);
	else
		sqlite3_bind_null(stmt, 10);

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

	sqlite3_column_pubkey(stmt, 2, &payment->destination);
	payment->msatoshi = sqlite3_column_int64(stmt, 3);
	sqlite3_column_sha256(stmt, 4, &payment->payment_hash);

	payment->timestamp = sqlite3_column_int(stmt, 5);
	if (sqlite3_column_type(stmt, 6) != SQLITE_NULL) {
		payment->payment_preimage = tal(payment, struct preimage);
		sqlite3_column_preimage(stmt, 6, payment->payment_preimage);
	} else
		payment->payment_preimage = NULL;

	/* Can be NULL for old db! */
	payment->path_secrets = sqlite3_column_secrets(payment, stmt, 7);

	payment->route_nodes = sqlite3_column_pubkey_array(payment, stmt, 8);
	payment->route_channels
		= sqlite3_column_short_channel_id_array(payment, stmt, 9);

	payment->msatoshi_sent = sqlite3_column_int64(stmt, 10);

	if (sqlite3_column_type(stmt, 11) != SQLITE_NULL)
		payment->description = tal_strdup(
		    payment, (const char *)sqlite3_column_text(stmt, 11));
	else
		payment->description = NULL;

	return payment;
}

/* List of the fields that stmt2payment expects to correctly convert */
#define PAYMENT_FIELDS                                                         \
	"id, status, destination, msatoshi, payment_hash, timestamp, "         \
	"payment_preimage, path_secrets, route_nodes, route_channels, "        \
	"msatoshi_sent, description "

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

	stmt = db_prepare(wallet->db, "SELECT " PAYMENT_FIELDS " FROM payments "
				      "WHERE payment_hash = ?");

	sqlite3_bind_sha256(stmt, 1, payment_hash);
	if (sqlite3_step(stmt) == SQLITE_ROW) {
		payment = wallet_stmt2payment(ctx, stmt);
	}
	db_stmt_done(stmt);
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

	sqlite3_bind_int(stmt, 1, newstatus);
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
				 struct pubkey **failnode,
				 struct short_channel_id **failchannel,
				 u8 **failupdate,
				 char **faildetail)
{
	sqlite3_stmt *stmt;
	int res;
	bool resb;
	size_t len;

	stmt = db_prepare(wallet->db,
			  "SELECT failonionreply, faildestperm"
			  "     , failindex, failcode"
			  "     , failnode, failchannel"
			  "     , failupdate, faildetail"
			  "  FROM payments"
			  " WHERE payment_hash=?;");
	sqlite3_bind_sha256(stmt, 1, payment_hash);
	res = sqlite3_step(stmt);
	assert(res == SQLITE_ROW);
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
		*failnode = tal(ctx, struct pubkey);
		resb = sqlite3_column_pubkey(stmt, 4, *failnode);
		assert(resb);
	}
	if (sqlite3_column_type(stmt, 5) == SQLITE_NULL)
		*failchannel = NULL;
	else {
		*failchannel = tal(ctx, struct short_channel_id);
		resb = sqlite3_column_short_channel_id(stmt, 5, *failchannel);
		assert(resb);
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
				 const struct pubkey *failnode,
				 const struct short_channel_id *failchannel,
				 const u8 *failupdate /*tal_arr*/,
				 const char *faildetail)
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
		sqlite3_bind_pubkey(stmt, 5, failnode);
	else
		sqlite3_bind_null(stmt, 5);
	if (failchannel) {
		/* sqlite3_bind_short_channel_id requires the input
		 * channel to be tal-allocated... */
		struct short_channel_id *scid = tal(tmpctx, struct short_channel_id);
		*scid = *failchannel;
		sqlite3_bind_short_channel_id(stmt, 6, scid);
	} else
		sqlite3_bind_null(stmt, 6);
	if (failupdate)
		sqlite3_bind_blob(stmt, 7,
				  failupdate, tal_count(failupdate),
				  SQLITE_TRANSIENT);
	else
		sqlite3_bind_null(stmt, 7);
	sqlite3_bind_blob(stmt, 8,
			  faildetail, strlen(faildetail),
			  SQLITE_TRANSIENT);

	sqlite3_bind_sha256(stmt, 9, payment_hash);

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
		stmt = db_prepare(wallet->db,
				  "SELECT " PAYMENT_FIELDS " FROM payments "
				  "WHERE payment_hash = ?;");
		sqlite3_bind_sha256(stmt, 1, payment_hash);
	} else {
		stmt = db_prepare(wallet->db,
				  "SELECT " PAYMENT_FIELDS " FROM payments;");
	}

	for (i = 0; sqlite3_step(stmt) == SQLITE_ROW; i++) {
		tal_resize(&payments, i+1);
		payments[i] = wallet_stmt2payment(payments, stmt);
	}

	db_stmt_done(stmt);

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
	sqlite3_stmt *stmt = db_query(w->db,
				      "SELECT val FROM vars WHERE name='genesis_hash'");
	struct bitcoin_blkid chainhash;

	if (stmt && sqlite3_step(stmt) == SQLITE_ROW) {
		sqlite3_column_sha256_double(stmt, 0, &chainhash.shad);
		db_stmt_done(stmt);
		if (!bitcoin_blkid_eq(&chainhash,
				      &chainparams->genesis_blockhash)) {
			log_broken(w->log, "Wallet blockchain hash does not "
					   "match network blockchain hash: %s "
					   "!= %s. "
				           "Are you on the right network? "
				           "(--network={bitcoin,testnet})",
				   type_to_string(w, struct bitcoin_blkid,
						  &chainhash),
				   type_to_string(w, struct bitcoin_blkid,
						  &chainparams->genesis_blockhash));
			return false;
		}
	} else {
		/* Still a pristine wallet, claim it for the chain
		 * that we are running */
		db_stmt_done(stmt);
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

	stmt = db_prepare(w->db, "SELECT txid, outnum FROM utxoset WHERE spendheight < ?");
	sqlite3_bind_int(stmt, 1, blockheight - UTXO_PRUNE_DEPTH);

	while (sqlite3_step(stmt) == SQLITE_ROW) {
		sqlite3_column_sha256_double(stmt, 0, &txid.shad);
		outpointfilter_remove(w->utxoset_outpoints, &txid, sqlite3_column_int(stmt, 1));
	}
	db_stmt_done(stmt);

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

	stmt = db_prepare(w->db, "SELECT * FROM blocks WHERE height >= ?;");
	sqlite3_bind_int(stmt, 1, b->height);
	assert(sqlite3_step(stmt) == SQLITE_DONE);
	db_stmt_done(stmt);
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
	int res;
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
		stmt = db_prepare(w->db,
				  "SELECT blockheight, txindex "
				  "FROM utxoset "
				  "WHERE txid = ? AND outnum = ?");
		sqlite3_bind_sha256_double(stmt, 1, &txid->shad);
		sqlite3_bind_int(stmt, 2, outnum);

		res = sqlite3_step(stmt);
		assert(res == SQLITE_ROW);

		scid = tal(ctx, struct short_channel_id);
		mk_short_channel_id(scid, sqlite3_column_int(stmt, 0),
				    sqlite3_column_int(stmt, 1), outnum);
		db_stmt_done(stmt);
		return scid;
	}
	return NULL;
}

void wallet_utxoset_add(struct wallet *w, const struct bitcoin_tx *tx,
			const u32 outnum, const u32 blockheight,
			const u32 txindex, const u8 *scriptpubkey,
			const u64 satoshis)
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
	sqlite3_bind_int64(stmt, 7, satoshis);
	db_exec_prepared(w->db, stmt);

	outpointfilter_add(w->utxoset_outpoints, &txid, outnum);
}

struct outpoint *wallet_outpoint_for_scid(struct wallet *w, tal_t *ctx,
					  const struct short_channel_id *scid)
{
	sqlite3_stmt *stmt;
	struct outpoint *op;
	stmt = db_prepare(w->db, "SELECT"
			  " txid,"
			  " spendheight,"
			  " scriptpubkey,"
			  " satoshis "
			  "FROM utxoset "
			  "WHERE blockheight = ?"
			  " AND txindex = ?"
			  " AND outnum = ?");
	sqlite3_bind_int(stmt, 1, short_channel_id_blocknum(scid));
	sqlite3_bind_int(stmt, 2, short_channel_id_txnum(scid));
	sqlite3_bind_int(stmt, 3, short_channel_id_outnum(scid));


	if (sqlite3_step(stmt) != SQLITE_ROW) {
		db_stmt_done(stmt);
		return NULL;
	}

	op = tal(ctx, struct outpoint);
	op->blockheight = short_channel_id_blocknum(scid);
	op->txindex = short_channel_id_txnum(scid);
	op->outnum = short_channel_id_outnum(scid);
	sqlite3_column_sha256_double(stmt, 0, &op->txid.shad);
	op->spendheight = sqlite3_column_int(stmt, 1);
	op->scriptpubkey = tal_arr(op, u8, sqlite3_column_bytes(stmt, 2));
	memcpy(op->scriptpubkey, sqlite3_column_blob(stmt, 2), sqlite3_column_bytes(stmt, 2));
	op->satoshis = sqlite3_column_int64(stmt, 3);
	db_stmt_done(stmt);

	return op;
}

void wallet_transaction_add(struct wallet *w, const struct bitcoin_tx *tx,
			    const u32 blockheight, const u32 txindex)
{
	struct bitcoin_txid txid;
	sqlite3_stmt *stmt = db_prepare(w->db, "SELECT blockheight FROM transactions WHERE id=?");
	bool known;

	bitcoin_txid(tx, &txid);
	sqlite3_bind_sha256(stmt, 1, &txid.shad.sha);
	known = sqlite3_step(stmt) == SQLITE_ROW;
	db_stmt_done(stmt);

	if (!known) {
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
	} else if (blockheight){
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

u32 wallet_transaction_height(struct wallet *w, const struct bitcoin_txid *txid)
{
	u32 blockheight;
	sqlite3_stmt *stmt = db_prepare(
		w->db, "SELECT blockheight FROM transactions WHERE id=?");
	sqlite3_bind_sha256(stmt, 1, &txid->shad.sha);

	if (sqlite3_step(stmt) != SQLITE_ROW) {
		db_stmt_done(stmt);
		return 0;
	}

	blockheight = sqlite3_column_int(stmt, 0);
	db_stmt_done(stmt);
	return blockheight;
}

struct txlocator *wallet_transaction_locate(const tal_t *ctx, struct wallet *w,
					    const struct bitcoin_txid *txid)
{
	struct txlocator *loc;
	sqlite3_stmt *stmt;

	stmt = db_prepare(
	    w->db, "SELECT blockheight, txindex FROM transactions WHERE id=?");
	sqlite3_bind_sha256(stmt, 1, &txid->shad.sha);

	if (sqlite3_step(stmt) != SQLITE_ROW) {
		goto fail;

	}
	if (sqlite3_column_type(stmt, 0) == SQLITE_NULL)
		goto fail;

	loc = tal(ctx, struct txlocator);
	loc->blkheight = sqlite3_column_int(stmt, 0);
	loc->index = sqlite3_column_int(stmt, 1);
	db_stmt_done(stmt);
	return loc;

fail:
	db_stmt_done(stmt);
	return NULL;
}

struct bitcoin_txid *wallet_transactions_by_height(const tal_t *ctx,
						   struct wallet *w,
						   const u32 blockheight)
{
	sqlite3_stmt *stmt;
	struct bitcoin_txid *txids = tal_arr(ctx, struct bitcoin_txid, 0);
	int count = 0;
	stmt = db_prepare(
	    w->db, "SELECT id FROM transactions WHERE blockheight=?");
	sqlite3_bind_int(stmt, 1, blockheight);

	while (sqlite3_step(stmt) == SQLITE_ROW) {
		count++;
		tal_resize(&txids, count);
		sqlite3_column_sha256(stmt, 0, &txids[count-1].shad.sha);
	}
	db_stmt_done(stmt);

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
	stmt = db_prepare(w->db, "SELECT DISTINCT(channel_id) FROM channeltxs WHERE type = ?;");
	sqlite3_bind_int(stmt, 1, WIRE_ONCHAIN_INIT);

	while (sqlite3_step(stmt) == SQLITE_ROW) {
		count++;
		tal_resize(&channel_ids, count);
			channel_ids[count-1] = sqlite3_column_int64(stmt, 0);
	}
	db_stmt_done(stmt);

	return channel_ids;
}

struct channeltx *wallet_channeltxs_get(struct wallet *w, const tal_t *ctx,
					u32 channel_id)
{
	sqlite3_stmt *stmt;
	size_t count = 0;
	struct channeltx *res = tal_arr(ctx, struct channeltx, 0);
	stmt = db_prepare(w->db,
			  "SELECT"
			  "  c.type"
			  ", c.blockheight"
			  ", t.rawtx"
			  ", c.input_num"
			  ", c.blockheight - t.blockheight + 1 AS depth"
			  ", t.id as txid "
			  "FROM channeltxs c "
			  "JOIN transactions t ON t.id == c.transaction_id "
			  "WHERE channel_id = ? "
			  "ORDER BY c.id ASC;");
	sqlite3_bind_int(stmt, 1, channel_id);

	while (sqlite3_step(stmt) == SQLITE_ROW) {
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
	db_stmt_done(stmt);
	return res;
}
