#include "config.h"
#include <assert.h>
#include <bitcoin/privkey.h>
#include <bitcoin/script.h>
#include <bitcoin/short_channel_id.h>
#include <ccan/crypto/hkdf_sha256/hkdf_sha256.h>
#include <ccan/err/err.h>
#include <ccan/mem/mem.h>
#include <ccan/opt/opt.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/tal/path/path.h>
#include <common/configdir.h>
#include <common/node_id.h>
#include <inttypes.h>
#include <sqlite3.h>

static void hsm_channel_secret_base(struct secret *channel_seed_base,
				    const struct secret *hsm_secret)
{
	hkdf_sha256(channel_seed_base, sizeof(struct secret), NULL, 0,
		    hsm_secret, sizeof(*hsm_secret),
		    /*~ Initially, we didn't support multiple channels per
		     * peer at all: a channel had to be completely forgotten
		     * before another could exist.  That was slightly relaxed,
		     * but the phrase "peer seed" is wired into the seed
		     * generation here, so we need to keep it that way for
		     * existing clients, rather than using "channel seed". */
		    "peer seed", strlen("peer seed"));
}

static void get_channel_seed(const struct secret *hsm_secret,
			     const struct node_id *peer_id, u64 dbid,
			     struct secret *channel_seed)
{
	struct secret channel_base;
	u8 input[sizeof(peer_id->k) + sizeof(dbid)];
	/*~ Again, "per-peer" should be "per-channel", but Hysterical Raisins */
	const char *info = "per-peer seed";

	/*~ We use the DER encoding of the pubkey, because it's platform
	 * independent.  Since the dbid is unique, however, it's completely
	 * unnecessary, but again, existing users can't be broken. */
	/* FIXME: lnd has a nicer BIP32 method for deriving secrets which we
	 * should migrate to. */
	hsm_channel_secret_base(&channel_base, hsm_secret);
	memcpy(input, peer_id->k, sizeof(peer_id->k));
	BUILD_ASSERT(sizeof(peer_id->k) == PUBKEY_CMPR_LEN);
	/*~ For all that talk about platform-independence, note that this
	 * field is endian-dependent!  But let's face it, little-endian won.
	 * In related news, we don't support EBCDIC or middle-endian. */
	memcpy(input + PUBKEY_CMPR_LEN, &dbid, sizeof(dbid));

	hkdf_sha256(channel_seed, sizeof(*channel_seed),
		    input, sizeof(input),
		    &channel_base, sizeof(channel_base),
		    info, strlen(info));
}

struct keys {
	struct privkey f, r, h, p, d;
	struct sha256 shaseed;
};

static void derive_keys(const struct secret *seed, struct keys *keys)
{
	hkdf_sha256(keys, sizeof(*keys), NULL, 0, seed, sizeof(*seed),
		    "c-lightning", strlen("c-lightning"));
}

static void derive_funding_key(const struct secret *hsm_secret,
			       const struct node_id *peer_id, u64 dbid,
			       struct pubkey *funding_pubkey)
{
	struct secret channel_seed;
	struct keys keys;

	get_channel_seed(hsm_secret, peer_id, dbid, &channel_seed);
	derive_keys(&channel_seed, &keys);

	if (!pubkey_from_privkey(&keys.f, funding_pubkey))
		abort();
}

static void sqlite3_column_pubkey(struct sqlite3_stmt *stmt, int pos, struct pubkey *dest)
{
	bool ok;
	assert(sqlite3_column_bytes(stmt, pos) == PUBKEY_CMPR_LEN);
	ok = pubkey_from_der(sqlite3_column_blob(stmt, pos), PUBKEY_CMPR_LEN, dest);
	assert(ok);
}

static void sqlite3_column_short_channel_id(struct sqlite3_stmt *stmt,
					    int pos,
					    struct short_channel_id *dest)
{
	const char *source = sqlite3_column_blob(stmt, pos);
	size_t sourcelen = sqlite3_column_bytes(stmt, pos);
	if (!short_channel_id_from_str(source, sourcelen, dest))
		abort();
}

static void copy_column(void *dst, size_t size,
			struct sqlite3_stmt *stmt,
			int pos)
{
	assert(sqlite3_column_bytes(stmt, pos) == size);
	memcpy(dst, sqlite3_column_blob(stmt, pos), size);
}

int main(int argc, char *argv[])
{
	char *config_filename, *base_dir;
	char *net_dir, *rpc_filename, *hsmfile, *dbfile;
	sqlite3 *sql;
	sqlite3_stmt *stmt;
	int flags = SQLITE_OPEN_READONLY, dberr;
	struct secret *hsm_secret;
	bool verbose = false;
	size_t num, num_ok;
	const tal_t *top_ctx = tal(NULL, char);

	setup_locale();
	wally_init(0);
	secp256k1_ctx = wally_get_secp_context();

	setup_option_allocators();

	minimal_config_opts(top_ctx, argc, argv, &config_filename, &base_dir,
			    &net_dir, &rpc_filename);

	opt_register_noarg("-v|--verbose", opt_set_bool, &verbose,
			 "Print everything");

	opt_parse(&argc, argv, opt_log_stderr_exit);

	if (argc != 1)
		errx(1, "no arguments accepted");

	hsmfile = path_join(top_ctx, net_dir, "hsm_secret");
	dbfile = path_join(top_ctx, net_dir, "lightningd.sqlite3");

	dberr = sqlite3_open_v2(dbfile, &sql, flags, NULL);
	if (dberr != SQLITE_OK)
		errx(1, "failed to open database %s: %s", dbfile,
			 sqlite3_errstr(dberr));

	hsm_secret = grab_file(hsmfile, hsmfile);
	if (!hsm_secret)
		err(1, "failed to read %s", hsmfile);

	dberr = sqlite3_prepare_v2(sql,
				   "SELECT channels.id, peers.node_id, channels.short_channel_id, channels.funding_tx_id, channels.funding_tx_outnum, channels.funding_satoshi, channels.fundingkey_remote, utxoset.scriptpubkey, utxoset.satoshis FROM channels INNER JOIN peers ON channels.peer_id = peers.id LEFT JOIN utxoset on channels.funding_tx_id = utxoset.txid AND channels.funding_tx_outnum = utxoset.outnum;", -1, &stmt, NULL); /* Raw: false positive! */
	if (dberr != SQLITE_OK)
		errx(1, "failed to prepare query for %s: %s", dbfile,
			 sqlite3_errstr(dberr));

	num = num_ok = 0;
	while ((dberr = sqlite3_step(stmt)) == SQLITE_ROW) {
		u64 dbid;
		struct node_id peer_id;
		struct short_channel_id scid;
		struct bitcoin_txid funding_txid;
		u32 funding_outnum;
		u64 funding_satoshis;
		struct pubkey remote_fundingkey, local_fundingkey;
		u8 *scriptpubkey;
		u64 utxo_satoshis;
		const tal_t *ctx = tal(dbfile, char);
		char txid_hex[65];
		u8 *wscript, *expect_scriptpubkey;

		num++;

		dbid = sqlite3_column_int64(stmt, 0);
		copy_column(&peer_id, sizeof(peer_id), stmt, 1);
		sqlite3_column_short_channel_id(stmt, 2, &scid);
		copy_column(&funding_txid, sizeof(funding_txid), stmt, 3);
		if (!bitcoin_txid_to_hex(&funding_txid,
					 txid_hex, sizeof(txid_hex)))
			abort();
		funding_outnum = sqlite3_column_int(stmt, 4);
		funding_satoshis = sqlite3_column_int64(stmt, 5);
		sqlite3_column_pubkey(stmt, 6, &remote_fundingkey);

		printf("Channel %s with peer %s: funding %s/%u: ",
			     fmt_short_channel_id(ctx, scid),
			     fmt_node_id(ctx, &peer_id),
			     txid_hex, funding_outnum);
		fflush(stdout);

		/* UTXO DNE */
		if (sqlite3_column_type(stmt, 7) == SQLITE_NULL) {
			printf("*** FATAL *** unknown funding output\n");
			continue;
		}

		scriptpubkey = tal_dup_arr(ctx, u8,
					   sqlite3_column_blob(stmt, 7),
					   sqlite3_column_bytes(stmt, 7), 0);
		utxo_satoshis = sqlite3_column_int64(stmt, 8);

		derive_funding_key(hsm_secret, &peer_id, dbid,
				   &local_fundingkey);

		wscript = bitcoin_redeem_2of2(ctx, &local_fundingkey, &remote_fundingkey);
		expect_scriptpubkey = scriptpubkey_p2wsh(ctx, wscript);

		if (!tal_arr_eq(expect_scriptpubkey, scriptpubkey)) {
			printf("*** FATAL *** outscript %s should be %s\n",
			       tal_hex(ctx, scriptpubkey),
			       tal_hex(ctx, expect_scriptpubkey));
			continue;
		}

		if (utxo_satoshis != funding_satoshis) {
			printf("*** FATAL *** amount %"PRIu64" should be %"PRIu64,
			       funding_satoshis, utxo_satoshis);
			continue;
		}
		if (verbose)
			printf("scriptpubkey = %s, expected %s,"
			       " amount = %"PRIu64", expected %"PRIu64": ",
			       tal_hex(ctx, scriptpubkey),
			       tal_hex(ctx, expect_scriptpubkey),
			       funding_satoshis, utxo_satoshis);
		printf("OK\n");
		num_ok++;
		tal_free(ctx);
	}
	if (dberr != SQLITE_DONE)
		errx(1, "failed iterating database: %s",
		     sqlite3_errstr(dberr));

	if (num_ok == num)
		printf("\nCheck passed!\n");
	else
		errx(1, "%zu channels incorrect.", num - num_ok);
	tal_free(top_ctx);
}
