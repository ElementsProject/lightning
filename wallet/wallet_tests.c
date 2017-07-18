#include "wallet.c"

#include "db.c"
#include "wallet/test_utils.h"

#include <stdio.h>
#include <unistd.h>

static bool test_wallet_outputs(void)
{
	char filename[] = "/tmp/ldb-XXXXXX";
	struct utxo u;
	int fd = mkstemp(filename);
	struct wallet *w = tal(NULL, struct wallet);
	CHECK_MSG(fd != -1, "Unable to generate temp filename");
	close(fd);

	w->db = db_open(w, filename);
	CHECK_MSG(w->db, "Failed opening the db");
	CHECK_MSG(db_migrate(w->db), "DB migration failed");

	memset(&u, 0, sizeof(u));

	/* Should work, it's the first time we add it */
	CHECK_MSG(wallet_add_utxo(w, &u, p2sh_wpkh),
		  "wallet_add_utxo failed on first add");

	/* Should fail, we already have that UTXO */
	CHECK_MSG(!wallet_add_utxo(w, &u, p2sh_wpkh),
		  "wallet_add_utxo succeeded on second add");

	/* Attempt to reserve the utxo */
	CHECK_MSG(wallet_update_output_status(w, &u.txid, u.outnum,
					      output_state_available,
					      output_state_reserved),
		  "could not reserve available output");

	/* Reserving twice should fail */
	CHECK_MSG(!wallet_update_output_status(w, &u.txid, u.outnum,
					       output_state_available,
					       output_state_reserved),
		  "could reserve already reserved output");

	/* Un-reserving should work */
	CHECK_MSG(wallet_update_output_status(w, &u.txid, u.outnum,
					      output_state_reserved,
					      output_state_available),
		  "could not unreserve reserved output");

	/* Switching from any to something else */
	CHECK_MSG(wallet_update_output_status(w, &u.txid, u.outnum,
					      output_state_any,
					      output_state_spent),
		  "could not change output state ignoring oldstate");

	tal_free(w);
	return true;
}

static bool test_shachain_crud(void)
{
	struct wallet_shachain a, b;
	char filename[] = "/tmp/ldb-XXXXXX";
	int fd = mkstemp(filename);
	struct wallet *w = tal(NULL, struct wallet);
	struct sha256 seed, hash;
	shachain_index_t index = UINT64_MAX >> (64 - SHACHAIN_BITS);

	w->db = db_open(w, filename);
	CHECK_MSG(w->db, "Failed opening the db");
	CHECK_MSG(db_migrate(w->db), "DB migration failed");

	CHECK_MSG(fd != -1, "Unable to generate temp filename");
	close(fd);
	memset(&seed, 'A', sizeof(seed));

	memset(&a, 0, sizeof(a));
	memset(&b, 0, sizeof(b));

	w->db = db_open(w, filename);
	CHECK(wallet_shachain_init(w, &a));

	CHECK(a.id == 1);

	CHECK(a.chain.num_valid == 0 && a.chain.min_index == 0);

	for (int i=0; i<100; i++) {
		shachain_from_seed(&seed, index, &hash);
		CHECK(wallet_shachain_add_hash(w, &a, index, &hash));
		index--;
	}

	CHECK(wallet_shachain_load(w, a.id, &b));
	CHECK_MSG(memcmp(&a, &b, sizeof(a)) == 0, "Loading from database doesn't match");
	tal_free(w);
	return true;
}

int main(void)
{
	bool ok = true;

	ok &= test_wallet_outputs();
	ok &= test_shachain_crud();

	return !ok;
}
