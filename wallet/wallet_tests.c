#include "wallet.c"

#include "db.c"
#include "wallet/test_utils.h"

#include <stdio.h>
#include <unistd.h>

static bool test_wallet_add_utxo(void)
{
	char filename[] = "/tmp/ldb-XXXXXX";
	struct utxo u;
	int fd = mkstemp(filename);
	struct wallet *w = tal(NULL, struct wallet);
	CHECK_MSG(fd != -1, "Unable to generate temp filename");
	close(fd);

	w->db = db_open(w, filename);
	CHECK_MSG(w->db,"Failed opening the db");
	CHECK_MSG(db_migrate(w->db), "DB migration failed");
		
	memset(&u, 0, sizeof(u));

	/* Should work, it's the first time we add it */
	CHECK_MSG(wallet_add_utxo(w, &u, p2sh_wpkh), "wallet_add_utxo failed on first add");

	/* Should fail, we already have that UTXO */
	CHECK_MSG(!wallet_add_utxo(w, &u, p2sh_wpkh), "wallet_add_utxo succeeded on second add");
	tal_free(w);
	return true;

}

int main(void)
{
	bool ok = true;

	ok &= test_wallet_add_utxo();

	return !ok;
}
