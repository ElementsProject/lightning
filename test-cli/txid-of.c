#include <ccan/crypto/shachain/shachain.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <ccan/opt/opt.h>
#include <ccan/str/hex/hex.h>
#include <ccan/err/err.h>
#include "bitcoin/tx.h"
#include "version.h"
#include "tx_from_file.h"
#include <unistd.h>

int main(int argc, char *argv[])
{
	const tal_t *ctx = tal_arr(NULL, char, 0);
	struct bitcoin_tx *tx;
	struct sha256_double txid;
	char str[hex_str_size(sizeof(txid))];

	err_set_progname(argv[0]);

	/* FIXME: Take update.pbs to adjust channel */
	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "<tx>\n"
			   "Print txid of the transaction in the file",
			   "Print this message.");
	opt_register_version();

 	opt_parse(&argc, argv, opt_log_stderr_exit);

	if (argc != 2)
		opt_usage_exit_fail("Expected 1 argument");

	tx = bitcoin_tx_from_file(ctx, argv[1]);
	bitcoin_txid(tx, &txid);

	if (!bitcoin_txid_to_hex(&txid, str, sizeof(str)))
		abort();

	/* Print it out. */
	if (!write_all(STDOUT_FILENO, str, strlen(str)))
		err(1, "Writing out txid");

	tal_free(ctx);
	return 0;
}
