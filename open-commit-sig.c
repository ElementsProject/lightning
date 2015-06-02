/* My example:
 * ./open-commit-sig A-open.pb B-open.pb cUBCjrdJu8tfvM7FT8So6aqs6G6bZS1Cax6Rc9rFzYL6nYG4XNEC A-leak-anchor-sigs.pb B-leak-anchor-sigs.pb > A-commit-sig.pb
 * ./open-commit-sig B-open.pb A-open.pb cQXhbUnNRsFcdzTQwjbCrud5yVskHTEas7tZPUWoJYNk5htGQrpi B-leak-anchor-sigs.pb A-leak-anchor-sigs.pb > B-commit-sig.pb
 */
#include <ccan/crypto/shachain/shachain.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <ccan/opt/opt.h>
#include <ccan/str/hex/hex.h>
#include <ccan/err/err.h>
#include <ccan/read_write_all/read_write_all.h>
#include "lightning.pb-c.h"
#include "anchor.h"
#include "base58.h"
#include "pkt.h"
#include "bitcoin_script.h"
#include "permute_tx.h"
#include "signature.h"
#include "commit_tx.h"
#include "pubkey.h"
#include <openssl/ec.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
	const tal_t *ctx = tal_arr(NULL, char, 0);
	OpenChannel *o1, *o2;
	struct bitcoin_tx *anchor, *commit;
	struct sha256_double txid;
	struct pkt *pkt;
	struct signature *sig;
	size_t *inmap, *outmap;
	EC_KEY *privkey;
	bool testnet;
	struct pubkey pubkey;

	err_set_progname(argv[0]);

	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "<open-channel-file1> <open-channel-file2> <commit-privkey> <leak-anchor-sigs1> <leak-anchor-sigs2>\n"
			   "Create the signature needed for the commit transaction",
			   "Print this message.");

 	opt_parse(&argc, argv, opt_log_stderr_exit);

	if (argc != 6)
		opt_usage_and_exit(NULL);

	o1 = pkt_from_file(argv[1], PKT__PKT_OPEN)->open;
	o2 = pkt_from_file(argv[2], PKT__PKT_OPEN)->open;

	privkey = key_from_base58(argv[3], strlen(argv[3]), &testnet, &pubkey);
	if (!privkey)
		errx(1, "Invalid private key '%s'", argv[3]);
	if (!testnet)
		errx(1, "Private key '%s' not on testnet!", argv[3]);

	/* Create merged anchor transaction */
	anchor = anchor_tx_create(ctx, o1, o2, &inmap, &outmap);
	if (!anchor)
		errx(1, "Failed transaction merge");

	/* Get the transaction ID of the anchor. */
	anchor_txid(anchor, argv[4], argv[5], inmap, &txid);

	/* Now create commitment tx to spend 2/2 output of anchor. */
	commit = create_commit_tx(ctx, o1, o2, &txid, outmap[0]);

	/* If contributions don't exceed fees, this fails. */
	if (!commit)
		errx(1, "Contributions %llu & %llu vs fees %llu & %llu",
		     (long long)o1->anchor->total,
		     (long long)o2->anchor->total,
		     (long long)o1->commitment_fee,
		     (long long)o2->commitment_fee);

	sig = sign_tx_input(ctx, commit, 0, anchor->output[outmap[0]].script,
			    anchor->output[outmap[0]].script_length, privkey);

	pkt = open_commit_sig_pkt(ctx, sig);
	if (!write_all(STDOUT_FILENO, pkt,
		       sizeof(pkt->len) + le32_to_cpu(pkt->len)))
		err(1, "Writing out packet");

	tal_free(ctx);
	return 0;
}

