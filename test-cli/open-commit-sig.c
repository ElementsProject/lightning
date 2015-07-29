#include <ccan/crypto/shachain/shachain.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <ccan/opt/opt.h>
#include <ccan/str/hex/hex.h>
#include <ccan/err/err.h>
#include <ccan/read_write_all/read_write_all.h>
#include "lightning.pb-c.h"
#include "anchor.h"
#include "bitcoin/base58.h"
#include "pkt.h"
#include "bitcoin/script.h"
#include "permute_tx.h"
#include "bitcoin/signature.h"
#include "commit_tx.h"
#include "bitcoin/pubkey.h"
#include "bitcoin/privkey.h"
#include "protobuf_convert.h"
#include <unistd.h>

int main(int argc, char *argv[])
{
	const tal_t *ctx = tal_arr(NULL, char, 0);
	OpenChannel *o1, *o2;
	struct bitcoin_tx *anchor, *commit;
	struct sha256_double txid;
	struct pkt *pkt;
	struct signature sig;
	size_t *inmap, *outmap;
	struct privkey privkey;
	bool testnet;
	struct pubkey pubkey1, pubkey2;
	u8 *subscript;
	struct sha256 rhash;

	err_set_progname(argv[0]);

	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "<open-channel-file1> <open-channel-file2> <commit-privkey>\n"
			   "Create the signature needed for the commit transaction",
			   "Print this message.");

 	opt_parse(&argc, argv, opt_log_stderr_exit);

	if (argc != 4)
		opt_usage_exit_fail("Expected 3 arguments");

	o1 = pkt_from_file(argv[1], PKT__PKT_OPEN)->open;
	o2 = pkt_from_file(argv[2], PKT__PKT_OPEN)->open;

	if (!key_from_base58(argv[3], strlen(argv[3]), &testnet, &privkey, &pubkey1))
		errx(1, "Invalid private key '%s'", argv[3]);
	if (!testnet)
		errx(1, "Private key '%s' not on testnet!", argv[3]);

	/* Create merged anchor transaction */
	anchor = anchor_tx_create(ctx, o1, o2, &inmap, &outmap);
	if (!anchor)
		errx(1, "Failed transaction merge");

	/* Get the transaction ID of the anchor. */
	anchor_txid(anchor, &txid);

	/* Now create THEIR commitment tx to spend 2/2 output of anchor. */
	proto_to_sha256(o2->revocation_hash, &rhash);
	commit = create_commit_tx(ctx, o2, o1, &rhash, 0, &txid, outmap[0]);

	/* If contributions don't exceed fees, this fails. */
	if (!commit)
		errx(1, "Contributions %llu & %llu vs fees %llu & %llu",
		     (long long)o1->anchor->total,
		     (long long)o2->anchor->total,
		     (long long)o1->commitment_fee,
		     (long long)o2->commitment_fee);

	/* Their pubkey must be valid */
	if (!proto_to_pubkey(o2->commit_key, &pubkey2))
		errx(1, "Invalid public open-channel-file2");

	/* Sign it for them. */
	subscript = bitcoin_redeem_2of2(ctx, &pubkey1, &pubkey2);
	sign_tx_input(ctx, commit, 0, subscript, tal_count(subscript),
		      &privkey, &pubkey1, &sig);

	pkt = open_commit_sig_pkt(ctx, &sig);
	if (!write_all(STDOUT_FILENO, pkt, pkt_totlen(pkt)))
		err(1, "Writing out packet");

	tal_free(ctx);
	return 0;
}

