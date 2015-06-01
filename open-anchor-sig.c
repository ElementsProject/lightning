/* My example:
 * ./open-anchor-sig A-open.pb B-open.pb cUjoranStkpgTRumAJZNiNEkknJv5UA7wzW1nZ7aPsm9ZWjkxypZ > A-anchor-scriptsigs.pb
 * ./open-anchor-sig B-open.pb A-open.pb cNggXygY8fPHWHEdoDqRa6xALau8gVMLq6q6vzMs2eNegLrJGNAW > B-anchor-scriptsigs.pb
 */
#include <ccan/err/err.h>
#include <ccan/opt/opt.h>
#include <ccan/read_write_all/read_write_all.h>
#include "bitcoin_tx.h"
#include "signature.h"
#include "lightning.pb-c.h"
#include "pkt.h"
#include "bitcoin_script.h"
#include "bitcoin_address.h"
#include "base58.h"
#include "anchor.h"

#include <openssl/ec.h>
#include <unistd.h>

/* All the input scripts are already set to 0.  We just need to make this one. */
static u8 *tx_scriptsig(const tal_t *ctx,
			struct bitcoin_tx *tx,
			unsigned int i,
			const BitcoinInput *input,
			EC_KEY *privkey,
			const struct bitcoin_compressed_pubkey *pubkey)
{
	struct signature *sig;
	struct bitcoin_address addr;

	sig = sign_tx_input(ctx, tx, i,
			    input->subscript.data, input->subscript.len,
			    privkey);
	if (!sig)
		return NULL;

	if (!is_pay_to_pubkey_hash(&input->subscript))
		errx(1, "FIXME: Don't know how to handle input");
	bitcoin_address(pubkey, &addr);
	return scriptsig_pay_to_pubkeyhash(ctx, &addr, sig);
}
	
int main(int argc, char *argv[])
{
	OpenChannel *o1, *o2;
	const tal_t *ctx = tal_arr(NULL, char, 0);
	struct bitcoin_tx *anchor;
	struct pkt *pkt;
	size_t i;
	u8 **sigs;
	size_t *map;

	err_set_progname(argv[0]);

	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "<open-channel-file1> <open-channel-file2> <privkey>...\n"
			   "Create signatures for transactions, and output to stdout",
			   "Print this message.");

 	opt_parse(&argc, argv, opt_log_stderr_exit);

	if (argc < 3)
		opt_usage_and_exit(NULL);

	o1 = pkt_from_file(argv[1], PKT__PKT_OPEN)->open;
	o2 = pkt_from_file(argv[2], PKT__PKT_OPEN)->open;

	/* Create merged transaction */
	anchor = anchor_tx_create(ctx, o1, o2, &map, NULL);
	if (!anchor)
		errx(1, "Failed transaction merge");

	/* Sign our inputs. */
	if (o1->anchor->n_inputs != argc - 3)
		errx(1, "Expected %zu private keys", o1->anchor->n_inputs);

	sigs = tal_arr(ctx, u8 *, o1->anchor->n_inputs);
	for (i = 0; i < o1->anchor->n_inputs; i++) {
		/* FIXME: Support non-compressed keys? */
		struct bitcoin_compressed_pubkey pubkey;
		EC_KEY *privkey;
		bool testnet;

		privkey = key_from_base58(argv[3+i], strlen(argv[3+i]),
					  &testnet, &pubkey);
		if (!privkey)
			errx(1, "Invalid private key '%s'", argv[3+i]);
		if (!testnet)
			errx(1, "Private key '%s' not on testnet!", argv[3+i]);
		
		sigs[i] = tx_scriptsig(sigs, anchor, map[i],
				       o1->anchor->inputs[i],
				       privkey, &pubkey);
	}

	pkt = open_anchor_sig_pkt(ctx, sigs, o1->anchor->n_inputs);
	if (!write_all(STDOUT_FILENO, pkt,
		       sizeof(pkt->len) + le32_to_cpu(pkt->len)))
		err(1, "Writing out packet");

	tal_free(ctx);
	return 0;
}
