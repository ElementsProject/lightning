#include "anchor.h"
#include "bitcoin/script.h"
#include "protobuf_convert.h"

#undef DEBUG
#ifdef DEBUG
#include <stdio.h>
#include "bitcoin/pubkey.h"

static void dump_anchor_spend(const char *what,
			      size_t input,
			      const struct pubkey *commitkey1,
			      const struct pubkey *commitkey2,
			      const struct pubkey *finalkey,
			      const struct sha256 *escapehash,
			      const struct pubkey *signingkey,
			      const struct signature *sig)
{
	size_t i;
	fprintf(stderr, "%s input %zu:", what, input);
	fprintf(stderr, " commitkey1=");
	for (i = 0; i < pubkey_len(commitkey1); i++)
		fprintf(stderr, "%02x", commitkey1->key[i]);
	fprintf(stderr, " commitkey2=");
	for (i = 0; i < pubkey_len(commitkey2); i++)
		fprintf(stderr, "%02x", commitkey2->key[i]);
	fprintf(stderr, " finalkey=");
	for (i = 0; i < pubkey_len(finalkey); i++)
		fprintf(stderr, "%02x", finalkey->key[i]);
	fprintf(stderr, " escapehash=");
	for (i = 0; i < sizeof(escapehash->u.u8); i++)
		fprintf(stderr, "%02x", escapehash->u.u8[i]);
	fprintf(stderr, " signingkey=");
	for (i = 0; i < pubkey_len(signingkey); i++)
		fprintf(stderr, "%02x", signingkey->key[i]);
	fprintf(stderr, " -> sig {r=");
	for (i = 0; i < sizeof(sig->r); i++)
		fprintf(stderr, "%02x", sig->r[i]);
	fprintf(stderr, ", s=");
	for (i = 0; i < sizeof(sig->s); i++)
		fprintf(stderr, "%02x", sig->s[i]);
	fprintf(stderr, "}\n");
}
#else
static void dump_anchor_spend(const char *what,
			      size_t input,
			      const struct pubkey *commitkey1,
			      const struct pubkey *commitkey2,
			      const struct pubkey *finalkey,
			      const struct sha256 *escapehash,
			      const struct pubkey *signingkey,
			      const struct signature *sig)
{
}
#endif

bool sign_anchor_spend(struct bitcoin_tx *tx,
		       const size_t inmap[2],
		       const struct pubkey *my_commitkey,
		       const struct pubkey *my_finalkey,
		       const struct sha256 *my_escapehash,
		       const struct pubkey *their_commitkey,
		       const struct pubkey *their_finalkey,
		       const struct sha256 *their_escapehash,
		       const struct pubkey *signing_pubkey,
		       const struct privkey *signing_privkey,
		       struct signature sig[2])
{
	const tal_t *ctx = tal(NULL, char);
	u8 *redeemscript;
	bool ret;

	/* Sign input for our anchor. */
	redeemscript = bitcoin_redeem_anchor(ctx, my_commitkey, their_commitkey,
					     their_finalkey, my_escapehash);
	ret = sign_tx_input(ctx, tx, inmap[0],
			    redeemscript, tal_count(redeemscript),
			    signing_privkey, signing_pubkey, &sig[inmap[0]]);
	dump_anchor_spend("signed from_mine", inmap[0],
			  my_commitkey, their_commitkey, their_finalkey,
			  my_escapehash, signing_pubkey, &sig[inmap[0]]);

	/* Sign input for their anchor. */
	redeemscript = bitcoin_redeem_anchor(ctx, their_commitkey, my_commitkey,
					     my_finalkey, their_escapehash);
	ret &= sign_tx_input(ctx, tx, inmap[1],
			     redeemscript, tal_count(redeemscript),
			     signing_privkey, signing_pubkey, &sig[inmap[1]]);

	dump_anchor_spend("signed from_yours", inmap[1],
			  their_commitkey, my_commitkey, my_finalkey,
			  their_escapehash, signing_pubkey, &sig[inmap[1]]);
	tal_free(ctx);
	return ret;
}

/* Check that their sigs sign this tx as expected. */
bool check_anchor_spend(struct bitcoin_tx *tx,
			const size_t inmap[2],
			const struct pubkey *my_commitkey,
			const struct pubkey *my_finalkey,
			const struct sha256 *my_escapehash,
			const struct pubkey *their_commitkey,
			const struct pubkey *their_finalkey,
			const struct sha256 *their_escapehash,
			const struct pubkey *signing_pubkey,
			const AnchorSpend *their_sigs)
{
	const tal_t *ctx;
	u8 *redeemscript;
	bool ret;
	struct bitcoin_signature sigs[2];

	sigs[0].stype = sigs[1].stype = SIGHASH_ALL;

	if (!proto_to_signature(their_sigs->sig0, &sigs[0].sig)
	    || !proto_to_signature(their_sigs->sig1, &sigs[1].sig))
		return false;

	ctx = tal(NULL, char);

	/* Input for our anchor. */
	redeemscript = bitcoin_redeem_anchor(ctx, my_commitkey, their_commitkey,
					     their_finalkey, my_escapehash);
	ret = check_tx_sig(tx, inmap[0], redeemscript, tal_count(redeemscript),
			   signing_pubkey, &sigs[inmap[0]]);

	dump_anchor_spend("checking from_mine", inmap[0],
			  my_commitkey, their_commitkey, their_finalkey,
			  my_escapehash, signing_pubkey, &sigs[inmap[0]].sig);

	/* Input for their anchor. */
	redeemscript = bitcoin_redeem_anchor(ctx, their_commitkey, my_commitkey,
					     my_finalkey, their_escapehash);
	ret &= check_tx_sig(tx, inmap[1], redeemscript, tal_count(redeemscript),
			    signing_pubkey, &sigs[inmap[1]]);

	dump_anchor_spend("checking from_yours", inmap[1],
			  their_commitkey, my_commitkey, my_finalkey,
			  their_escapehash, signing_pubkey, &sigs[inmap[1]].sig);

	tal_free(ctx);
	return ret;
}

/* Set up input scriptsigs for this transaction. */
bool populate_anchor_inscripts(const tal_t *ctx,
			       struct bitcoin_tx *tx,
			       const size_t inmap[2],
			       const struct pubkey *my_commitkey,
			       const struct pubkey *my_finalkey,
			       const struct sha256 *my_escapehash,
			       const struct pubkey *their_commitkey,
			       const struct pubkey *their_finalkey,
			       const struct sha256 *their_escapehash,
			       const AnchorSpend *my_sigs,
			       const AnchorSpend *their_sigs)
{
	u8 *redeemscript;
	struct bitcoin_signature theirs[2], mine[2];

	theirs[0].stype = theirs[1].stype = mine[0].stype = mine[1].stype
		= SIGHASH_ALL;

	if (!proto_to_signature(their_sigs->sig0, &theirs[0].sig)
	    || !proto_to_signature(their_sigs->sig1, &theirs[1].sig)
	    || !proto_to_signature(my_sigs->sig0, &mine[0].sig)
	    || !proto_to_signature(my_sigs->sig1, &mine[1].sig))
		return false;

	/* Input for our anchor. */
	redeemscript = bitcoin_redeem_anchor(ctx, my_commitkey, their_commitkey,
					     their_finalkey, my_escapehash);

	tx->input[inmap[0]].script
		= scriptsig_p2sh_anchor_commit(ctx,
					       &theirs[inmap[0]],
					       &mine[inmap[0]],
					       redeemscript,
					       tal_count(redeemscript));
	tal_free(redeemscript);

	/* Input for their anchor. */
	redeemscript = bitcoin_redeem_anchor(ctx, their_commitkey, my_commitkey,
					     my_finalkey, their_escapehash);
	/* They created their anchor to expect sigs in other order. */
	tx->input[inmap[1]].script
		= scriptsig_p2sh_anchor_commit(ctx,
					       &mine[inmap[1]],
					       &theirs[inmap[1]],
					       redeemscript,
					       tal_count(redeemscript));
	tal_free(redeemscript);

	/* Set up lengths. */
	tx->input[0].script_length = tal_count(tx->input[0].script);
	tx->input[1].script_length = tal_count(tx->input[1].script);

	return true;
}
