#ifndef LIGHTNING_ANCHOR_H
#define LIGHTNING_ANCHOR_H
#include <ccan/tal/tal.h>
#include "bitcoin/signature.h"
#include "bitcoin/tx.h"
#include "lightning.pb-c.h"

/* Sign this transaction which spends the anchors. */
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
		       struct signature sig[2]);

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
			const AnchorSpend *their_sigs);

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
			       const AnchorSpend *their_sigs);
#endif /* LIGHTNING_ANCHOR_H */
