#include <ccan/err/err.h>
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/structeq/structeq.h>
#include "test-cli/gather_updates.h"
#include "commit_tx.h"
#include "funding.h"
#include "pkt.h"
#include "protobuf_convert.h"

static void check_preimage(const Sha256Hash *preimage,
			   const struct sha256 *old,
			   const struct sha256 *h,
			   const char *file)
{
	struct sha256 sha;

	if (!h)
		return;

	proto_to_sha256(preimage, &sha);
	sha256(&sha, &sha, sizeof(sha));
	if (!structeq(&sha, old))
		errx(1, "Invalid preimage in %s!", file);
}

static void get_rhash(const Sha256Hash *rhash, struct sha256 *old,
		      struct sha256 *new)
{
	if (new) {
		*old = *new;
		proto_to_sha256(rhash, new);
	}
}

/* Takes complete update history, gets summary of last state. */
struct channel_state *gather_updates(const tal_t *ctx,
			const OpenChannel *o1, const OpenChannel *o2,
			const OpenAnchor *oa, uint64_t fee,
			char **argv,
			size_t *num_updates,
			struct sha256 *our_rhash,
			struct sha256 *their_rhash,
			struct signature *their_commit_sig)
{
	Signature *sig = NULL;
	struct sha256 old_our_rhash, old_their_rhash;
	struct channel_state *cstate;
	
	/* Start sanity check. */
	cstate = initial_funding(NULL, o1, o2, oa, fee);
	if (!cstate)
		errx(1, "Invalid open combination (need 1 anchor offer)");

	if (our_rhash)
		proto_to_sha256(o1->revocation_hash, our_rhash);

	if (their_rhash)
		proto_to_sha256(o2->revocation_hash, their_rhash);

	/* If o2 sent anchor, it contains their commit sig. */
	if (o2->anch == OPEN_CHANNEL__ANCHOR_OFFER__WILL_CREATE_ANCHOR)
		sig = oa->commit_sig;

	if (num_updates)
		*num_updates = 0;
	while (*argv) {
		int64_t delta;
		bool received;
		Pkt *pkt;

		/* + marks messages sent by us, - for messages from them */
		if (strstarts(*argv, "+")) {
			received = false;
		} else if (strstarts(*argv, "-")) {
			received = true;
		} else
			errx(1, "%s does not start with +/-", *argv);

		pkt = any_pkt_from_file(*argv + 1);
		switch (pkt->pkt_case) {
		case PKT__PKT_OPEN_COMMIT_SIG:
			if (received)
				sig = pkt->open_commit_sig->sig;
			break;
		case PKT__PKT_UPDATE: {
			if (received) {
				delta = -pkt->update->delta;
				get_rhash(pkt->update->revocation_hash,
					  &old_their_rhash, their_rhash);
			} else {
				delta = pkt->update->delta;
				get_rhash(pkt->update->revocation_hash,
					  &old_our_rhash, our_rhash);
			}
			if (!funding_delta(o1, o2, oa, delta,
					   &cstate->a, &cstate->b))
				errx(1, "Impossible funding update %lli %s",
				     (long long)delta, *argv);
			if (num_updates)
				(*num_updates)++;
			break;
		}
		case PKT__PKT_UPDATE_ACCEPT:
			if (received) {
				sig = pkt->update_accept->sig;
				get_rhash(pkt->update_accept->revocation_hash,
					  &old_their_rhash, their_rhash);
			} else {
				get_rhash(pkt->update_accept->revocation_hash,
					  &old_our_rhash, our_rhash);
			}
			break;
		case PKT__PKT_UPDATE_SIGNATURE:
			if (received) {
				sig = pkt->update_signature->sig;
				check_preimage(pkt->update_signature
					       ->revocation_preimage,
					       &old_their_rhash, their_rhash,
					       *argv);
			} else {
				check_preimage(pkt->update_signature
					       ->revocation_preimage,
					       &old_our_rhash, our_rhash,
					       *argv);
			}
			break;
		case PKT__PKT_UPDATE_COMPLETE:
			if (received) {
				check_preimage(pkt->update_complete
					       ->revocation_preimage,
					       &old_their_rhash, their_rhash,
					       *argv);
			} else {
				check_preimage(pkt->update_complete
					       ->revocation_preimage,
					       &old_our_rhash, our_rhash,
					       *argv);
			}
			break;
		default:
			errx(1, "Unexpected packet type %u", pkt->pkt_case);
		}
		argv++;
	}

	if (their_commit_sig) {
		if (!sig)
			errx(1, "No commit signature message found");
		if (!proto_to_signature(sig, their_commit_sig))
			errx(1, "Invalid signature");
	}

	return cstate;
}
