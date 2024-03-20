#include "config.h"
#include <common/bolt11.h>
#include <common/json_parse.h>
#include <gossipd/gossipd_wiregen.h>
#include <lightningd/channel.h>
#include <lightningd/lightningd.h>
#include <lightningd/peer_control.h>
#include <lightningd/routehint.h>

static bool scid_in_arr(const struct short_channel_id *scidarr,
			struct short_channel_id scid)
{
	for (size_t i = 0; i < tal_count(scidarr); i++)
		if (short_channel_id_eq(scidarr[i], scid))
			return true;

	return false;
}

struct routehint_candidate *
routehint_candidates(const tal_t *ctx,
		     struct lightningd *ld,
		     const char *buf,
		     const jsmntok_t *toks,
		     const bool *expose_all_private,
		     const struct short_channel_id *hints,
		     bool *none_public,
		     struct amount_msat *avail_capacity,
		     struct amount_msat *private_capacity,
		     struct amount_msat *deadend_capacity,
		     struct amount_msat *offline_capacity)
{
	struct routehint_candidate *candidates, *privcandidates;
	const jsmntok_t *t, *arr;
	size_t i;

	log_debug(ld->log, "routehint: %.*s",
		  json_tok_full_len(toks),
		  json_tok_full(buf, toks));

	/* We get the full JSON, including result. */
	t = json_get_member(buf, toks, "result");
	if (!t)
		fatal("Missing result from listincoming: %.*s",
		      json_tok_full_len(toks),
		      json_tok_full(buf, toks));
	arr = json_get_member(buf, t, "incoming");

	candidates = tal_arr(ctx, struct routehint_candidate, 0);
	privcandidates = tal_arr(tmpctx, struct routehint_candidate, 0);
	*none_public = true;
	*deadend_capacity = AMOUNT_MSAT(0);
	*offline_capacity = AMOUNT_MSAT(0);
	*avail_capacity = AMOUNT_MSAT(0);
	*private_capacity = AMOUNT_MSAT(0);

	/* We combine the JSON output which knows the peers' details,
	 * with our internal information */
	json_for_each_arr(i, t, arr) {
		struct amount_msat capacity;
		const char *err;
		struct routehint_candidate candidate;
		struct amount_msat fee_base, htlc_max;
		struct route_info *r;
		bool is_public;

		r = tal(tmpctx, struct route_info);

		err = json_scan(tmpctx, buf, t,
				"{id:%"
				",short_channel_id:%"
				",fee_base_msat:%"
				",fee_proportional_millionths:%"
				",cltv_expiry_delta:%"
				",htlc_max_msat:%"
				",incoming_capacity_msat:%"
				"}",
				JSON_SCAN(json_to_node_id, &r->pubkey),
				JSON_SCAN(json_to_short_channel_id,
					  &r->short_channel_id),
				JSON_SCAN(json_to_msat, &fee_base),
				JSON_SCAN(json_to_u32,
					  &r->fee_proportional_millionths),
				JSON_SCAN(json_to_u16, &r->cltv_expiry_delta),
				JSON_SCAN(json_to_msat, &htlc_max),
				JSON_SCAN(json_to_msat, &capacity));

		if (err) {
			fatal("Invalid return from listincoming (%s): %.*s",
			      err,
			      json_tok_full_len(toks),
			      json_tok_full(buf, toks));
		}

		/* Note: listincoming returns real scid or local alias if no real scid. */
		candidate.c = any_channel_by_scid(ld, r->short_channel_id, true);
		if (!candidate.c) {
			log_debug(ld->log, "%s: channel not found in peer %s",
				  fmt_short_channel_id(tmpctx, r->short_channel_id),
				  fmt_node_id(tmpctx, &r->pubkey));
			continue;
		}

		/* Check channel is in CHANNELD_NORMAL or CHANNELD_AWAITING_SPLICE */
		if (!channel_state_can_add_htlc(candidate.c->state)) {
			log_debug(ld->log, "%s: abnormal channel",
				  fmt_short_channel_id(tmpctx,
						       r->short_channel_id));
			continue;
		}

		/* FIXME: we don't actually check htlc_minimum_msat! */

		/* If they set an htlc_maximum_msat, consider that the
		 * capacity ceiling.  We *could* do multiple HTLCs,
		 * but presumably that would defeat the spirit of the
		 * limit anyway */
		/* FIXME: Present max capacity of multiple channels? */
		candidate.capacity = channel_amount_receivable(candidate.c);
		if (amount_msat_greater(candidate.capacity, htlc_max))
			candidate.capacity = htlc_max;

		/* Now we can tell if it's public.  If so (even if it's otherwise
		 * unusable), we *don't* expose private channels! */
		is_public = (candidate.c->channel_flags
			     & CHANNEL_FLAGS_ANNOUNCE_CHANNEL);

		if (is_public)
			*none_public = false;

		/* If they explicitly say to expose all private ones, consider
		 * it public. */
		if (expose_all_private != NULL && *expose_all_private)
			is_public = true;

		r->fee_base_msat = fee_base.millisatoshis; /* Raw: route_info */
		/* Could wrap: if so ignore */
		if (!amount_msat_eq(amount_msat(r->fee_base_msat), fee_base)) {
			log_debug(ld->log,
				  "Peer charging insane fee %.*s; ignoring",
				  json_tok_full_len(t),
				  json_tok_full(buf, t));
			continue;
		}

		/* Consider only hints they gave */
		if (hints) {
			log_debug(ld->log, "We have hints!");
			/* Allow specification by alias, too */
			if (!scid_in_arr(hints, r->short_channel_id)
			    && (!candidate.c->alias[REMOTE]
				|| !scid_in_arr(hints, *candidate.c->alias[REMOTE]))) {
				log_debug(ld->log, "scid %s not in hints",
					  fmt_short_channel_id(tmpctx,
							       r->short_channel_id));
				continue;
			}
			/* If they give us a hint, we use even if capacity 0 */
		} else if (amount_msat_eq(capacity, AMOUNT_MSAT(0))) {
			log_debug(ld->log, "%s: deadend",
				  fmt_short_channel_id(tmpctx,
						       r->short_channel_id));
			if (!amount_msat_add(deadend_capacity,
					     *deadend_capacity,
					     candidate.capacity))
				fatal("Overflow summing deadend capacity!");
			continue;
		}

		/* Is it offline? */
		if (candidate.c->owner == NULL) {
			log_debug(ld->log, "%s: offline",
				  fmt_short_channel_id(tmpctx,
						       r->short_channel_id));
			if (!amount_msat_add(offline_capacity,
					     *offline_capacity,
					     candidate.capacity))
				fatal("Overflow summing offline capacity!");
			continue;
		}

		/* BOLT-channel-type #2:
		 *   - if `channel_type` has `option_scid_alias` set:
		 *       - MUST NOT use the real `short_channel_id` in
		 *         BOLT 11 `r` fields.
		 */
		if (channel_has(candidate.c, OPT_SCID_ALIAS)) {
			if (!candidate.c->alias[REMOTE]) {
				log_debug(ld->log, "%s: no remote alias (yet?)",
					  fmt_short_channel_id(tmpctx,
							       r->short_channel_id));
				continue;
			}
			r->short_channel_id = *candidate.c->alias[REMOTE];
		} else {
			/* Older code didn't remember type correctly,
			 * or negotiate properly, so best effort here */

			/* Note explicit flag test here: if we're told to expose all
			 * private channels, then "is_public" is forced true */
			if (candidate.c->alias[REMOTE]
			    /* Use remote alias if it's all we've got, or unannounced channel */
			    && (!(candidate.c->channel_flags & CHANNEL_FLAGS_ANNOUNCE_CHANNEL)
				|| !candidate.c->scid)) {
				r->short_channel_id = *candidate.c->alias[REMOTE];
			} else if (candidate.c->scid) {
				r->short_channel_id = *candidate.c->scid;
			} else {
				/* Haven't got remote alias yet?  Can't use ut. */
				log_debug(ld->log, "%s: no alias",
					  fmt_short_channel_id(tmpctx,
							       r->short_channel_id));
				continue;
			}
		}

		/* OK, finish it and append to one of the arrays. */
		if (is_public) {
			log_debug(ld->log, "%s: added to public",
				  fmt_short_channel_id(tmpctx,
						       r->short_channel_id));
			candidate.r = tal_steal(candidates, r);
			tal_arr_expand(&candidates, candidate);
			if (!amount_msat_add(avail_capacity,
					     *avail_capacity,
					     candidate.capacity)) {
				fatal("Overflow summing pub capacities %s + %s",
				      fmt_amount_msat(tmpctx,
						      *avail_capacity),
				      fmt_amount_msat(tmpctx,
						      candidate.capacity));
			}
		} else {
			log_debug(ld->log, "%s: added to private",
				  fmt_short_channel_id(tmpctx,
						       r->short_channel_id));
			candidate.r = tal_steal(privcandidates, r);
			tal_arr_expand(&privcandidates, candidate);
			if (!amount_msat_add(private_capacity,
					     *private_capacity,
					     candidate.capacity)) {
				fatal("Overflow summing priv capacities %s + %s",
				      fmt_amount_msat(tmpctx,
						      *private_capacity),
				      fmt_amount_msat(tmpctx,
						      candidate.capacity));
			}
		}
	}

	/* By default, only consider private channels if there are
	 * no public channels *at all* */
	if (expose_all_private == NULL
	    && tal_count(candidates) == 0 && *none_public) {
		log_debug(ld->log, "No publics: using private channels");
		tal_free(candidates);
		candidates = tal_steal(ctx, privcandidates);
		*avail_capacity = *private_capacity;
		/* This reflects *unused* private capacity. */
		*private_capacity = AMOUNT_MSAT(0);
	}

	return candidates;
}
