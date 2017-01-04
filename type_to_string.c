#include "bitcoin/locktime.h"
#include "bitcoin/pubkey.h"
#include "bitcoin/tx.h"
#include "daemon/channel.h"
#include "daemon/htlc.h"
#include "daemon/lightningd.h"
#include "daemon/peer.h"
#include "protobuf_convert.h"
#include "type_to_string.h"
#include "utils.h"
#include <ccan/tal/str/str.h>
#include <inttypes.h>

char *type_to_string_(const tal_t *ctx,  const char *typename,
		      union printable_types u)
{
	char *s = NULL;

	/* GCC checks we're one of these, so we should be. */
	if (streq(typename, "struct pubkey"))
		s = pubkey_to_hexstr(ctx, u.pubkey);
	else if (streq(typename, "struct sha256_double"))
		s = tal_hexstr(ctx, u.sha256_double, sizeof(*u.sha256_double));
	else if (streq(typename, "struct sha256"))
		s = tal_hexstr(ctx, u.sha256, sizeof(*u.sha256));
	else if (streq(typename, "struct rel_locktime")) {
		if (rel_locktime_is_seconds(u.rel_locktime))
			s = tal_fmt(ctx, "+%usec",
				    rel_locktime_to_seconds(u.rel_locktime));
		else
			s = tal_fmt(ctx, "+%ublocks",
				    rel_locktime_to_blocks(u.rel_locktime));
	} else if (streq(typename, "struct abs_locktime")) {
		if (abs_locktime_is_seconds(u.abs_locktime))
			s = tal_fmt(ctx, "%usec",
				    abs_locktime_to_seconds(u.abs_locktime));
		else
			s = tal_fmt(ctx, "%ublocks",
				    abs_locktime_to_blocks(u.abs_locktime));
	} else if (streq(typename, "struct bitcoin_tx")) {
		u8 *lin = linearize_tx(ctx, u.bitcoin_tx);
		s = tal_hexstr(ctx, lin, tal_count(lin));
	} else if (streq(typename, "struct htlc")) {
		const struct htlc *h = u.htlc;
		s = tal_fmt(ctx, "{ id=%"PRIu64
			    " msatoshi=%"PRIu64
			    " expiry=%s"
			    " rhash=%s"
			    " rval=%s"
			    " src=%s }",
			    h->id, h->msatoshi,
			    type_to_string(ctx, struct abs_locktime, &h->expiry),
			    type_to_string(ctx, struct sha256, &h->rhash),
			    h->r ? tal_hexstr(ctx, h->r, sizeof(*h->r))
			    : "UNKNOWN",
			    h->src ? type_to_string(ctx, struct pubkey,
						    h->src->peer->id)
			    : "local");
	} else if (streq(typename, "struct rval")) {
		s = tal_hexstr(ctx, u.rval, sizeof(*u.rval));
	} else if (streq(typename, "struct channel_oneside")) {
		s = tal_fmt(ctx, "{ pay_msat=%u"
			    " fee_msat=%u"
			    " num_htlcs=%u }",
			    u.channel_oneside->pay_msat,
			    u.channel_oneside->fee_msat,
			    u.channel_oneside->num_htlcs);
	} else if (streq(typename, "struct channel_state")) {
		s = tal_fmt(ctx, "{ anchor=%"PRIu64
			    " fee_rate=%"PRIu64
			    " num_nondust=%u"
			    " ours=%s"
			    " theirs=%s }",
			    u.cstate->anchor,
			    u.cstate->fee_rate,
			    u.cstate->num_nondust,
			    type_to_string(ctx, struct channel_oneside,
					   &u.cstate->side[LOCAL]),
			    type_to_string(ctx, struct channel_oneside,
					   &u.cstate->side[REMOTE]));
	} else if (streq(typename, "struct netaddr")) {
		s = netaddr_name(ctx, u.netaddr);
	}

	return s;
}
