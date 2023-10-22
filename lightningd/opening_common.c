#include "config.h"
#include <ccan/ccan/tal/str/str.h>
#include <common/json_command.h>
#include <common/type_to_string.h>
#include <common/wire_error.h>
#include <errno.h>
#include <hsmd/hsmd_wiregen.h>
#include <lightningd/channel.h>
#include <lightningd/channel_control.h>
#include <lightningd/connect_control.h>
#include <lightningd/hsm_control.h>
#include <lightningd/notification.h>
#include <lightningd/opening_common.h>
#include <lightningd/peer_control.h>
#include <lightningd/peer_fd.h>
#include <lightningd/subd.h>
#include <openingd/openingd_wiregen.h>

static void destroy_uncommitted_channel(struct uncommitted_channel *uc)
{
	struct subd *open_daemon = uc->open_daemon;

	if (open_daemon) {
		uc->open_daemon = NULL;
		subd_release_channel(open_daemon, uc);
	}

	/* This is how shutdown_subdaemons tells us not to delete from db! */
	if (!uc->peer->uncommitted_channel)
		return;

	uc->peer->uncommitted_channel = NULL;

	maybe_delete_peer(uc->peer);
}

struct uncommitted_channel *
new_uncommitted_channel(struct peer *peer)
{
	struct lightningd *ld = peer->ld;
	struct uncommitted_channel *uc = tal(ld, struct uncommitted_channel);
	const u8 *new_channel_msg;

	uc->peer = peer;
	assert(!peer->uncommitted_channel);

	uc->transient_billboard = NULL;
	uc->dbid = wallet_get_channel_dbid(ld->wallet);

	uc->log = new_logger(uc, ld->log_book, &uc->peer->id,
			     "chan#%"PRIu64, uc->dbid);

	uc->fc = NULL;
	uc->our_config.id = 0;
	/* BOLT #2:
	 *
	 * The sender:
	 *   - if `channel_type` includes `option_zeroconf`:
	 *      - MUST set `minimum_depth` to zero.
	 *   - otherwise:
	 *     - SHOULD set `minimum_depth` to a number of blocks it
	 *       considers reasonable to avoid double-spending of the
	 *       funding transaction.
	 */
	 /* We override this in openchannel hook if we want zeroconf */
	uc->minimum_depth = ld->config.anchor_confirms;

	/* Use default 1% reserve if not otherwise specified. If this
	 * is not-NULL it will be used by openingd as absolute value
	 * (clamped to dust limit). */
	uc->reserve = NULL;

	memset(&uc->cid, 0xFF, sizeof(uc->cid));

	/* Declare the new channel to the HSM. */
	new_channel_msg = towire_hsmd_new_channel(NULL, &uc->peer->id, uc->dbid);
	new_channel_msg = hsm_sync_req(tmpctx, ld, take(new_channel_msg));
	if (!fromwire_hsmd_new_channel_reply(new_channel_msg))
		fatal("HSM gave bad hsm_new_channel_reply %s",
		      tal_hex(new_channel_msg, new_channel_msg));

	get_channel_basepoints(ld, &uc->peer->id, uc->dbid,
			       &uc->local_basepoints, &uc->local_funding_pubkey);

	uc->peer->uncommitted_channel = uc;
	tal_add_destructor(uc, destroy_uncommitted_channel);

	uc->got_offer = false;
	uc->open_daemon = NULL;

	return uc;
}

void opend_channel_errmsg(struct uncommitted_channel *uc,
			  struct peer_fd *peer_fd,
			  const char *desc,
			  const u8 *err_for_them UNUSED,
			  bool disconnect UNUSED,
			  bool warning UNUSED)
{
	/* Close fds, if any. */
	tal_free(peer_fd);
	uncommitted_channel_disconnect(uc, LOG_INFORM, desc);
	tal_free(uc);
}

/* There's nothing permanent in an unconfirmed transaction */
void opend_channel_set_billboard(struct uncommitted_channel *uc,
				 bool perm UNUSED,
				 const char *happenings TAKES)
{
	uc->transient_billboard = tal_free(uc->transient_billboard);
	if (happenings)
		uc->transient_billboard = tal_strdup(uc, happenings);
}


void uncommitted_channel_disconnect(struct uncommitted_channel *uc,
				    enum log_level level,
				    const char *desc)
{
	log_(uc->log, level, NULL, false, "%s", desc);
	if (uc->fc && uc->fc->cmd)
		was_pending(command_fail(uc->fc->cmd, LIGHTNINGD, "%s", desc));
}


void kill_uncommitted_channel(struct uncommitted_channel *uc,
			      const char *why)
{
	log_info(uc->log, "Killing opening daemon: %s", why);

	uncommitted_channel_disconnect(uc, LOG_INFORM, why);
	tal_free(uc);
}

void channel_config(struct lightningd *ld,
		    struct channel_config *ours,
		    u32 *max_to_self_delay,
		    struct amount_msat *min_effective_htlc_capacity)
{
	/* FIXME: depend on feerate. */
	*max_to_self_delay = ld->config.locktime_max;

	/* Take minimal effective capacity from config min_capacity_sat */
	if (!amount_sat_to_msat(min_effective_htlc_capacity,
				amount_sat(ld->config.min_capacity_sat)))
		fatal("amount_msat overflow for config.min_capacity_sat");

	/* BOLT #2:
	 *
	 * The sending node SHOULD:
	 *...
	 *   - set `dust_limit_satoshis` to a sufficient value to allow
	 *     commitment transactions to propagate through the Bitcoin network.
	 */
	ours->dust_limit = chainparams->dust_limit;
	ours->max_htlc_value_in_flight = AMOUNT_MSAT(UINT64_MAX);

	ours->max_dust_htlc_exposure_msat
		= ld->config.max_dust_htlc_exposure_msat;

	/* Don't care */
	ours->htlc_minimum = ld->config.htlc_minimum_msat;

	/* BOLT #2:
	 *
	 * The sending node SHOULD:
	 *   - set `to_self_delay` sufficient to ensure the sender can
	 *     irreversibly spend a commitment transaction output, in case of
	 *     misbehavior by the receiver.
	 */
	 ours->to_self_delay = ld->config.locktime_blocks;

	 ours->max_accepted_htlcs = ld->config.max_concurrent_htlcs;

	 /* This is filled in by lightning_openingd, for consistency. */
	 ours->channel_reserve = AMOUNT_SAT(UINT64_MAX);
}
