#include <ccan/ccan/tal/str/str.h>
#include <common/json_command.h>
#include <common/jsonrpc_errors.h>
#include <connectd/connectd_wiregen.h>
#include <lightningd/channel.h>
#include <lightningd/log.h>
#include <lightningd/notification.h>
#include <lightningd/opening_common.h>
#include <lightningd/peer_control.h>
#include <lightningd/subd.h>
#include <openingd/dualopend_wiregen.h>
#include <openingd/openingd_wiregen.h>
#include <wallet/wallet.h>

static void destroy_uncommitted_channel(struct uncommitted_channel *uc)
{
	if (uc->open_daemon) {
		struct subd *open_daemon= uc->open_daemon;
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

	uc->peer = peer;
	assert(!peer->uncommitted_channel);

	uc->transient_billboard = NULL;
	uc->dbid = wallet_get_channel_dbid(ld->wallet);

	uc->log = new_log(uc, ld->log_book, &uc->peer->id,
			  "chan#%"PRIu64, uc->dbid);

	uc->fc = NULL;
	uc->our_config.id = 0;

	get_channel_basepoints(ld, &uc->peer->id, uc->dbid,
			       &uc->local_basepoints, &uc->local_funding_pubkey);

	uc->peer->uncommitted_channel = uc;
	tal_add_destructor(uc, destroy_uncommitted_channel);

	return uc;
}

void opend_channel_errmsg(struct uncommitted_channel *uc,
			  struct per_peer_state *pps,
			  const struct channel_id *channel_id UNUSED,
			  const char *desc,
			  bool soft_error UNUSED,
			  const u8 *err_for_them UNUSED)
{
	/* Close fds, if any. */
	tal_free(pps);
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
	u8 *msg = towire_connectd_peer_disconnected(tmpctx, &uc->peer->id);
	log_(uc->log, level, NULL, false, "%s", desc);
	subd_send_msg(uc->peer->ld->connectd, msg);
	if (uc->fc && uc->fc->cmd)
		was_pending(command_fail(uc->fc->cmd, LIGHTNINGD, "%s", desc));
	notify_disconnect(uc->peer->ld, &uc->peer->id);
}


void kill_uncommitted_channel(struct uncommitted_channel *uc,
			      const char *why)
{
	log_info(uc->log, "Killing opening daemon: %s", why);

	/* Close opend daemon. */
	subd_release_channel(uc->open_daemon, uc);
	uc->open_daemon = NULL;

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

	/* Don't care */
	ours->htlc_minimum = AMOUNT_MSAT(0);

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

#if DEVELOPER
 /* Indented to avoid include ordering check */
 #include <lightningd/memdump.h>

static void opening_died_forget_memleak(struct subd *open_daemon,
					struct command *cmd)
{
	/* FIXME: We ignore the remaining opening daemons in this case. */
	opening_memleak_done(cmd, NULL);
}

/* Mutual recursion */
static void opening_memleak_req_next(struct command *cmd, struct peer *prev);
static void opening_memleak_req_done(struct subd *open_daemon,
				     const u8 *msg, const int *fds UNUSED,
				     struct command *cmd)
{
	bool found_leak;
	struct uncommitted_channel *uc = open_daemon->channel;

	tal_del_destructor2(open_daemon, opening_died_forget_memleak, cmd);
	if (!fromwire_openingd_dev_memleak_reply(msg, &found_leak) &&
			!fromwire_dual_open_dev_memleak_reply(msg,
							      &found_leak)) {
		was_pending(command_fail(cmd, LIGHTNINGD,
					 "Bad opening_dev_memleak"));
		return;
	}

	if (found_leak) {
		opening_memleak_done(cmd, open_daemon);
		return;
	}
	opening_memleak_req_next(cmd, uc->peer);
}

static void opening_memleak_req_next(struct command *cmd, struct peer *prev)
{
	struct peer *p;
	u8 *msg;

	list_for_each(&cmd->ld->peers, p, list) {
		struct subd *open_daemon;

		if (!p->uncommitted_channel)
			continue;
		if (p == prev) {
			prev = NULL;
			continue;
		}
		if (prev != NULL)
			continue;

		open_daemon = p->uncommitted_channel->open_daemon;

		if (!open_daemon)
			continue;

		if (streq(open_daemon->name, "dualopend"))
			msg = towire_dual_open_dev_memleak(NULL);
		else
			msg = towire_openingd_dev_memleak(NULL);

		subd_req(p, open_daemon, take(msg), -1, 0,
			 opening_memleak_req_done, cmd);
		/* Just in case it dies before replying! */
		tal_add_destructor2(p->uncommitted_channel->open_daemon,
				    opening_died_forget_memleak, cmd);
		return;
	}
	opening_memleak_done(cmd, NULL);
}

void opening_dev_memleak(struct command *cmd)
{
	opening_memleak_req_next(cmd, NULL);
}
#endif /* DEVELOPER */
