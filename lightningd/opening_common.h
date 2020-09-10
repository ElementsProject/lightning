#ifndef LIGHTNING_LIGHTNINGD_OPENING_COMMON_H
#define LIGHTNING_LIGHTNINGD_OPENING_COMMON_H
#include "config.h"
#include <bitcoin/pubkey.h>
#include <common/amount.h>
#include <common/channel_config.h>
#include <common/derive_basepoints.h>
#include <common/status_levels.h>

struct amount_msat;
struct amount_sat;
struct basepoints;
struct channel_config;
struct command;
struct lightningd;
struct log;
struct peer;
struct wally_tx;

struct uncommitted_channel {
	/* peer->uncommitted_channel == this */
	struct peer *peer;

	/* opening daemon which is running now */
	struct subd *open_daemon;

	/* Reserved dbid for if we become a real struct channel */
	u64 dbid;

	/* For logging */
	struct log *log;

	/* Openingd can tell us stuff. */
	const char *transient_billboard;

	/* If we offered channel, this contains information, otherwise NULL */
	struct funding_channel *fc;

	/* Our basepoints for the channel. */
	struct basepoints local_basepoints;

	/* Public key for funding tx. */
	struct pubkey local_funding_pubkey;

	/* These are *not* filled in by new_uncommitted_channel: */

	/* Minimum funding depth (if opener == REMOTE). */
	u32 minimum_depth;

	/* Our channel config. */
	struct channel_config our_config;
};

struct funding_channel {
	struct command *cmd; /* Which initially owns us until openingd request */

	struct wallet_tx *wtx;
	struct amount_msat push;
	struct amount_sat funding;
	u8 channel_flags;
	const u8 *our_upfront_shutdown_script;

	/* Variables we need to compose fields in cmd's response */
	const char *hextx;

	/* Peer we're trying to reach. */
	struct pubkey peerid;

	/* Channel, subsequent owner of us */
	struct uncommitted_channel *uc;

	/* Whether or not this is in the middle of getting funded */
	bool inflight;

	/* Any commands trying to cancel us. */
	struct command **cancels;

	/* Place to stash the per-peer-state while we wait
	 * for them to get back to us with signatures */
	struct per_peer_state *pps;
};

struct uncommitted_channel *
new_uncommitted_channel(struct peer *peer);

void opend_channel_errmsg(struct uncommitted_channel *uc,
			  struct per_peer_state *pps,
			  const struct channel_id *channel_id UNUSED,
			  const char *desc,
			  bool soft_error UNUSED,
			  const u8 *err_for_them UNUSED);

void opend_channel_set_billboard(struct uncommitted_channel *uc,
				 bool perm UNUSED,
				 const char *happenings TAKES);

void uncommitted_channel_disconnect(struct uncommitted_channel *uc,
				    enum log_level level,
				    const char *desc);

void kill_uncommitted_channel(struct uncommitted_channel *uc,
			      const char *why);

void channel_config(struct lightningd *ld,
		    struct channel_config *ours,
		    u32 *max_to_self_delay,
		    struct amount_msat *min_effective_htlc_capacity);

#if DEVELOPER
struct command;
/* Calls report_leak_info() async. */
void opening_dev_memleak(struct command *cmd);
#endif

#endif /* LIGHTNING_LIGHTNINGD_OPENING_COMMON_H */
