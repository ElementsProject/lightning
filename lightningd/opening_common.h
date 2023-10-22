#ifndef LIGHTNING_LIGHTNINGD_OPENING_COMMON_H
#define LIGHTNING_LIGHTNINGD_OPENING_COMMON_H
#include "config.h"
#include <bitcoin/pubkey.h>
#include <common/amount.h>
#include <common/channel_config.h>
#include <common/channel_id.h>
#include <common/derive_basepoints.h>
#include <common/status_levels.h>

struct amount_msat;
struct amount_sat;
struct basepoints;
struct channel_config;
struct command;
struct lightningd;
struct logger;
struct peer;
struct wally_tx;

struct uncommitted_channel {
	/* peer->uncommitted_channel == this */
	struct peer *peer;

	/* opening daemon which is running now */
	struct subd *open_daemon;

	/* Reserved dbid for if we become a real struct channel */
	u64 dbid;

	/* Channel id (temporary!) */
	struct channel_id cid;

	/* For logging */
	struct logger *log;

	/* Openingd can tell us stuff. */
	const char *transient_billboard;

	/* If we offered channel, this contains information, otherwise NULL */
	struct funding_channel *fc;

	/* Our basepoints for the channel. */
	struct basepoints local_basepoints;

	/* Public key for funding tx. */
	struct pubkey local_funding_pubkey;

	/* If true, we are already in fundee-mode and any future
	 * `fundchannel_start` on our end should fail.
	 */
	bool got_offer;

	/* These are *not* filled in by new_uncommitted_channel: */

	/* Minimum funding depth (if opener == REMOTE). */
	u32 minimum_depth;

	/* Our channel config. */
	struct channel_config our_config;

	/* Reserve we will impose on the other side. If this is NULL
	 * we will use our default of 1% of the funding
	 * amount. Otherwise it will be used by openingd as absolute
	 * value (clamped to dust limit). */
	struct amount_sat *reserve;
};

struct funding_channel {
	struct command *cmd; /* Which initially owns us until openingd request */

	struct wallet_tx *wtx;
	struct amount_msat push;
	struct amount_sat funding_sats;

	u8 channel_flags;
	const u8 *our_upfront_shutdown_script;

	/* Variables we need to compose fields in cmd's response */
	const char *hextx;

	/* Peer we're trying to reach. */
	struct pubkey peerid;

	/* Channel, subsequent owner of us */
	struct uncommitted_channel *uc;

	/* Channel type we ended up negotiating. */
	struct channel_type *channel_type;

	/* The scriptpubkey to pay (once started) */
	u8 *funding_scriptpubkey;

	/* Whether or not this is in the middle of getting funded */
	bool inflight;

	/* Initial openingd_funder_start msg */
	const u8 *open_msg;

	/* Any commands trying to cancel us. */
	struct command **cancels;

	/* Place to stash the per-peer-state while we wait
	 * for them to get back to us with signatures */
	struct peer_fd *peer_fd;
};

struct uncommitted_channel *new_uncommitted_channel(struct peer *peer);

void opend_channel_errmsg(struct uncommitted_channel *uc,
			  struct peer_fd *peer_fd,
			  const char *desc,
			  const u8 *err_for_them UNUSED,
			  bool disconnect UNUSED,
			  bool warning UNUSED);

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

#endif /* LIGHTNING_LIGHTNINGD_OPENING_COMMON_H */
