#ifndef LIGHTNING_PLUGINS_SPENDER_PSBT_MULTIVIEW_H
#define LIGHTNING_PLUGINS_SPENDER_PSBT_MULTIVIEW_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

struct wally_psbt;

/* When one funding transaction is negotiated with several peers at
 * once (multifundchannel, or a splice that also opens new channels),
 * we keep a single "parent" PSBT plus one "node view" per peer.
 *
 * There's a few ground rules here about how we store/keep
 * the PSBT input/outputs in such a way that we can Do The
 * Right Thing for each of our peers.
 *
 * Core Lightning will make sure that our peer isn't removing/adding
 * any updates that it's not allowed to (i.e. ours or a different
 * node's that we're pretending are 'ours').
 *
 * The parent copy of the PSBT has all of the inputs/outputs added to it,
 * but the serial_ids are decremented by one to the even-pair, e.g. a
 * serial_id of 3 -> 2; 17 -> 16; etc.
 *
 * If the even-pair of a provided serial_id is taken/occupied,
 * the update is rejected (the parent is unmodified and the
 * function returns false).
 *
 * The peer's inputs/outputs updates are then copied to the parent psbt.
 */

/* psbt_multiview_merge - fold one negotiation's returned PSBT into the
 * shared parent.
 *
 * The changeset between @old_node_psbt (what that negotiation last saw)
 * and @new_node_psbt (what it just returned) is applied to @parent_psbt.
 * Peer additions (odd serials) are stored even-pair normalized
 * (serial - 1).  Our own (even serial) additions are ignored -- they
 * are already on the parent -- UNLESS listed in @preserve_in_serials /
 * @preserve_out_serials (tal_arr's or NULL), which marks daemon-minted
 * entries (funding outputs, a splice's old-funding input) that must be
 * copied onto the parent verbatim.
 *
 * @parent_changed (may be NULL) is set to whether anything was
 * added to/removed from the parent.
 *
 * On failure (missing serial, serial collision on the parent, or an
 * illegal removal) returns false and *@parent_psbt is unmodified. */
bool psbt_multiview_merge(const tal_t *ctx,
			  struct wally_psbt *old_node_psbt,
			  struct wally_psbt *new_node_psbt,
			  const u64 *preserve_in_serials,
			  const u64 *preserve_out_serials,
			  bool *parent_changed,
			  struct wally_psbt **parent_psbt);

/* psbt_multiview_rebuild_node - rebuild one negotiation's view from the
 * parent.
 *
 * Clones @parent_psbt and, for every entry that carries an odd serial
 * in *@node_psbt (i.e. that negotiation's peer contributions), flips
 * the cloned entry's even-pair serial (serial - 1) back to the odd
 * serial.  All other peers' contributions stay masked as ours.
 * *@node_psbt is replaced by the rebuilt clone.
 *
 * Returns false (and leaves *@node_psbt alone) if a serial is missing. */
bool psbt_multiview_rebuild_node(const tal_t *ctx,
				 const struct wally_psbt *parent_psbt,
				 struct wally_psbt **node_psbt);

#endif /* LIGHTNING_PLUGINS_SPENDER_PSBT_MULTIVIEW_H */
