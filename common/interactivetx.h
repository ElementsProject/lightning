#ifndef LIGHTNING_COMMON_INTERACTIVETX_H
#define LIGHTNING_COMMON_INTERACTIVETX_H

#include "config.h"
#include <ccan/short_types/short_types.h>
#include <common/channel_id.h>
#include <common/per_peer_state.h>
#include <common/tx_roles.h>
#include <common/utils.h>
#include <wally_psbt.h>

/* Interactive tx handles the building and updating of a transaction between
 * two peers. A PSBT is passed back and forth between two peers in steps. In
 * each step a peer can suggest a single change or signal they're done
 * updating with WIRE_TX_COMPLETE. Once two steps in a row result in
 * WIRE_TX_COMPLETE the transaction is considered complete.
 */

#define INTERACTIVETX_NUM_TX_MSGS (TX_RM_OUTPUT + 1)
enum tx_msgs {
	TX_ADD_INPUT,
	TX_ADD_OUTPUT,
	TX_RM_INPUT,
	TX_RM_OUTPUT,
};

struct interactivetx_context {

	enum tx_role our_role;
	struct per_peer_state *pps;
	struct channel_id channel_id;

	/* The existing funding outpoint of a channel being spliced.
	 * This input will send funding_txid instead of prevtx. */
	struct bitcoin_outpoint *shared_outpoint;

	/* When receiving `tx_add_input` we will fill in prevtx using this
	 * value when `shared_outpoint`'s txid matches */
	struct bitcoin_tx *funding_tx;

	/* Track how many of each tx collab msg we receive */
	u16 tx_add_input_count, tx_add_output_count;

	/* Returns a PSBT with at least one change to the transaction as
	 * compared to ictx->current_psbt.
	 *
	 * If set to NULL, the default implementation will simply return
	 * ictx->desired_psbt.
	 *
	 * If no more changes are demanded, return NULL or current_psbt
	 * unchanged to signal completion.
	 */
	struct wally_psbt *(*next_update_fn)(const tal_t *ctx,
					  struct interactivetx_context *ictx);

	/* Set this to the intial psbt. Defaults to an empty PSBT. */
	struct wally_psbt *current_psbt;

	/* Optional field for storing your side's desired psbt state, to be
	 * used inside 'next_update_fn'.
	 */
	struct wally_psbt *desired_psbt;

	/* If true, process_interactivetx_updates will return when local changes
	 * are exhausted and 'tx_complete' will not be sent.
	 */
	bool pause_when_complete;

	/* Internal cached change set */
	struct psbt_changeset *change_set;
};

/* Builds a new default interactivetx context with default values */
struct interactivetx_context *new_interactivetx_context(const tal_t *ctx,
							enum tx_role our_role,
							struct per_peer_state *pps,
							struct channel_id channel_id);

/* Blocks the thread until we run out of changes (and we send tx_complete),
 * or an error occurs. If 'pause_when_complete' on the `interactivetx_context`
 * is set, this behavior changes and we return without sending tx_complete.
 *
 * If received_tx_complete is not NULL:
 * in -> true means we assume we've received tx_complete in a previous round.
 * out -> true means the last message from the peer was 'tx_complete'.
 *
 * Returns NULL on success or a description of the error on failure.
 *
 * If `tx_abort` is received, NULL is returned and `abort_msg` will be set to
 */
char *process_interactivetx_updates(const tal_t *ctx,
				    struct interactivetx_context *ictx,
				    bool *received_tx_complete,
				    u8 **abort_msg);

/* If the given ictx would cause `process_interactivetx_updates to send tx
 * changes when called. Returns true if an error occurs
 * (call `process_interactivetx_updates` for a description of the error).
 */
bool interactivetx_has_changes(struct interactivetx_context *ictx,
			       struct wally_psbt *next_psbt);

#endif /* LIGHTNING_COMMON_INTERACTIVETX_H */
