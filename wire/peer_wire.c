#include "config.h"
#include <ccan/mem/mem.h>
#include <wire/peer_wire.h>

static bool unknown_type(enum peer_wire t)
{
	switch (t) {
	case WIRE_WARNING:
	case WIRE_INIT:
	case WIRE_ERROR:
	case WIRE_OPEN_CHANNEL:
	case WIRE_ACCEPT_CHANNEL:
	case WIRE_FUNDING_CREATED:
	case WIRE_FUNDING_SIGNED:
	case WIRE_FUNDING_LOCKED:
	case WIRE_SHUTDOWN:
	case WIRE_CLOSING_SIGNED:
	case WIRE_UPDATE_ADD_HTLC:
	case WIRE_UPDATE_FULFILL_HTLC:
	case WIRE_UPDATE_FAIL_HTLC:
	case WIRE_UPDATE_FAIL_MALFORMED_HTLC:
	case WIRE_COMMITMENT_SIGNED:
	case WIRE_REVOKE_AND_ACK:
	case WIRE_UPDATE_FEE:
	case WIRE_UPDATE_BLOCKHEIGHT:
	case WIRE_CHANNEL_REESTABLISH:
	case WIRE_ANNOUNCEMENT_SIGNATURES:
	case WIRE_CHANNEL_ANNOUNCEMENT:
	case WIRE_NODE_ANNOUNCEMENT:
	case WIRE_CHANNEL_UPDATE:
	case WIRE_PING:
	case WIRE_PONG:
	case WIRE_QUERY_SHORT_CHANNEL_IDS:
	case WIRE_REPLY_SHORT_CHANNEL_IDS_END:
	case WIRE_QUERY_CHANNEL_RANGE:
	case WIRE_REPLY_CHANNEL_RANGE:
	case WIRE_GOSSIP_TIMESTAMP_FILTER:
	case WIRE_OBS2_ONION_MESSAGE:
	case WIRE_ONION_MESSAGE:
	case WIRE_TX_ADD_INPUT:
	case WIRE_TX_REMOVE_INPUT:
	case WIRE_TX_ADD_OUTPUT:
	case WIRE_TX_REMOVE_OUTPUT:
	case WIRE_TX_COMPLETE:
	case WIRE_TX_SIGNATURES:
	case WIRE_OPEN_CHANNEL2:
	case WIRE_ACCEPT_CHANNEL2:
	case WIRE_INIT_RBF:
	case WIRE_ACK_RBF:
#if EXPERIMENTAL_FEATURES
	case WIRE_STFU:
#endif
		return false;
	}
	return true;
}

bool is_msg_for_gossipd(const u8 *cursor)
{
	switch ((enum peer_wire)fromwire_peektype(cursor)) {
	case WIRE_CHANNEL_ANNOUNCEMENT:
	case WIRE_NODE_ANNOUNCEMENT:
	case WIRE_CHANNEL_UPDATE:
	case WIRE_QUERY_SHORT_CHANNEL_IDS:
	case WIRE_REPLY_SHORT_CHANNEL_IDS_END:
	case WIRE_QUERY_CHANNEL_RANGE:
	case WIRE_REPLY_CHANNEL_RANGE:
		return true;
	case WIRE_WARNING:
	case WIRE_INIT:
	case WIRE_PING:
	case WIRE_PONG:
	case WIRE_ERROR:
	case WIRE_OPEN_CHANNEL:
	case WIRE_ACCEPT_CHANNEL:
	case WIRE_FUNDING_CREATED:
	case WIRE_FUNDING_SIGNED:
	case WIRE_FUNDING_LOCKED:
	case WIRE_SHUTDOWN:
	case WIRE_CLOSING_SIGNED:
	case WIRE_UPDATE_ADD_HTLC:
	case WIRE_UPDATE_FULFILL_HTLC:
	case WIRE_UPDATE_FAIL_HTLC:
	case WIRE_UPDATE_FAIL_MALFORMED_HTLC:
	case WIRE_COMMITMENT_SIGNED:
	case WIRE_REVOKE_AND_ACK:
	case WIRE_UPDATE_FEE:
	case WIRE_UPDATE_BLOCKHEIGHT:
	case WIRE_CHANNEL_REESTABLISH:
	case WIRE_ANNOUNCEMENT_SIGNATURES:
	case WIRE_GOSSIP_TIMESTAMP_FILTER:
	case WIRE_TX_ADD_INPUT:
	case WIRE_TX_REMOVE_INPUT:
	case WIRE_TX_ADD_OUTPUT:
	case WIRE_TX_REMOVE_OUTPUT:
	case WIRE_TX_COMPLETE:
	case WIRE_TX_SIGNATURES:
	case WIRE_OPEN_CHANNEL2:
	case WIRE_ACCEPT_CHANNEL2:
	case WIRE_INIT_RBF:
	case WIRE_ACK_RBF:
	case WIRE_OBS2_ONION_MESSAGE:
	case WIRE_ONION_MESSAGE:
#if EXPERIMENTAL_FEATURES
	case WIRE_STFU:
#endif
		break;
	}
	return false;
}

bool is_msg_gossip_broadcast(const u8 *cursor)
{
	switch ((enum peer_wire)fromwire_peektype(cursor)) {
	case WIRE_CHANNEL_ANNOUNCEMENT:
	case WIRE_NODE_ANNOUNCEMENT:
	case WIRE_CHANNEL_UPDATE:
		return true;
	case WIRE_QUERY_SHORT_CHANNEL_IDS:
	case WIRE_REPLY_SHORT_CHANNEL_IDS_END:
	case WIRE_QUERY_CHANNEL_RANGE:
	case WIRE_REPLY_CHANNEL_RANGE:
	case WIRE_ONION_MESSAGE:
	case WIRE_OBS2_ONION_MESSAGE:
	case WIRE_WARNING:
	case WIRE_INIT:
	case WIRE_PING:
	case WIRE_PONG:
	case WIRE_ERROR:
	case WIRE_OPEN_CHANNEL:
	case WIRE_ACCEPT_CHANNEL:
	case WIRE_FUNDING_CREATED:
	case WIRE_FUNDING_SIGNED:
	case WIRE_FUNDING_LOCKED:
	case WIRE_SHUTDOWN:
	case WIRE_CLOSING_SIGNED:
	case WIRE_UPDATE_ADD_HTLC:
	case WIRE_UPDATE_FULFILL_HTLC:
	case WIRE_UPDATE_FAIL_HTLC:
	case WIRE_UPDATE_FAIL_MALFORMED_HTLC:
	case WIRE_COMMITMENT_SIGNED:
	case WIRE_REVOKE_AND_ACK:
	case WIRE_UPDATE_FEE:
	case WIRE_UPDATE_BLOCKHEIGHT:
	case WIRE_CHANNEL_REESTABLISH:
	case WIRE_ANNOUNCEMENT_SIGNATURES:
	case WIRE_GOSSIP_TIMESTAMP_FILTER:
	case WIRE_TX_ADD_INPUT:
	case WIRE_TX_REMOVE_INPUT:
	case WIRE_TX_ADD_OUTPUT:
	case WIRE_TX_REMOVE_OUTPUT:
	case WIRE_TX_COMPLETE:
	case WIRE_TX_SIGNATURES:
	case WIRE_OPEN_CHANNEL2:
	case WIRE_ACCEPT_CHANNEL2:
	case WIRE_INIT_RBF:
	case WIRE_ACK_RBF:
#if EXPERIMENTAL_FEATURES
	case WIRE_STFU:
#endif
		break;
	}
	return false;
}

/* Return true if it's an unknown ODD message.  cursor is a tal ptr. */
bool is_unknown_msg_discardable(const u8 *cursor)
{
	enum peer_wire t = fromwire_peektype(cursor);
	return unknown_type(t) && (t & 1);
}

/* Extract channel_id from various packets, return true if possible. */
bool extract_channel_id(const u8 *in_pkt, struct channel_id *channel_id)
{
	const u8 *cursor = in_pkt;
	size_t max = tal_bytelen(in_pkt);
	enum peer_wire t;

	t = fromwire_u16(&cursor, &max);

	/* We carefully quote bolts here, in case anything changes! */
	switch (t) {
	/* These ones don't have a channel_id */
	case WIRE_INIT:
	case WIRE_PING:
	case WIRE_PONG:
	case WIRE_CHANNEL_ANNOUNCEMENT:
	case WIRE_NODE_ANNOUNCEMENT:
	case WIRE_CHANNEL_UPDATE:
	case WIRE_QUERY_SHORT_CHANNEL_IDS:
	case WIRE_REPLY_SHORT_CHANNEL_IDS_END:
	case WIRE_QUERY_CHANNEL_RANGE:
	case WIRE_REPLY_CHANNEL_RANGE:
	case WIRE_GOSSIP_TIMESTAMP_FILTER:
	case WIRE_OBS2_ONION_MESSAGE:
	case WIRE_ONION_MESSAGE:
		return false;

	/* Special cases: */
	case WIRE_ERROR:
		/* BOLT #1:
		 * 1. type: 17 (`error`)
		 * 2. data:
		 *    * [`channel_id`:`channel_id`]
		 *...
		 * The channel is referred to by `channel_id`, unless
		 * `channel_id` is 0
		 */
		/* fall thru */
	case WIRE_WARNING:
		/* BOLT-warning #1:
		 * 1. type: 1 (`warning`)
		 * 2. data:
		 *    * [`channel_id`:`channel_id`]
		 *...
		 * The channel is referred to by `channel_id`, unless
		 * `channel_id` is 0
		 */
		if (!fromwire_channel_id(&cursor, &max, channel_id))
			return false;
		if (memeqzero(channel_id->id, sizeof(channel_id->id)))
			return false;
		return true;

	case WIRE_OPEN_CHANNEL:
		/* BOLT #2:
		 * 1. type: 32 (`open_channel`)
		 * 2. data:
		 *    * [`chain_hash`:`chain_hash`]
		 *    * [`32*byte`:`temporary_channel_id`]
		 */
	case WIRE_OPEN_CHANNEL2:
		/* BOLT-dualfund #2:
		 * 1. type: 64 (`open_channel2`)
		 * 2. data:
		 *    * [`chain_hash`:`chain_hash`]
		 *    * [`channel_id`:`zerod_channel_id`]
		 */

		/* Skip over chain_hash */
		fromwire_pad(&cursor, &max, sizeof(struct bitcoin_blkid));

	/* These have them at the start */
	case WIRE_TX_ADD_INPUT:
		/* BOLT-dualfund #2:
		 * 1. type: 66 (`tx_add_input`)
		 * 2. data:
		 *     * [`channel_id`:`channel_id`]
		 */
	case WIRE_TX_ADD_OUTPUT:
		/* BOLT-dualfund #2:
		 * 1. type: 67 (`tx_add_output`)
		 * 2. data:
		 *     * [`channel_id`:`channel_id`]
		 */
	case WIRE_TX_REMOVE_INPUT:
		/* BOLT-dualfund #2:
		 * 1. type: 68 (`tx_remove_input`)
		 * 2. data:
		 *     * [`channel_id`:`channel_id`]
		 */
	case WIRE_TX_REMOVE_OUTPUT:
		/* BOLT-dualfund #2:
		 * 1. type: 69 (`tx_remove_output`)
		 * 2. data:
		 *     * [`channel_id`:`channel_id`]
		 */
	case WIRE_TX_COMPLETE:
		/* BOLT-dualfund #2:
		 * 1. type: 70 (`tx_complete`)
		 * 2. data:
		 *     * [`channel_id`:`channel_id`]
		 */
	case WIRE_TX_SIGNATURES:
		/* BOLT-dualfund #2:
		 * 1. type: 71 (`tx_signatures`)
		 * 2. data:
		 *     * [`channel_id`:`channel_id`]
		 */
	case WIRE_ACCEPT_CHANNEL:
		/* BOLT #2:
		 * 1. type: 33 (`accept_channel`)
		 * 2. data:
		 *    * [`32*byte`:`temporary_channel_id`]
		 */
	case WIRE_FUNDING_CREATED:
		/* BOLT #2:
		 * 1. type: 34 (`funding_created`)
		 * 2. data:
		 *     * [`32*byte`:`temporary_channel_id`]
		 */
	case WIRE_FUNDING_SIGNED:
		/* BOLT #2:
		 * 1. type: 35 (`funding_signed`)
		 * 2. data:
		 *     * [`channel_id`:`channel_id`]
		 */
	case WIRE_FUNDING_LOCKED:
		/* BOLT #2:
		 * 1. type: 36 (`funding_locked`)
		 * 2. data:
		 *     * [`channel_id`:`channel_id`]
		 */
	case WIRE_ACCEPT_CHANNEL2:
		/* BOLT-dualfund #2:
		 * 1. type: 65 (`accept_channel2`)
		 * 2. data:
		 *     * [`channel_id`:`channel_id`]
		 */
	case WIRE_INIT_RBF:
		/* BOLT-dualfund #2:
		 * 1. type: 72 (`init_rbf`)
		 * 2. data:
		 *    * [`channel_id`:`channel_id`]
		 */
	case WIRE_ACK_RBF:
		/* BOLT-dualfund #2:
		 * 1. type: 73 (`ack_rbf`)
		 * 2. data:
		 *     * [`channel_id`:`channel_id`]
		 */
	case WIRE_SHUTDOWN:
		/* BOLT #2:
		 * 1. type: 38 (`shutdown`)
		 * 2. data:
		 *    * [`channel_id`:`channel_id`]
		 */
	case WIRE_CLOSING_SIGNED:
		/* BOLT #2:
		 * 1. type: 39 (`closing_signed`)
		 * 2. data:
		 *    * [`channel_id`:`channel_id`]
		 */
	case WIRE_UPDATE_ADD_HTLC:
		/* BOLT #2:
		 * 1. type: 128 (`update_add_htlc`)
		 * 2. data:
		 *    * [`channel_id`:`channel_id`]
		 */
	case WIRE_UPDATE_FULFILL_HTLC:
		/* BOLT #2:
		 * 1. type: 130 (`update_fulfill_htlc`)
		 * 2. data:
		 *    * [`channel_id`:`channel_id`]
		 */
	case WIRE_UPDATE_FAIL_HTLC:
		/* BOLT #2:
		 * 1. type: 131 (`update_fail_htlc`)
		 * 2. data:
		 *    * [`channel_id`:`channel_id`]
		 */
	case WIRE_UPDATE_FAIL_MALFORMED_HTLC:
		/* BOLT #2:
		 * 1. type: 135 (`update_fail_malformed_htlc`)
		 * 2. data:
		 *    * [`channel_id`:`channel_id`]
		 */
	case WIRE_COMMITMENT_SIGNED:
		/* BOLT #2:
		 * 1. type: 132 (`commitment_signed`)
		 * 2. data:
		 *    * [`channel_id`:`channel_id`]
		 */
	case WIRE_REVOKE_AND_ACK:
		/* BOLT #2:
		 * 1. type: 133 (`revoke_and_ack`)
		 * 2. data:
		 *    * [`channel_id`:`channel_id`]
		 */
	case WIRE_UPDATE_FEE:
		/* BOLT #2:
		 * 1. type: 134 (`update_fee`)
		 * 2. data:
		 *    * [`channel_id`:`channel_id`]
		 */
	case WIRE_UPDATE_BLOCKHEIGHT:
		/* BOLT-liquidity-ads #2:
		 * 1. type: 137 (`update_blockheight`)
		 * 2. data:
		 *    * [`channel_id`:`channel_id`]
		 */
	case WIRE_CHANNEL_REESTABLISH:
		/* BOLT #2:
		 * 1. type: 136 (`channel_reestablish`)
		 * 2. data:
		 *    * [`channel_id`:`channel_id`]
		 */
	case WIRE_ANNOUNCEMENT_SIGNATURES:
		/* BOLT #7:
		 * 1. type: 259 (`announcement_signatures`)
		 * 2. data:
		 *     * [`channel_id`:`channel_id`]
		 */
#if EXPERIMENTAL_FEATURES
	case WIRE_STFU:
		/* BOLT-quiescent #2:
		 * 1. type: 2 (`stfu`)
		 * 2. data:
		 *     * [`channel_id`:`channel_id`]
		 */
#endif
		return fromwire_channel_id(&cursor, &max, channel_id);
	}
	return false;
}
