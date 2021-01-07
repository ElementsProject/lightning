#include <bitcoin/block.h>
#include <wire/peer_wire.h>

static bool unknown_type(enum peer_wire t)
{
	switch (t) {
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
#if EXPERIMENTAL_FEATURES
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
	case WIRE_BLACKLIST_PODLE:
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
	case WIRE_PING:
	case WIRE_PONG:
#if EXPERIMENTAL_FEATURES
	case WIRE_ONION_MESSAGE:
#endif
		return true;
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
	case WIRE_CHANNEL_REESTABLISH:
	case WIRE_ANNOUNCEMENT_SIGNATURES:
	case WIRE_GOSSIP_TIMESTAMP_FILTER:
#if EXPERIMENTAL_FEATURES
	case WIRE_TX_ADD_INPUT:
	case WIRE_TX_REMOVE_INPUT:
	case WIRE_TX_ADD_OUTPUT:
	case WIRE_TX_REMOVE_OUTPUT:
	case WIRE_TX_COMPLETE:
	case WIRE_TX_SIGNATURES:
	case WIRE_OPEN_CHANNEL2:
	case WIRE_ACCEPT_CHANNEL2:
	case WIRE_INIT_RBF:
	case WIRE_BLACKLIST_PODLE:
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
	struct amount_sat ignored_sat;
	struct amount_msat ignored_msat;
	u64 ignored_u64;
	u32 ignored_u32;
	u16 ignored_u16;
	u8 ignored_u8;
	struct pubkey ignored_pubkey;
	struct bitcoin_blkid ignored_chainhash;
	struct secret ignored_secret;
	struct tlv_open_channel_tlvs *tlvs = tlv_open_channel_tlvs_new(tmpctx);

	if (fromwire_channel_reestablish(in_pkt, channel_id,
					 &ignored_u64, &ignored_u64,
					 &ignored_secret, &ignored_pubkey))
		return true;
	if (fromwire_open_channel(in_pkt, &ignored_chainhash,
				  channel_id, &ignored_sat,
				  &ignored_msat, &ignored_sat,
				  &ignored_msat, &ignored_sat,
				  &ignored_msat, &ignored_u32,
				  &ignored_u16, &ignored_u16,
				  &ignored_pubkey, &ignored_pubkey,
				  &ignored_pubkey, &ignored_pubkey,
				  &ignored_pubkey, &ignored_pubkey,
				  &ignored_u8, tlvs))
		return true;
	return false;
}
