#include <wire/peer_wire.h>

static bool unknown_type(enum wire_type t)
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
	case WIRE_ANNOUNCEMENT_SIGNATURES:
	case WIRE_CHANNEL_ANNOUNCEMENT:
	case WIRE_NODE_ANNOUNCEMENT:
	case WIRE_CHANNEL_UPDATE:
	case WIRE_PING:
	case WIRE_PONG:
		return false;
	}
	return true;
}

/* Return true if it's an unknown message.  cursor is a tal ptr. */
bool unknown_msg(const u8 *cursor)
{
	return unknown_type(fromwire_peektype(cursor));
}

/* Return true if it's an unknown ODD message.  cursor is a tal ptr. */
bool unknown_msg_discardable(const u8 *cursor)
{
	enum wire_type t = fromwire_peektype(cursor);
	return unknown_type(t) && (t & 1);
}
