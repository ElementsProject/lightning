#include <hsmd/capabilities.h>
#include <hsmd/libhsmd.h>

/* Version codes for BIP32 extended keys in libwally-core.
 * It's not suitable to add this struct into client struct,
 * so set it static.*/
struct  bip32_key_version  bip32_key_version;

#if DEVELOPER
/* If they specify --dev-force-privkey it ends up in here. */
struct privkey *dev_force_privkey;
/* If they specify --dev-force-bip32-seed it ends up in here. */
struct secret *dev_force_bip32_seed;
#endif

/* Have we initialized the secretstuff? */
bool initialized = false;

struct hsmd_client *hsmd_client_new_main(const tal_t *ctx, u64 capabilities,
					 void *extra)
{
	struct hsmd_client *c = tal(ctx, struct hsmd_client);
	c->dbid = 0;
	c->capabilities = capabilities;
	c->extra = extra;
	return c;
}

struct hsmd_client *hsmd_client_new_peer(const tal_t *ctx, u64 capabilities,
					 u64 dbid,
					 const struct node_id *peer_id,
					 void *extra)
{
	struct hsmd_client *c = tal(ctx, struct hsmd_client);
	c->dbid = dbid;
	c->capabilities = capabilities;
	c->id = *peer_id;
	c->extra = extra;
	return c;
}

/*~ This routine checks that a client is allowed to call the handler. */
bool check_client_capabilities(struct hsmd_client *client, enum hsmd_wire t)
{
	/*~ Here's a useful trick: enums in C are not real types, they're
	 * semantic sugar sprinkled over an int, bascally (in fact, older
	 * versions of gcc used to convert the values ints in the parser!).
	 *
	 * But GCC will do one thing for us: if we have a switch statement
	 * with a controlling expression which is an enum, it will warn us
	 * if a declared enum value is *not* handled in the switch, eg:
	 *     enumeration value ‘FOOBAR’ not handled in switch [-Werror=switch]
	 *
	 * This only works if there's no 'default' label, which is sometimes
	 * hard, as we *can* have non-enum values in our enum.  But the tradeoff
	 * is worth it so the compiler tells us everywhere we have to fix when
	 * we add a new enum identifier!
	 */
	switch (t) {
	case WIRE_HSMD_ECDH_REQ:
		return (client->capabilities & HSM_CAP_ECDH) != 0;

	case WIRE_HSMD_CANNOUNCEMENT_SIG_REQ:
	case WIRE_HSMD_CUPDATE_SIG_REQ:
	case WIRE_HSMD_NODE_ANNOUNCEMENT_SIG_REQ:
		return (client->capabilities & HSM_CAP_SIGN_GOSSIP) != 0;

	case WIRE_HSMD_SIGN_DELAYED_PAYMENT_TO_US:
	case WIRE_HSMD_SIGN_REMOTE_HTLC_TO_US:
	case WIRE_HSMD_SIGN_PENALTY_TO_US:
	case WIRE_HSMD_SIGN_LOCAL_HTLC_TX:
		return (client->capabilities & HSM_CAP_SIGN_ONCHAIN_TX) != 0;

	case WIRE_HSMD_GET_PER_COMMITMENT_POINT:
	case WIRE_HSMD_CHECK_FUTURE_SECRET:
		return (client->capabilities & HSM_CAP_COMMITMENT_POINT) != 0;

	case WIRE_HSMD_SIGN_REMOTE_COMMITMENT_TX:
	case WIRE_HSMD_SIGN_REMOTE_HTLC_TX:
		return (client->capabilities & HSM_CAP_SIGN_REMOTE_TX) != 0;

	case WIRE_HSMD_SIGN_MUTUAL_CLOSE_TX:
		return (client->capabilities & HSM_CAP_SIGN_CLOSING_TX) != 0;

	case WIRE_HSMD_INIT:
	case WIRE_HSMD_CLIENT_HSMFD:
	case WIRE_HSMD_SIGN_WITHDRAWAL:
	case WIRE_HSMD_SIGN_INVOICE:
	case WIRE_HSMD_SIGN_COMMITMENT_TX:
	case WIRE_HSMD_GET_CHANNEL_BASEPOINTS:
	case WIRE_HSMD_DEV_MEMLEAK:
	case WIRE_HSMD_SIGN_MESSAGE:
	case WIRE_HSMD_GET_OUTPUT_SCRIPTPUBKEY:
	case WIRE_HSMD_SIGN_BOLT12:
		return (client->capabilities & HSM_CAP_MASTER) != 0;

	/*~ These are messages sent by the HSM so we should never receive them. */
	/* FIXME: Since we autogenerate these, we should really generate separate
	 * enums for replies to avoid this kind of clutter! */
	case WIRE_HSMD_ECDH_RESP:
	case WIRE_HSMD_CANNOUNCEMENT_SIG_REPLY:
	case WIRE_HSMD_CUPDATE_SIG_REPLY:
	case WIRE_HSMD_CLIENT_HSMFD_REPLY:
	case WIRE_HSMD_NODE_ANNOUNCEMENT_SIG_REPLY:
	case WIRE_HSMD_SIGN_WITHDRAWAL_REPLY:
	case WIRE_HSMD_SIGN_INVOICE_REPLY:
	case WIRE_HSMD_INIT_REPLY:
	case WIRE_HSMSTATUS_CLIENT_BAD_REQUEST:
	case WIRE_HSMD_SIGN_COMMITMENT_TX_REPLY:
	case WIRE_HSMD_SIGN_TX_REPLY:
	case WIRE_HSMD_GET_PER_COMMITMENT_POINT_REPLY:
	case WIRE_HSMD_CHECK_FUTURE_SECRET_REPLY:
	case WIRE_HSMD_GET_CHANNEL_BASEPOINTS_REPLY:
	case WIRE_HSMD_DEV_MEMLEAK_REPLY:
	case WIRE_HSMD_SIGN_MESSAGE_REPLY:
	case WIRE_HSMD_GET_OUTPUT_SCRIPTPUBKEY_REPLY:
	case WIRE_HSMD_SIGN_BOLT12_REPLY:
		break;
	}
	return false;
}

u8 *hsmd_handle_client_message(const tal_t *ctx, struct hsmd_client *client,
			       const u8 *msg)
{
	return NULL;
}
