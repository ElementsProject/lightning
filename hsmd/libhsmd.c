#include <ccan/crypto/hkdf_sha256/hkdf_sha256.h>
#include <common/bolt12_merkle.h>
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

/*~ ccan/compiler.h defines PRINTF_FMT as the gcc compiler hint so it will
 * check that fmt and other trailing arguments really are the correct type.
 */
/* This function is used to format an error message before passing it
 * to the library user specified hsmd_status_bad_request */
static u8 *hsmd_status_bad_request_fmt(struct hsmd_client *client,
				       const u8 *msg, const char *fmt, ...)
    PRINTF_FMT(3, 4);

static u8 *hsmd_status_bad_request_fmt(struct hsmd_client *client,
				       const u8 *msg, const char *fmt, ...)
{
	va_list ap;
	char *str;

	va_start(ap, fmt);
	str = tal_fmt(tmpctx, fmt, ap);
	va_end(ap);
	return hsmd_status_bad_request(client, msg, str);
}

/* Convenience wrapper for when we simply can't parse. */
static u8 *hsmd_status_malformed_request(struct hsmd_client *c, const u8 *msg_in)
{
	return hsmd_status_bad_request(c, msg_in, "could not parse request");
}

/*~ This returns the secret and/or public key for this node. */
static void node_key(struct privkey *node_privkey, struct pubkey *node_id)
{
	u32 salt = 0;
	struct privkey unused_s;
	struct pubkey unused_k;

	/* If caller specifies NULL, they don't want the results. */
	if (node_privkey == NULL)
		node_privkey = &unused_s;
	if (node_id == NULL)
		node_id = &unused_k;

	/*~ So, there is apparently a 1 in 2^127 chance that a random value is
	 * not a valid private key, so this never actually loops. */
	do {
		/*~ ccan/crypto/hkdf_sha256 implements RFC5869 "Hardened Key
		 * Derivation Functions".  That means that if a derived key
		 * leaks somehow, the other keys are not compromised. */
		hkdf_sha256(node_privkey, sizeof(*node_privkey),
			    &salt, sizeof(salt),
			    &secretstuff.hsm_secret,
			    sizeof(secretstuff.hsm_secret),
			    "nodeid", 6);
		salt++;
	} while (!secp256k1_ec_pubkey_create(secp256k1_ctx, &node_id->pubkey,
					     node_privkey->secret.data));

#if DEVELOPER
	/* In DEVELOPER mode, we can override with --dev-force-privkey */
	if (dev_force_privkey) {
		*node_privkey = *dev_force_privkey;
		if (!secp256k1_ec_pubkey_create(secp256k1_ctx, &node_id->pubkey,
						node_privkey->secret.data))
			hsmd_status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "Failed to derive pubkey for dev_force_privkey");
	}
#endif
}

/*~ This returns the secret and/or public x-only key for this node. */
static void node_schnorrkey(secp256k1_keypair *node_keypair,
			    struct pubkey32 *node_id32)
{
	secp256k1_keypair unused_kp;
	struct privkey node_privkey;

	if (!node_keypair)
		node_keypair = &unused_kp;

	node_key(&node_privkey, NULL);
	if (secp256k1_keypair_create(secp256k1_ctx, node_keypair,
				     node_privkey.secret.data) != 1)
		hsmd_status_failed(STATUS_FAIL_INTERNAL_ERROR,
				   "Failed to derive keypair");

	if (node_id32) {
		if (secp256k1_keypair_xonly_pub(secp256k1_ctx,
						&node_id32->pubkey,
						NULL, node_keypair) != 1)
			hsmd_status_failed(STATUS_FAIL_INTERNAL_ERROR,
					   "Failed to derive xonly pub");
	}
}

/*~ lightningd asks us to sign a message.  I tweeted the spec
 * in https://twitter.com/rusty_twit/status/1182102005914800128:
 *
 * @roasbeef & @bitconner point out that #lnd algo is:
 *    zbase32(SigRec(SHA256(SHA256("Lightning Signed Message:" + msg)))).
 * zbase32 from https://philzimmermann.com/docs/human-oriented-base-32-encoding.txt
 * and SigRec has first byte 31 + recovery id, followed by 64 byte sig.  #specinatweet
 */
static u8 *handle_sign_message(struct hsmd_client *c, const u8 *msg_in)
{
	u8 *msg;
	struct sha256_ctx sctx = SHA256_INIT;
	struct sha256_double shad;
	secp256k1_ecdsa_recoverable_signature rsig;
	struct privkey node_pkey;

	if (!fromwire_hsmd_sign_message(tmpctx, msg_in, &msg))
		return hsmd_status_malformed_request(c, msg_in);

	/* Prefixing by a known string means we'll never be convinced
	 * to sign some gossip message, etc. */
	sha256_update(&sctx, "Lightning Signed Message:",
		      strlen("Lightning Signed Message:"));
	sha256_update(&sctx, msg, tal_count(msg));
	sha256_double_done(&sctx, &shad);

	node_key(&node_pkey, NULL);
	/*~ By no small coincidence, this libsecp routine uses the exact
	 * recovery signature format mandated by BOLT 11. */
	if (!secp256k1_ecdsa_sign_recoverable(secp256k1_ctx, &rsig,
                                              shad.sha.u.u8,
                                              node_pkey.secret.data,
                                              NULL, NULL)) {
		return hsmd_status_bad_request(c, msg_in, "Failed to sign message");
	}

	return towire_hsmd_sign_message_reply(NULL, &rsig);
}

/*~ lightningd asks us to sign a bolt12 (e.g. offer). */
static u8 *handle_sign_bolt12(struct hsmd_client *c, const u8 *msg_in)
{
	char *messagename, *fieldname;
	struct sha256 merkle, sha;
	struct bip340sig sig;
	secp256k1_keypair kp;
	u8 *publictweak;

	if (!fromwire_hsmd_sign_bolt12(tmpctx, msg_in,
				       &messagename, &fieldname, &merkle,
				       &publictweak))
		return hsmd_status_malformed_request(c, msg_in);

	sighash_from_merkle(messagename, fieldname, &merkle, &sha);

	if (!publictweak) {
		node_schnorrkey(&kp, NULL);
	} else {
		/* If we're tweaking key, we use bolt12 key */
		struct pubkey32 bolt12;
		struct sha256 tweak;

		if (secp256k1_keypair_xonly_pub(secp256k1_ctx,
						&bolt12.pubkey, NULL,
						&secretstuff.bolt12) != 1)
			hsmd_status_failed(
			    STATUS_FAIL_INTERNAL_ERROR,
			    "Could not derive bolt12 public key.");
		payer_key_tweak(&bolt12, publictweak, tal_bytelen(publictweak),
				&tweak);

		kp = secretstuff.bolt12;

		if (secp256k1_keypair_xonly_tweak_add(secp256k1_ctx,
						      &kp,
						      tweak.u.u8) != 1) {
			return hsmd_status_bad_request_fmt(
			    c, msg_in, "Failed to get tweak key");
		}
	}

	if (!secp256k1_schnorrsig_sign(secp256k1_ctx, sig.u8,
				       sha.u.u8,
				       &kp,
				       NULL, NULL)) {
		return hsmd_status_bad_request_fmt(c, msg_in,
						   "Failed to sign bolt12");
	}

	return towire_hsmd_sign_bolt12_reply(NULL, &sig);
}

u8 *hsmd_handle_client_message(const tal_t *ctx, struct hsmd_client *client,
			       const u8 *msg)
{
	enum hsmd_wire t = fromwire_peektype(msg);

	hsmd_status_debug("Client: Received message %d from client", t);

	/* Before we do anything else, is this client allowed to do
	 * what he asks for? */
	if (!check_client_capabilities(client, t))
		return hsmd_status_bad_request_fmt(
		    client, msg, "does not have capability to run %d", t);

	/* If we aren't initialized yet we better get an init message
	 * first. Otherwise we don't load the secret and every
	 * signature we produce is just going to be junk. */
	if (!initialized && t != WIRE_HSMD_INIT)
		hsmd_status_failed(STATUS_FAIL_MASTER_IO,
			      "hsmd was not initialized correctly, expected "
			      "message type %d, got %d",
			      WIRE_HSMD_INIT, t);

	/* Now actually go and do what the client asked for */
	switch (t) {
	case WIRE_HSMD_INIT:
	case WIRE_HSMD_CLIENT_HSMFD:
	case WIRE_HSMD_GET_CHANNEL_BASEPOINTS:
	case WIRE_HSMD_GET_OUTPUT_SCRIPTPUBKEY:
	case WIRE_HSMD_ECDH_REQ:
	case WIRE_HSMD_CANNOUNCEMENT_SIG_REQ:
	case WIRE_HSMD_CUPDATE_SIG_REQ:
	case WIRE_HSMD_NODE_ANNOUNCEMENT_SIG_REQ:
	case WIRE_HSMD_SIGN_INVOICE:
	case WIRE_HSMD_SIGN_WITHDRAWAL:
	case WIRE_HSMD_SIGN_COMMITMENT_TX:
	case WIRE_HSMD_SIGN_DELAYED_PAYMENT_TO_US:
	case WIRE_HSMD_SIGN_REMOTE_HTLC_TO_US:
	case WIRE_HSMD_SIGN_PENALTY_TO_US:
	case WIRE_HSMD_SIGN_LOCAL_HTLC_TX:
	case WIRE_HSMD_GET_PER_COMMITMENT_POINT:
	case WIRE_HSMD_CHECK_FUTURE_SECRET:
	case WIRE_HSMD_SIGN_REMOTE_COMMITMENT_TX:
	case WIRE_HSMD_SIGN_REMOTE_HTLC_TX:
	case WIRE_HSMD_SIGN_MUTUAL_CLOSE_TX:
		/* Not implemented yet. Should not have been passed here yet. */
		return hsmd_status_bad_request_fmt(client, msg, "Not implemented yet.");

	case WIRE_HSMD_SIGN_BOLT12:
		return handle_sign_bolt12(client, msg);
	case WIRE_HSMD_SIGN_MESSAGE:
		return handle_sign_message(client, msg);

	case WIRE_HSMD_DEV_MEMLEAK:
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
	return hsmd_status_bad_request(client, msg, "Unknown request");
}
