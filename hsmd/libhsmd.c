#include "config.h"
#include <bitcoin/script.h>
#include <ccan/array_size/array_size.h>
#include <ccan/crypto/hkdf_sha256/hkdf_sha256.h>
#include <ccan/tal/str/str.h>
#include <common/bolt12_id.h>
#include <common/bolt12_merkle.h>
#include <common/hash_u5.h>
#include <common/key_derive.h>
#include <common/lease_rates.h>
#include <hsmd/libhsmd.h>
#include <hsmd/permissions.h>
#include <inttypes.h>
#include <secp256k1_ecdh.h>
#include <secp256k1_schnorrsig.h>
#include <sodium/utils.h>
#include <wally_psbt.h>

/* The negotiated protocol version ends up in here. */
u64 hsmd_mutual_version;

/* If they specify --dev-force-privkey it ends up in here. */
struct privkey *dev_force_privkey;
/* If they specify --dev-force-bip32-seed it ends up in here. */
struct secret *dev_force_bip32_seed;

/*~ Nobody will ever find it here!  hsm_secret is our root secret, the bip32
 * tree, bolt12 payer_id keys and derived_secret are derived from that, and
 * cached here. */
struct {
	struct secret hsm_secret;
	struct ext_key bip32;
	struct secret bolt12;
	struct secret derived_secret;
} secretstuff;

/* Have we initialized the secretstuff? */
bool initialized = false;

/* Do we fail all preapprove requests? */
bool dev_fail_preapprove = false;
bool dev_no_preapprove_check = false;

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
bool hsmd_check_client_capabilities(struct hsmd_client *client,
				    enum hsmd_wire t)
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
		return (client->capabilities & HSM_PERM_ECDH) != 0;

	case WIRE_HSMD_CANNOUNCEMENT_SIG_REQ:
	case WIRE_HSMD_CUPDATE_SIG_REQ:
	case WIRE_HSMD_NODE_ANNOUNCEMENT_SIG_REQ:
		return (client->capabilities & HSM_PERM_SIGN_GOSSIP) != 0;

	case WIRE_HSMD_SIGN_DELAYED_PAYMENT_TO_US:
	case WIRE_HSMD_SIGN_REMOTE_HTLC_TO_US:
	case WIRE_HSMD_SIGN_PENALTY_TO_US:
	case WIRE_HSMD_SIGN_LOCAL_HTLC_TX:
		return (client->capabilities & HSM_PERM_SIGN_ONCHAIN_TX) != 0;

	case WIRE_HSMD_GET_PER_COMMITMENT_POINT:
	case WIRE_HSMD_CHECK_FUTURE_SECRET:
	case WIRE_HSMD_SETUP_CHANNEL:
		return (client->capabilities & HSM_PERM_COMMITMENT_POINT) != 0;

	case WIRE_HSMD_SIGN_REMOTE_COMMITMENT_TX:
	case WIRE_HSMD_SIGN_REMOTE_HTLC_TX:
	case WIRE_HSMD_VALIDATE_COMMITMENT_TX:
	case WIRE_HSMD_REVOKE_COMMITMENT_TX:
	case WIRE_HSMD_VALIDATE_REVOCATION:
		return (client->capabilities & HSM_PERM_SIGN_REMOTE_TX) != 0;

	case WIRE_HSMD_SIGN_MUTUAL_CLOSE_TX:
		return (client->capabilities & HSM_PERM_SIGN_CLOSING_TX) != 0;

	case WIRE_HSMD_SIGN_SPLICE_TX:
		return (client->capabilities & HSM_PERM_SIGN_SPLICE_TX) != 0;

	case WIRE_HSMD_SIGN_OPTION_WILL_FUND_OFFER:
		return (client->capabilities & HSM_PERM_SIGN_WILL_FUND_OFFER) != 0;

	case WIRE_HSMD_CHECK_OUTPOINT:
	case WIRE_HSMD_LOCK_OUTPOINT:
		return (client->capabilities & HSM_PERM_LOCK_OUTPOINT) != 0;

	case WIRE_HSMD_INIT:
	case WIRE_HSMD_DEV_PREINIT:
	case WIRE_HSMD_NEW_CHANNEL:
 	case WIRE_HSMD_FORGET_CHANNEL:
	case WIRE_HSMD_CLIENT_HSMFD:
	case WIRE_HSMD_SIGN_WITHDRAWAL:
	case WIRE_HSMD_SIGN_INVOICE:
	case WIRE_HSMD_SIGN_COMMITMENT_TX:
	case WIRE_HSMD_GET_CHANNEL_BASEPOINTS:
	case WIRE_HSMD_DEV_MEMLEAK:
	case WIRE_HSMD_SIGN_MESSAGE:
	case WIRE_HSMD_GET_OUTPUT_SCRIPTPUBKEY:
	case WIRE_HSMD_SIGN_BOLT12:
	case WIRE_HSMD_SIGN_BOLT12_2:
	case WIRE_HSMD_PREAPPROVE_INVOICE:
	case WIRE_HSMD_PREAPPROVE_KEYSEND:
	case WIRE_HSMD_PREAPPROVE_INVOICE_CHECK:
	case WIRE_HSMD_PREAPPROVE_KEYSEND_CHECK:
	case WIRE_HSMD_DERIVE_SECRET:
	case WIRE_HSMD_CHECK_PUBKEY:
	case WIRE_HSMD_SIGN_ANY_PENALTY_TO_US:
	case WIRE_HSMD_SIGN_ANY_DELAYED_PAYMENT_TO_US:
	case WIRE_HSMD_SIGN_ANY_REMOTE_HTLC_TO_US:
	case WIRE_HSMD_SIGN_ANY_LOCAL_HTLC_TX:
	case WIRE_HSMD_SIGN_ANCHORSPEND:
	case WIRE_HSMD_SIGN_HTLC_TX_MINGLE:
	case WIRE_HSMD_SIGN_ANY_CANNOUNCEMENT_REQ:
		return (client->capabilities & HSM_PERM_MASTER) != 0;

	/*~ These are messages sent by the HSM so we should never receive them. */
	/* FIXME: Since we autogenerate these, we should really generate separate
	 * enums for replies to avoid this kind of clutter! */
	case WIRE_HSMD_ECDH_RESP:
	case WIRE_HSMD_CANNOUNCEMENT_SIG_REPLY:
	case WIRE_HSMD_CUPDATE_SIG_REPLY:
	case WIRE_HSMD_CLIENT_HSMFD_REPLY:
	case WIRE_HSMD_NEW_CHANNEL_REPLY:
	case WIRE_HSMD_SETUP_CHANNEL_REPLY:
	case WIRE_HSMD_CHECK_OUTPOINT_REPLY:
	case WIRE_HSMD_LOCK_OUTPOINT_REPLY:
 	case WIRE_HSMD_FORGET_CHANNEL_REPLY:
	case WIRE_HSMD_NODE_ANNOUNCEMENT_SIG_REPLY:
	case WIRE_HSMD_SIGN_WITHDRAWAL_REPLY:
	case WIRE_HSMD_SIGN_INVOICE_REPLY:
	case WIRE_HSMD_INIT_REPLY_V4:
	case WIRE_HSMSTATUS_CLIENT_BAD_REQUEST:
	case WIRE_HSMD_SIGN_COMMITMENT_TX_REPLY:
	case WIRE_HSMD_VALIDATE_COMMITMENT_TX_REPLY:
	case WIRE_HSMD_REVOKE_COMMITMENT_TX_REPLY:
	case WIRE_HSMD_VALIDATE_REVOCATION_REPLY:
	case WIRE_HSMD_SIGN_TX_REPLY:
	case WIRE_HSMD_SIGN_OPTION_WILL_FUND_OFFER_REPLY:
	case WIRE_HSMD_GET_PER_COMMITMENT_POINT_REPLY:
	case WIRE_HSMD_CHECK_FUTURE_SECRET_REPLY:
	case WIRE_HSMD_GET_CHANNEL_BASEPOINTS_REPLY:
	case WIRE_HSMD_DEV_MEMLEAK_REPLY:
	case WIRE_HSMD_SIGN_MESSAGE_REPLY:
	case WIRE_HSMD_GET_OUTPUT_SCRIPTPUBKEY_REPLY:
	case WIRE_HSMD_SIGN_BOLT12_REPLY:
	case WIRE_HSMD_SIGN_BOLT12_2_REPLY:
	case WIRE_HSMD_PREAPPROVE_INVOICE_REPLY:
	case WIRE_HSMD_PREAPPROVE_KEYSEND_REPLY:
	case WIRE_HSMD_PREAPPROVE_INVOICE_CHECK_REPLY:
	case WIRE_HSMD_PREAPPROVE_KEYSEND_CHECK_REPLY:
	case WIRE_HSMD_DERIVE_SECRET_REPLY:
	case WIRE_HSMD_CHECK_PUBKEY_REPLY:
	case WIRE_HSMD_SIGN_ANCHORSPEND_REPLY:
	case WIRE_HSMD_SIGN_HTLC_TX_MINGLE_REPLY:
	case WIRE_HSMD_SIGN_ANY_CANNOUNCEMENT_REPLY:
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

	/* In --developer mode, we can override with --dev-force-privkey */
	if (dev_force_privkey) {
		*node_privkey = *dev_force_privkey;
		if (!secp256k1_ec_pubkey_create(secp256k1_ctx, &node_id->pubkey,
						node_privkey->secret.data))
			hsmd_status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "Failed to derive pubkey for dev_force_privkey");
	}
}

/*~ This returns the secret key for this node. */
static void node_schnorrkey(secp256k1_keypair *node_keypair)
{
	struct privkey node_privkey;

	node_key(&node_privkey, NULL);
	if (secp256k1_keypair_create(secp256k1_ctx, node_keypair,
				     node_privkey.secret.data) != 1)
		hsmd_status_failed(STATUS_FAIL_INTERNAL_ERROR,
				   "Failed to derive keypair");
}

/*~ This secret is the basis for all per-channel secrets: the per-channel seeds
 * will be generated by mixing in the dbid and the peer node_id. */
static void hsm_channel_secret_base(struct secret *channel_seed_base)
{
	hkdf_sha256(channel_seed_base, sizeof(struct secret), NULL, 0,
		    &secretstuff.hsm_secret, sizeof(secretstuff.hsm_secret),
		    /*~ Initially, we didn't support multiple channels per
		     * peer at all: a channel had to be completely forgotten
		     * before another could exist.  That was slightly relaxed,
		     * but the phrase "peer seed" is wired into the seed
		     * generation here, so we need to keep it that way for
		     * existing clients, rather than using "channel seed". */
		    "peer seed", strlen("peer seed"));
}

/* This will derive pseudorandom secret Key from a derived key */
static u8 *handle_derive_secret(struct hsmd_client *c, const u8 *msg_in)
{
	u8 *info;
	struct secret secret;

	if (!fromwire_hsmd_derive_secret(tmpctx, msg_in, &info))
		return hsmd_status_malformed_request(c, msg_in);

	hkdf_sha256(&secret, sizeof(struct secret), NULL, 0,
		    &secretstuff.derived_secret, sizeof(secretstuff.derived_secret),
		    info, tal_bytelen(info));

	return towire_hsmd_derive_secret_reply(NULL, &secret);
}

/*~ This gets the seed for this particular channel. */
static void get_channel_seed(const struct node_id *peer_id, u64 dbid,
			     struct secret *channel_seed)
{
	struct secret channel_base;
	u8 input[sizeof(peer_id->k) + sizeof(dbid)];
	/*~ Again, "per-peer" should be "per-channel", but Hysterical Raisins */
	const char *info = "per-peer seed";

	/*~ We use the DER encoding of the pubkey, because it's platform
	 * independent.  Since the dbid is unique, however, it's completely
	 * unnecessary, but again, existing users can't be broken. */
	/* FIXME: lnd has a nicer BIP32 method for deriving secrets which we
	 * should migrate to. */
	hsm_channel_secret_base(&channel_base);
	memcpy(input, peer_id->k, sizeof(peer_id->k));
	BUILD_ASSERT(sizeof(peer_id->k) == PUBKEY_CMPR_LEN);
	/*~ For all that talk about platform-independence, note that this
	 * field is endian-dependent!  But let's face it, little-endian won.
	 * In related news, we don't support EBCDIC or middle-endian. */
	memcpy(input + PUBKEY_CMPR_LEN, &dbid, sizeof(dbid));

	hkdf_sha256(channel_seed, sizeof(*channel_seed),
		    input, sizeof(input),
		    &channel_base, sizeof(channel_base),
		    info, strlen(info));
}

/* ~This stub implementation is overriden by fully validating signers
 * that need to manage per-channel state. */
static u8 *handle_new_channel(struct hsmd_client *c, const u8 *msg_in)
{
	struct node_id peer_id;
	u64 dbid;

	if (!fromwire_hsmd_new_channel(msg_in, &peer_id, &dbid))
		return hsmd_status_malformed_request(c, msg_in);

	/* Stub implementation */

	return towire_hsmd_new_channel_reply(NULL);
}

static bool mem_is_zero(const void *mem, size_t len)
{
	size_t i;
	for (i = 0; i < len; ++i)
		if (((const unsigned char *)mem)[i])
			return false;
	return true;
}

/* ~This stub implementation is overriden by fully validating signers
 * that need the unchanging channel parameters. */
static u8 *handle_setup_channel(struct hsmd_client *c, const u8 *msg_in)
{
	bool is_outbound;
	struct amount_sat channel_value;
	struct amount_msat push_value;
	struct bitcoin_txid funding_txid;
	u16 funding_txout;
	u16 local_to_self_delay;
	u8 *local_shutdown_script;
	u32 *local_shutdown_wallet_index;
	struct basepoints remote_basepoints;
	struct pubkey remote_funding_pubkey;
	u16 remote_to_self_delay;
	u8 *remote_shutdown_script;
	struct amount_msat value_msat;
	struct channel_type *channel_type;

	if (!fromwire_hsmd_setup_channel(tmpctx, msg_in, &is_outbound,
					&channel_value, &push_value, &funding_txid,
					&funding_txout, &local_to_self_delay,
					&local_shutdown_script,
					&local_shutdown_wallet_index,
					&remote_basepoints,
					&remote_funding_pubkey,
					&remote_to_self_delay,
					&remote_shutdown_script,
					&channel_type))
		return hsmd_status_malformed_request(c, msg_in);

	/* Stub implementation */

	/* Fail fast if any values are uninitialized or obviously wrong. */
	assert(amount_sat_greater(channel_value, AMOUNT_SAT(0)));
	assert(amount_sat_to_msat(&value_msat, channel_value));
	assert(!mem_is_zero(&funding_txid, sizeof(funding_txid)));
	assert(local_to_self_delay > 0);
	assert(remote_to_self_delay > 0);

	return towire_hsmd_setup_channel_reply(NULL);
}

/* ~This stub implementation is overriden by fully validating signers
 * that need to manage per-channel state. */
static u8 *handle_forget_channel(struct hsmd_client *c, const u8 *msg_in)
{
	struct node_id peer_id;
	u64 dbid;

	if (!fromwire_hsmd_forget_channel(msg_in, &peer_id, &dbid))
		return hsmd_status_malformed_request(c, msg_in);

	/* Stub implementation */

	return towire_hsmd_forget_channel_reply(NULL);
}

/* ~This stub implementation is overriden by fully validating signers
 * to ensure they are caught up when outpoints are freshly buried */
static u8 *handle_check_outpoint(struct hsmd_client *c, const u8 *msg_in)
{
	struct bitcoin_txid funding_txid;
	u16 funding_txout;
	bool is_buried;

	if (!fromwire_hsmd_check_outpoint(msg_in, &funding_txid, &funding_txout))
		return hsmd_status_malformed_request(c, msg_in);

	/* This stub always approves */
	is_buried = true;

	return towire_hsmd_check_outpoint_reply(NULL, is_buried);
}

/* ~This stub implementation is overriden by fully validating signers to
 * change their funding/splice state to locked */
static u8 *handle_lock_outpoint(struct hsmd_client *c, const u8 *msg_in)
{
	struct bitcoin_txid funding_txid;
	u16 funding_txout;

	if (!fromwire_hsmd_lock_outpoint(msg_in, &funding_txid, &funding_txout))
		return hsmd_status_malformed_request(c, msg_in);

	/* Stub implementation */

	return towire_hsmd_lock_outpoint_reply(NULL);
}

/*~ For almost every wallet tx we use the BIP32 seed, but not for onchain
 * unilateral closes from a peer: they (may) have an output to us using a
 * public key based on the channel basepoints.  It's a bit spammy to spend
 * those immediately just to make the wallet simpler, and we didn't appreciate
 * the problem when we designed the protocol for commitment transaction keys.
 *
 * So we store just enough about the channel it came from (which may be
 * long-gone) to regenerate the keys here.  That has the added advantage that
 * the secrets themselves stay within the HSM. */
static void hsm_unilateral_close_privkey(struct privkey *dst,
					 struct unilateral_close_info *info)
{
	struct secret channel_seed;
	struct basepoints basepoints;
	struct secrets secrets;

	get_channel_seed(&info->peer_id, info->channel_id, &channel_seed);
	derive_basepoints(&channel_seed, NULL, &basepoints, &secrets, NULL);

	/* BOLT #3:
	 *
	 * ### `remotepubkey` Derivation
	 *
	 * The `remotepubkey` is simply the remote node's `payment_basepoint`.
	 */
	/* The old BOLT defined what happened prior to option_static_remotekey,
	 * which we still support for existing channels:
	 *
	 * If `option_static_remotekey` or `option_anchors` is
	 * negotiated, the `remotepubkey` is simply the remote node's
	 * `payment_basepoint`, otherwise it is calculated as above using the
	 * remote node's `payment_basepoint`.
	 */
	/* In our UTXO representation, this is indicated by a NULL
	 * commitment_point. */
	if (!info->commitment_point)
		dst->secret = secrets.payment_basepoint_secret;
	else if (!derive_simple_privkey(&secrets.payment_basepoint_secret,
					&basepoints.payment,
					info->commitment_point,
					dst)) {
		hsmd_status_failed(STATUS_FAIL_INTERNAL_ERROR,
				   "Deriving unilateral_close_privkey");
	}
}

/*~ Get the keys for this given BIP32 index: if privkey is NULL, we
 * don't fill it in. */
static void bitcoin_key(struct privkey *privkey, struct pubkey *pubkey,
			u32 index)
{
	struct ext_key ext;
	struct privkey unused_priv;

	if (privkey == NULL)
		privkey = &unused_priv;

	if (index >= BIP32_INITIAL_HARDENED_CHILD)
		hsmd_status_failed(STATUS_FAIL_MASTER_IO, "Index %u too great",
				   index);

	/*~ This uses libwally, which doesn't dovetail directly with
	 * libsecp256k1 even though it, too, uses it internally. */
	if (bip32_key_from_parent(&secretstuff.bip32, index,
				  BIP32_FLAG_KEY_PRIVATE, &ext) != WALLY_OK)
		hsmd_status_failed(STATUS_FAIL_INTERNAL_ERROR,
				   "BIP32 of %u failed", index);

	/* libwally says: The private key with prefix byte 0; remove it
	 * for libsecp256k1. */
	memcpy(privkey->secret.data, ext.priv_key+1, 32);
	if (!secp256k1_ec_pubkey_create(secp256k1_ctx, &pubkey->pubkey,
					privkey->secret.data))
		hsmd_status_failed(STATUS_FAIL_INTERNAL_ERROR,
				   "BIP32 pubkey %u create failed", index);
}

/* This gets the bitcoin private key needed to spend from our wallet */
static void hsm_key_for_utxo(struct privkey *privkey, struct pubkey *pubkey,
			     const struct utxo *utxo)
{
	if (utxo->close_info != NULL) {
		/* This is a their_unilateral_close/to-us output, so
		 * we need to derive the secret the long way */
		hsmd_status_debug("Unilateral close output, deriving secrets");
		hsm_unilateral_close_privkey(privkey, utxo->close_info);
		pubkey_from_privkey(privkey, pubkey);
		hsmd_status_debug("Derived public key %s from unilateral close",
				  fmt_pubkey(tmpctx, pubkey));
	} else {
		/* Simple case: just get derive via HD-derivation */
		bitcoin_key(privkey, pubkey, utxo->keyindex);
	}
}

/* Find our inputs by the pubkey associated with the inputs, and
 * add a partial sig for each */
static void sign_our_inputs(struct utxo **utxos, struct wally_psbt *psbt)
{
	for (size_t i = 0; i < tal_count(utxos); i++) {
		struct utxo *utxo = utxos[i];
		for (size_t j = 0; j < psbt->num_inputs; j++) {
			struct privkey privkey;
			struct pubkey pubkey;

			if (!wally_psbt_input_spends(&psbt->inputs[j],
						   &utxo->outpoint))
				continue;

			hsm_key_for_utxo(&privkey, &pubkey, utxo);

			/* This line is basically the entire reason we have
			 * to iterate through to match the psbt input
			 * to the UTXO -- otherwise we would just
			 * call wally_psbt_sign for every utxo privkey
			 * and be done with it. We can't do that though
			 * because any UTXO that's derived from channel_info
			 * requires the HSM to find the pubkey, and we
			 * skip doing that until now as a bit of a reduction
			 * of complexity in the calling code */
			const size_t script_len = tal_bytelen(utxo->scriptPubkey);
			psbt_input_add_pubkey(psbt, j, &pubkey,
					      is_p2tr(utxo->scriptPubkey, script_len, NULL));

			/* It's actually a P2WSH in this case. */
			if (utxo->close_info && utxo->close_info->option_anchors) {
				const u8 *wscript
					= bitcoin_wscript_to_remote_anchored(tmpctx,
									     &pubkey,
									     utxo->close_info->csv);
				psbt_input_set_witscript(psbt, j, wscript);
				psbt_input_set_wit_utxo(psbt, j,
							scriptpubkey_p2wsh(psbt, wscript),
							utxo->amount);
			}
			tal_wally_start();
			if (wally_psbt_sign(psbt, privkey.secret.data,
					    sizeof(privkey.secret.data),
					    EC_FLAG_GRIND_R) != WALLY_OK) {
				tal_wally_end(psbt);
				/* Converting to v0 for log consumption */
				psbt_set_version(psbt, 0);
				hsmd_status_failed(STATUS_FAIL_INTERNAL_ERROR,
				    "Received wally_err attempting to "
				    "sign input %zu with key %s. PSBT: %s",
				    j, fmt_pubkey(tmpctx, &pubkey),
				    fmt_wally_psbt(tmpctx, psbt));
			}
			tal_wally_end(psbt);
		}
	}
}

/*~ This covers several cases where onchaind is creating a transaction which
 * sends funds to our internal wallet. */
/* FIXME: Derive output address for this client, and check it here! */
static u8 *handle_sign_to_us_tx(struct hsmd_client *c, const u8 *msg_in,
				u32 input_num,
				struct bitcoin_tx *tx,
				const struct privkey *privkey,
				const u8 *wscript,
				enum sighash_type sighash_type)
{
	struct bitcoin_signature sig;
	struct pubkey pubkey;

	if (input_num >= tx->wtx->num_inputs)
		return hsmd_status_bad_request_fmt(c, msg_in,
						   "bad input %u of %zu",
						   input_num, tx->wtx->num_inputs);

	if (!pubkey_from_privkey(privkey, &pubkey))
		return hsmd_status_bad_request(c, msg_in,
					       "bad pubkey_from_privkey");

	if (tx->wtx->num_inputs != 1)
		return hsmd_status_bad_request(c, msg_in, "bad txinput count");

	sign_tx_input(tx, 0, NULL, wscript, privkey, &pubkey, sighash_type, &sig);

	return towire_hsmd_sign_tx_reply(NULL, &sig);
}

/* This will check lightningd's key derivation: hopefully any errors in
 * this process are independent of errors in lightningd! */
static u8 *handle_check_pubkey(struct hsmd_client *c, const u8 *msg_in)
{
	u32 index;
	struct pubkey their_pubkey, our_pubkey;
	struct privkey our_privkey;

	if (!fromwire_hsmd_check_pubkey(msg_in, &index, &their_pubkey))
		return hsmd_status_malformed_request(c, msg_in);

	/* We abort if lightningd asks for a stupid index. */
	bitcoin_key(&our_privkey, &our_pubkey, index);
	if (!pubkey_eq(&our_pubkey, &their_pubkey)) {
		hsmd_status_failed(STATUS_FAIL_INTERNAL_ERROR,
				   "BIP32 derivation index %u differed:"
				   " they got %s, we got %s",
				   index,
				   fmt_pubkey(tmpctx, &their_pubkey),
				   fmt_pubkey(tmpctx, &our_pubkey));
	}

	return towire_hsmd_check_pubkey_reply(NULL, true);
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

/*~ lightningd asks us to sign a liquidity ad offer */
static u8 *handle_sign_option_will_fund_offer(struct hsmd_client *c,
					      const u8 *msg_in)
{
	struct pubkey funding_pubkey;
	u32 lease_expiry, channel_fee_base_max_msat;
	u16 channel_fee_max_ppt;
	struct sha256 sha;
	secp256k1_ecdsa_signature sig;
	struct privkey node_pkey;

	if (!fromwire_hsmd_sign_option_will_fund_offer(msg_in,
						       &funding_pubkey,
						       &lease_expiry,
						       &channel_fee_base_max_msat,
						       &channel_fee_max_ppt))
		return hsmd_status_malformed_request(c, msg_in);

	lease_rates_get_commitment(&funding_pubkey, lease_expiry,
				   channel_fee_base_max_msat,
				   channel_fee_max_ppt,
				   &sha);

	node_key(&node_pkey, NULL);

	if (!secp256k1_ecdsa_sign(secp256k1_ctx, &sig,
				  sha.u.u8,
				  node_pkey.secret.data,
				  NULL, NULL))
		return hsmd_status_bad_request(c, msg_in,
					       "Failed to sign message");

	return towire_hsmd_sign_option_will_fund_offer_reply(NULL, &sig);
}

static void payer_key_tweak(const struct pubkey *bolt12,
			    const u8 *publictweak, size_t publictweaklen,
			    struct sha256 *tweak)
{
	u8 rawkey[PUBKEY_CMPR_LEN];
	struct sha256_ctx sha;

	pubkey_to_der(rawkey, bolt12);

	sha256_init(&sha);
	sha256_update(&sha, rawkey, sizeof(rawkey));
	sha256_update(&sha, publictweak, publictweaklen);
	sha256_done(&sha, tweak);
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
		node_schnorrkey(&kp);
	} else {
		/* If we're tweaking key, we use bolt12 key */
		struct privkey tweakedkey;
		struct pubkey bolt12;
		struct sha256 tweak;

		if (secp256k1_ec_pubkey_create(secp256k1_ctx, &bolt12.pubkey,
					       secretstuff.bolt12.data) != 1)
			hsmd_status_failed(STATUS_FAIL_INTERNAL_ERROR,
					   "Could derive bolt12 public key.");

		payer_key_tweak(&bolt12, publictweak, tal_bytelen(publictweak),
				&tweak);

		tweakedkey.secret = secretstuff.bolt12;
		if (secp256k1_ec_seckey_tweak_add(secp256k1_ctx,
						  tweakedkey.secret.data,
						  tweak.u.u8) != 1)
			hsmd_status_failed(STATUS_FAIL_INTERNAL_ERROR,
					   "Could tweak bolt12 key.");

		if (secp256k1_keypair_create(secp256k1_ctx, &kp,
					     tweakedkey.secret.data) != 1)
			hsmd_status_failed(STATUS_FAIL_INTERNAL_ERROR,
					   "Failed to derive bolt12 keypair");
	}

	if (!secp256k1_schnorrsig_sign32(secp256k1_ctx, sig.u8,
				       sha.u.u8,
				       &kp,
				       NULL)) {
		return hsmd_status_bad_request_fmt(c, msg_in,
						   "Failed to sign bolt12");
	}

	return towire_hsmd_sign_bolt12_reply(NULL, &sig);
}

/*~ lightningd asks us to sign a bolt12 (e.g. offer): modern version */
static u8 *handle_sign_bolt12_2(struct hsmd_client *c, const u8 *msg_in)
{
	char *messagename, *fieldname;
	struct sha256 merkle, sha;
	struct bip340sig sig;
	secp256k1_keypair kp;
	u8 *info;
	u8 *tweakmessage;

	if (!fromwire_hsmd_sign_bolt12_2(tmpctx, msg_in,
					 &messagename, &fieldname, &merkle,
					 &info, &tweakmessage))
		return hsmd_status_malformed_request(c, msg_in);

	sighash_from_merkle(messagename, fieldname, &merkle, &sha);

	if (tweakmessage) {
		struct secret base_secret;
		struct sha256 tweak;
		struct privkey tweakedkey;

		/* See handle_derive_secret: this gives a base secret. */
		hkdf_sha256(&base_secret, sizeof(base_secret), NULL, 0,
			    &secretstuff.derived_secret,
			    sizeof(secretstuff.derived_secret),
			    info, tal_bytelen(info));

		/* This is simply SHA256(secret || tweakmessage) */
		bolt12_alias_tweak(&base_secret,
				   tweakmessage, tal_bytelen(tweakmessage),
				   &tweak);

		node_key(&tweakedkey, NULL);
		if (secp256k1_ec_seckey_tweak_add(secp256k1_ctx,
						  tweakedkey.secret.data,
						  tweak.u.u8) != 1)
			hsmd_status_failed(STATUS_FAIL_INTERNAL_ERROR,
					   "Couldn't tweak key.");
		if (secp256k1_keypair_create(secp256k1_ctx, &kp,
					     tweakedkey.secret.data) != 1)
			hsmd_status_failed(STATUS_FAIL_INTERNAL_ERROR,
					   "Failed to derive tweaked keypair");
	} else {
		node_schnorrkey(&kp);
	}

	if (!secp256k1_schnorrsig_sign32(secp256k1_ctx, sig.u8,
				       sha.u.u8,
				       &kp,
				       NULL)) {
		return hsmd_status_bad_request_fmt(c, msg_in,
						   "Failed to sign bolt12");
	}

	return towire_hsmd_sign_bolt12_2_reply(NULL, &sig);
}

/*~ lightningd asks us to approve an invoice. This stub implementation
 * is overriden by fully validating signers that need to track invoice
 * payments. */
static u8 *handle_preapprove_invoice(struct hsmd_client *c, const u8 *msg_in)
{
	char *invstring;
	bool approved;
	bool check_only = false;

	if (!fromwire_hsmd_preapprove_invoice(tmpctx, msg_in, &invstring)
	    && !fromwire_hsmd_preapprove_invoice_check(tmpctx, msg_in, &invstring, &check_only))
		return hsmd_status_malformed_request(c, msg_in);

	hsmd_status_debug("preapprove_invoice: check_only=%u", check_only);

	/* This stub always approves unless overridden */
	approved = !dev_fail_preapprove;

	return towire_hsmd_preapprove_invoice_reply(NULL, approved);
}

/*~ lightningd asks us to approve a keysend payment. This stub implementation
 * is overriden by fully validating signers that need to track keysend
 * payments. */
static u8 *handle_preapprove_keysend(struct hsmd_client *c, const u8 *msg_in)
{
	struct node_id destination;
	struct sha256 payment_hash;
	struct amount_msat amount_msat;
	bool approved;
	bool check_only = false;

	if (!fromwire_hsmd_preapprove_keysend(msg_in, &destination, &payment_hash, &amount_msat)
	    && !fromwire_hsmd_preapprove_keysend_check(msg_in, &destination, &payment_hash,
						       &amount_msat, &check_only)) {
		return hsmd_status_malformed_request(c, msg_in);
	}

	hsmd_status_debug("preapprove_keysend: check_only=%u", check_only);

	/* This stub always approves unless overridden */
	approved = !dev_fail_preapprove;

	return towire_hsmd_preapprove_keysend_reply(NULL, approved);
}

/*~ Lightning invoices, defined by BOLT 11, are signed.  This has been
 * surprisingly controversial; it means a node needs to be online to create
 * invoices.  However, it seems clear to me that in a world without
 * intermedaries you need proof that you have received an offer (the
 * signature), as well as proof that you've paid it (the preimage). */
static u8 *handle_sign_invoice(struct hsmd_client *c, const u8 *msg_in)
{
	/*~ We make up a 'u5' type to represent BOLT11's 5-bits-per-byte
	 * format: it's only for human consumption, as typedefs are almost
	 * entirely transparent to the C compiler. */
	u5 *u5bytes;
	u8 *hrpu8;
	char *hrp;
	struct sha256 sha;
        secp256k1_ecdsa_recoverable_signature rsig;
	struct hash_u5 hu5;
	struct privkey node_pkey;

	if (!fromwire_hsmd_sign_invoice(tmpctx, msg_in, &u5bytes, &hrpu8))
		return hsmd_status_malformed_request(c, msg_in);

	/* BOLT #11:
	 *
	 * A writer... MUST set `signature` to a valid 512-bit
	 * secp256k1 signature of the SHA2 256-bit hash of the
	 * human-readable part, represented as UTF-8 bytes,
	 * concatenated with the data part (excluding the signature)
	 * with 0 bits appended to pad the data to the next byte
	 * boundary, with a trailing byte containing the recovery ID
	 * (0, 1, 2, or 3).
	 */

	/* FIXME: Check invoice! */

	/*~ tal_dup_arr() does what you'd expect: allocate an array by copying
	 * another; the cast is needed because the hrp is a 'char' array, not
	 * a 'u8' (unsigned char) as it's the "human readable" part.
	 *
	 * The final arg of tal_dup_arr() is how many extra bytes to allocate:
	 * it's so often zero that I've thought about dropping the argument, but
	 * in cases like this (adding a NUL terminator) it's perfect. */
	hrp = tal_dup_arr(tmpctx, char, (char *)hrpu8, tal_count(hrpu8), 1);
	hrp[tal_count(hrpu8)] = '\0';

	hash_u5_init(&hu5, hrp);
	hash_u5(&hu5, u5bytes, tal_count(u5bytes));
	hash_u5_done(&hu5, &sha);

	node_key(&node_pkey, NULL);
	/*~ By no small coincidence, this libsecp routine uses the exact
	 * recovery signature format mandated by BOLT 11. */
	if (!secp256k1_ecdsa_sign_recoverable(secp256k1_ctx, &rsig,
                                              (const u8 *)&sha,
                                              node_pkey.secret.data,
                                              NULL, NULL)) {
		return hsmd_status_bad_request_fmt(c, msg_in,
						   "Failed to sign invoice");
	}

	return towire_hsmd_sign_invoice_reply(NULL, &rsig);
}

/*~ This gets the basepoints for a channel; it's not private information really
 * (we tell the peer this to establish a channel, as it sets up the keys used
 * for each transaction).
 *
 * Note that this is asked by lightningd, so it tells us what channels it wants.
 */
static u8 *handle_get_channel_basepoints(struct hsmd_client *c,
					 const u8 *msg_in)
{
	struct node_id peer_id;
	u64 dbid;
	struct secret seed;
	struct basepoints basepoints;
	struct pubkey funding_pubkey;

	if (!fromwire_hsmd_get_channel_basepoints(msg_in, &peer_id, &dbid))
		return hsmd_status_malformed_request(c, msg_in);

	get_channel_seed(&peer_id, dbid, &seed);
	derive_basepoints(&seed, &funding_pubkey, &basepoints, NULL, NULL);

	return towire_hsmd_get_channel_basepoints_reply(NULL, &basepoints,
							&funding_pubkey);
}

/*~ The client has asked us to extract the shared secret from an EC Diffie
 * Hellman token.  This doesn't leak any information, but requires the private
 * key, so the hsmd performs it.  It's used to set up an encryption key for the
 * connection handshaking (BOLT #8) and for the onion wrapping (BOLT #4). */
static u8 *handle_ecdh(struct hsmd_client *c, const u8 *msg_in)
{
	struct privkey privkey;
	struct pubkey point;
	struct secret ss;

	if (!fromwire_hsmd_ecdh_req(msg_in, &point))
		return hsmd_status_malformed_request(c, msg_in);

	/*~ We simply use the secp256k1_ecdh function: if privkey.secret.data is invalid,
	 * we kill them for bad randomness (~1 in 2^127 if privkey.secret.data is random) */
	node_key(&privkey, NULL);
	if (secp256k1_ecdh(secp256k1_ctx, ss.data, &point.pubkey,
			   privkey.secret.data, NULL, NULL) != 1) {
		return hsmd_status_bad_request_fmt(c, msg_in,
						   "secp256k1_ecdh fail");
	}

	/*~ In the normal case, we return the shared secret, and then read
	 * the next msg. */
	return towire_hsmd_ecdh_resp(NULL, &ss);
}

/*~ This is used when the remote peer claims to have knowledge of future
 * commitment states (option_data_loss_protect in the spec) which means we've
 * been restored from backup or something, and may have already revealed
 * secrets.  We carefully check that this is true, here. */
static u8 *handle_check_future_secret(struct hsmd_client *c, const u8 *msg_in)
{
	struct secret channel_seed;
	struct sha256 shaseed;
	u64 n;
	struct secret secret, suggested;

	if (!fromwire_hsmd_check_future_secret(msg_in, &n, &suggested))
		return hsmd_status_malformed_request(c, msg_in);

	get_channel_seed(&c->id, c->dbid, &channel_seed);
	if (!derive_shaseed(&channel_seed, &shaseed))
		return hsmd_status_bad_request_fmt(c, msg_in,
						   "bad derive_shaseed");

	if (!per_commit_secret(&shaseed, &secret, n))
		return hsmd_status_bad_request_fmt(
		    c, msg_in, "bad commit secret #%" PRIu64, n);

	/*~ Note the special secret_eq_consttime: we generate foo_eq for many
	 * types using ccan/structeq, but not 'struct secret' because any
	 * comparison risks leaking information about the secret if it is
	 * timing dependent. */
	return towire_hsmd_check_future_secret_reply(
	    NULL, secret_eq_consttime(&secret, &suggested));
}

static u8 *handle_get_output_scriptpubkey(struct hsmd_client *c,
					  const u8 *msg_in)
{
	struct pubkey pubkey;
	struct privkey privkey;
	struct unilateral_close_info info;
	u8 *scriptPubkey;

	info.commitment_point = NULL;
	if (!fromwire_hsmd_get_output_scriptpubkey(tmpctx, msg_in,
						  &info.channel_id,
						  &info.peer_id,
						  &info.commitment_point))
		return hsmd_status_malformed_request(c, msg_in);

	hsm_unilateral_close_privkey(&privkey, &info);
	pubkey_from_privkey(&privkey, &pubkey);
	scriptPubkey = scriptpubkey_p2wpkh(tmpctx, &pubkey);

	return towire_hsmd_get_output_scriptpubkey_reply(NULL,
								       scriptPubkey);
}

/*~ The specific routine to sign the channel_announcement message.  This is
 * defined in BOLT #7, and requires *two* signatures: one from this node's key
 * (to prove it's from us), and one from the bitcoin key used to create the
 * funding transaction (to prove we own the output). */
static const char *handle_sign_cannouncement(const tal_t *ctx,
					     const struct node_id *peer_id,
					     u64 dbid,
					     const u8 *ca,
					     secp256k1_ecdsa_signature *node_sig,
					     secp256k1_ecdsa_signature *bitcoin_sig)
{
	/*~ Our autogeneration code doesn't define field offsets, so we just
	 * copy this from the spec itself.
	 *
	 * Note that 'check-source' will actually find and check this quote
	 * against the spec (if available); whitespace is ignored and
	 * "..." means some content is skipped, but it works remarkably well to
	 * track spec changes. */

	/* BOLT #7:
	 *
	 * - MUST compute the double-SHA256 hash `h` of the message, beginning
	 *   at offset 256, up to the end of the message.
	 *     - Note: the hash skips the 4 signatures but hashes the rest of the
	 *       message, including any future fields appended to the end.
	 */
	/* First type bytes are the msg type */
	size_t offset = 2 + 256;
	struct privkey node_pkey;
	struct sha256_double hash;
	struct pubkey funding_pubkey;
	struct privkey funding_privkey;
	struct secret channel_seed;

	/*~ You'll find FIXMEs like this scattered through the code.
	 * Sometimes they suggest simple improvements which someone like
	 * yourself should go ahead an implement.  Sometimes they're deceptive
	 * quagmires which will cause you nothing but grief.  You decide! */

	/*~ Christian uses TODO(cdecker) or FIXME(cdecker), but I'm sure he won't
	 * mind if you fix this for him! */

	/* FIXME: We should cache these. */
 	get_channel_seed(peer_id, dbid, &channel_seed);
	derive_funding_key(&channel_seed, &funding_pubkey, &funding_privkey);

	if (tal_count(ca) < offset)
		return tal_fmt(ctx, "bad cannounce length %zu", tal_count(ca));

	if (fromwire_peektype(ca) != WIRE_CHANNEL_ANNOUNCEMENT)
		return tal_fmt(ctx, "Invalid channel announcement");

	node_key(&node_pkey, NULL);
	sha256_double(&hash, ca + offset, tal_count(ca) - offset);

	sign_hash(&node_pkey, &hash, node_sig);
	sign_hash(&funding_privkey, &hash, bitcoin_sig);
	return NULL;
}

static u8 *handle_cannouncement_sig(struct hsmd_client *c, const u8 *msg_in)
{
	u8 *ca;
	secp256k1_ecdsa_signature node_sig, bitcoin_sig;
	const char *err;

	/*~ fromwire_ routines which need to do allocation take a tal context
	 * as their first field; tmpctx is good here since we won't need it
	 * after this function. */
	if (!fromwire_hsmd_cannouncement_sig_req(tmpctx, msg_in, &ca))
		return hsmd_status_malformed_request(c, msg_in);

	err = handle_sign_cannouncement(tmpctx, &c->id, c->dbid, ca,
					&node_sig, &bitcoin_sig);
	if (err)
		return hsmd_status_bad_request_fmt(c, msg_in, "%s", err);

	return towire_hsmd_cannouncement_sig_reply(NULL, &node_sig, &bitcoin_sig);
}

/* This variant is used by modern lightningd to sign for a particular channel */
static u8 *handle_any_cannouncement_sig(struct hsmd_client *c, const u8 *msg_in)
{
	u8 *ca;
	struct node_id peer_id;
	u64 dbid;
	secp256k1_ecdsa_signature node_sig, bitcoin_sig;
	const char *err;

	if (!fromwire_hsmd_sign_any_cannouncement_req(tmpctx, msg_in, &ca, &peer_id, &dbid))
		return hsmd_status_malformed_request(c, msg_in);

	err = handle_sign_cannouncement(tmpctx, &peer_id, dbid, ca,
					&node_sig, &bitcoin_sig);
	if (err)
		return hsmd_status_bad_request_fmt(c, msg_in, "%s", err);

	return towire_hsmd_sign_any_cannouncement_reply(NULL, &node_sig, &bitcoin_sig);
}

/*~ It's optional for nodes to send node_announcement, but it lets us set our
 * favourite color and cool alias!  Plus other minor details like how to
 * connect to us. */
static u8 *handle_sign_node_announcement(struct hsmd_client *c,
					 const u8 *msg_in)
{
	/* BOLT #7:
	 *
	 * The origin node:
	 *...
	 * - MUST set `signature` to the signature of the double-SHA256 of the
	 *   entire remaining packet after `signature` (using the key given by
	 *   `node_id`).
	 */
	/* 2 bytes msg type + 64 bytes signature */
	size_t offset = 66;
	struct sha256_double hash;
	struct privkey node_pkey;
	secp256k1_ecdsa_signature sig;
	u8 *reply;
	u8 *ann;

	if (!fromwire_hsmd_node_announcement_sig_req(tmpctx, msg_in, &ann))
		return hsmd_status_malformed_request(c, msg_in);

	if (tal_count(ann) < offset)
		return hsmd_status_bad_request(c, msg_in,
					       "Node announcement too short");

	if (fromwire_peektype(ann) != WIRE_NODE_ANNOUNCEMENT)
		return hsmd_status_bad_request(c, msg_in,
					       "Invalid announcement");

	node_key(&node_pkey, NULL);
	sha256_double(&hash, ann + offset, tal_count(ann) - offset);

	sign_hash(&node_pkey, &hash, &sig);

	reply = towire_hsmd_node_announcement_sig_reply(NULL, &sig);
	return reply;
}

/*~ The specific routine to sign the channel_update message. */
static u8 *handle_channel_update_sig(struct hsmd_client *c, const u8 *msg_in)
{
	/* BOLT #7:
	 *
	 * - MUST set `signature` to the signature of the double-SHA256 of the
	 *   entire remaining packet after `signature`, using its own
	 *   `node_id`.
	 */
	/* 2 bytes msg type + 64 bytes signature */
	size_t offset = 66;
	struct privkey node_pkey;
	struct sha256_double hash;
	secp256k1_ecdsa_signature sig;
	struct short_channel_id scid;
	u32 timestamp, fee_base_msat, fee_proportional_mill;
	struct amount_msat htlc_minimum, htlc_maximum;
	u8 message_flags, channel_flags;
	u16 cltv_expiry_delta;
	struct bitcoin_blkid chain_hash;
	u8 *cu;

	if (!fromwire_hsmd_cupdate_sig_req(tmpctx, msg_in, &cu))
		return hsmd_status_malformed_request(c, msg_in);

	if (!fromwire_channel_update(cu, &sig,
			&chain_hash, &scid, &timestamp, &message_flags,
			&channel_flags, &cltv_expiry_delta,
			&htlc_minimum, &fee_base_msat,
			&fee_proportional_mill, &htlc_maximum)) {
		return hsmd_status_bad_request(c, msg_in,
					       "Bad inner channel_update");
	}
	if (tal_count(cu) < offset)
		return hsmd_status_bad_request(
		    c, msg_in, "inner channel_update too short");

	node_key(&node_pkey, NULL);
	sha256_double(&hash, cu + offset, tal_count(cu) - offset);

	sign_hash(&node_pkey, &hash, &sig);

	cu = towire_channel_update(tmpctx, &sig, &chain_hash,
				   scid, timestamp, message_flags, channel_flags,
				   cltv_expiry_delta, htlc_minimum,
				   fee_base_msat, fee_proportional_mill,
				   htlc_maximum);
	return towire_hsmd_cupdate_sig_reply(NULL, cu);
}

/*~ This get the Nth a per-commitment point, and for N > 2, returns the
 * grandparent per-commitment secret.  This pattern is because after
 * negotiating commitment N-1, we send them the next per-commitment point,
 * and reveal the previous per-commitment secret as a promise not to spend
 * the previous commitment transaction. */
static u8 *handle_get_per_commitment_point(struct hsmd_client *c, const u8 *msg_in)
{
	struct secret channel_seed;
	struct sha256 shaseed;
	struct pubkey per_commitment_point;
	u64 n;
	struct secret *old_secret;

	if (!fromwire_hsmd_get_per_commitment_point(msg_in, &n))
		return hsmd_status_malformed_request(c, msg_in);

	get_channel_seed(&c->id, c->dbid, &channel_seed);
	if (!derive_shaseed(&channel_seed, &shaseed))
		return hsmd_status_bad_request(c, msg_in, "bad derive_shaseed");

	if (!per_commit_point(&shaseed, &per_commitment_point, n))
		return hsmd_status_bad_request_fmt(
		    c, msg_in, "bad per_commit_point %" PRIu64, n);

	if (hsmd_mutual_version < 6 && n >= 2) {
		old_secret = tal(tmpctx, struct secret);
		if (!per_commit_secret(&shaseed, old_secret, n - 2)) {
			return hsmd_status_bad_request_fmt(
			    c, msg_in, "Cannot derive secret %" PRIu64, n - 2);
		}
	} else
		old_secret = NULL;

	/*~ hsm_client_wire.csv marks the secret field here optional, so it only
	 * gets included if the parameter is non-NULL.  We violate 80 columns
	 * pretty badly here, but it's a recommendation not a religion. */
	return towire_hsmd_get_per_commitment_point_reply(
	    NULL, &per_commitment_point, old_secret);
}

/*~ lightningd asks us to sign a withdrawal; same as above but in theory
 * we can do more to check the previous case is valid. */
static u8 *handle_sign_withdrawal_tx(struct hsmd_client *c, const u8 *msg_in)
{
	struct utxo **utxos;
	struct wally_psbt *psbt;

	if (!fromwire_hsmd_sign_withdrawal(tmpctx, msg_in,
					  &utxos, &psbt))
		return hsmd_status_malformed_request(c, msg_in);

	sign_our_inputs(utxos, psbt);

	return towire_hsmd_sign_withdrawal_reply(NULL, psbt);
}

/* This is used by closingd to sign off on a mutual close tx. */
static u8 *handle_sign_mutual_close_tx(struct hsmd_client *c, const u8 *msg_in)
{
	struct secret channel_seed;
	struct bitcoin_tx *tx;
	struct pubkey remote_funding_pubkey, local_funding_pubkey;
	struct bitcoin_signature sig;
	struct secrets secrets;
	const u8 *funding_wscript;

	if (!fromwire_hsmd_sign_mutual_close_tx(tmpctx, msg_in,
					       &tx,
					       &remote_funding_pubkey))
		return hsmd_status_malformed_request(c, msg_in);

	tx->chainparams = c->chainparams;
	/* FIXME: We should know dust level, decent fee range and
	 * balances, and final_keyindex, and thus be able to check tx
	 * outputs! */
	get_channel_seed(&c->id, c->dbid, &channel_seed);
	derive_basepoints(&channel_seed,
			  &local_funding_pubkey, NULL, &secrets, NULL);

	funding_wscript = bitcoin_redeem_2of2(tmpctx,
					      &local_funding_pubkey,
					      &remote_funding_pubkey);
	sign_tx_input(tx, 0, NULL, funding_wscript,
		      &secrets.funding_privkey,
		      &local_funding_pubkey,
		      SIGHASH_ALL, &sig);

	return towire_hsmd_sign_tx_reply(NULL, &sig);
}

/* This is used by channeld to sign the final splice tx. */
static u8 *handle_sign_splice_tx(struct hsmd_client *c, const u8 *msg_in)
{
	struct secret channel_seed;
	struct bitcoin_tx *tx;
	struct pubkey remote_funding_pubkey, local_funding_pubkey;
	struct bitcoin_signature sig;
	struct secrets secrets;
	unsigned int input_index;
	const u8 *funding_wscript;

	if (!fromwire_hsmd_sign_splice_tx(tmpctx, msg_in,
					  &tx,
					  &remote_funding_pubkey,
					  &input_index))
		return hsmd_status_malformed_request(c, msg_in);

	tx->chainparams = c->chainparams;
	get_channel_seed(&c->id, c->dbid, &channel_seed);
	derive_basepoints(&channel_seed,
			  &local_funding_pubkey, NULL, &secrets, NULL);

	funding_wscript = bitcoin_redeem_2of2(tmpctx,
					      &local_funding_pubkey,
					      &remote_funding_pubkey);

	sign_tx_input(tx, input_index, NULL, funding_wscript,
		      &secrets.funding_privkey,
		      &local_funding_pubkey,
		      SIGHASH_ALL, &sig);

	return towire_hsmd_sign_tx_reply(NULL, &sig);
}

/*~ Originally, onchaind would ask for hsmd to sign txs directly, and then
 * tell lightningd to broadcast it.  With "bring-your-own-fees" HTLCs, this
 * changed, since we need to find a UTXO to attach to the transaction,
 * so now lightningd takes care of it all.
 *
 * The interfaces are very similar, so we have core functions that both
 * variants call after unwrapping the message. */
static u8 *do_sign_local_htlc_tx(struct hsmd_client *c,
				 const u8 *msg_in,
				 u32 input_num,
				 const struct node_id *peerid,
				 u64 channel_dbid,
				 u64 commit_num,
				 struct bitcoin_tx *tx,
				 const u8 *wscript,
				 bool option_anchor_outputs)
{
	struct secret channel_seed, htlc_basepoint_secret;
	struct sha256 shaseed;
	struct pubkey per_commitment_point, htlc_basepoint;
	struct bitcoin_signature sig;
	struct privkey htlc_privkey;
	struct pubkey htlc_pubkey;

	if (input_num >= tx->wtx->num_inputs)
		return hsmd_status_bad_request_fmt(c, msg_in,
						   "bad input %u of %zu",
						   input_num, tx->wtx->num_inputs);

	tx->chainparams = c->chainparams;
	get_channel_seed(peerid, channel_dbid, &channel_seed);

	if (!derive_shaseed(&channel_seed, &shaseed))
		return hsmd_status_bad_request_fmt(c, msg_in,
						   "bad derive_shaseed");

	if (!per_commit_point(&shaseed, &per_commitment_point, commit_num))
		return hsmd_status_bad_request_fmt(
		    c, msg_in, "bad per_commitment_point %" PRIu64, commit_num);

	if (!derive_htlc_basepoint(&channel_seed,
				   &htlc_basepoint,
				   &htlc_basepoint_secret))
		return hsmd_status_bad_request_fmt(
		    c, msg_in, "Failed deriving htlc basepoint");

	if (!derive_simple_privkey(&htlc_basepoint_secret,
				   &htlc_basepoint,
				   &per_commitment_point,
				   &htlc_privkey))
		return hsmd_status_bad_request_fmt(
		    c, msg_in, "Failed deriving htlc privkey");

	if (!pubkey_from_privkey(&htlc_privkey, &htlc_pubkey))
		return hsmd_status_bad_request_fmt(c, msg_in,
						   "bad pubkey_from_privkey");

	if (tx->wtx->num_inputs != 1)
		return hsmd_status_bad_request_fmt(c, msg_in,
						   "bad txinput count");

	/* FIXME: Check that output script is correct! */

	/* BOLT #3:
	 * ## HTLC-Timeout and HTLC-Success Transactions
	 *...
	 * * if `option_anchors` applies to this commitment transaction,
	 *   `SIGHASH_SINGLE|SIGHASH_ANYONECANPAY` is used as described in [BOLT #5]
	 */
	sign_tx_input(tx, input_num, NULL, wscript, &htlc_privkey, &htlc_pubkey,
		      option_anchor_outputs
		      ? (SIGHASH_SINGLE|SIGHASH_ANYONECANPAY)
		      : SIGHASH_ALL,
		      &sig);

	return towire_hsmd_sign_tx_reply(NULL, &sig);
}

/*~ Called from onchaind (deprecated) */
static u8 *handle_sign_local_htlc_tx(struct hsmd_client *c, const u8 *msg_in)
{
	u64 commit_num;
	struct bitcoin_tx *tx;
	u8 *wscript;
	bool option_anchor_outputs;

	if (!fromwire_hsmd_sign_local_htlc_tx(tmpctx, msg_in,
					     &commit_num, &tx, &wscript,
					     &option_anchor_outputs))
		return hsmd_status_malformed_request(c, msg_in);

	return do_sign_local_htlc_tx(c, msg_in, 0, &c->id, c->dbid,
				     commit_num, tx, wscript,
				     option_anchor_outputs);
}

/*~ This is the same function, but lightningd calling it */
static u8 *handle_sign_any_local_htlc_tx(struct hsmd_client *c, const u8 *msg_in)
{
	u64 commit_num;
	struct bitcoin_tx *tx;
	u8 *wscript;
	bool option_anchor_outputs;
	struct node_id peer_id;
	u32 input_num;
	u64 dbid;

	if (!fromwire_hsmd_sign_any_local_htlc_tx(tmpctx, msg_in,
						  &commit_num, &tx, &wscript,
						  &option_anchor_outputs,
						  &input_num, &peer_id, &dbid))
		return hsmd_status_malformed_request(c, msg_in);

	return do_sign_local_htlc_tx(c, msg_in, input_num, &peer_id, dbid,
				     commit_num, tx, wscript,
				     option_anchor_outputs);
}

/*~ This is used by channeld to create signatures for the remote peer's
 * HTLC transactions. */
static u8 *handle_sign_remote_htlc_tx(struct hsmd_client *c, const u8 *msg_in)
{
	struct secret channel_seed;
	struct bitcoin_tx *tx;
	struct bitcoin_signature sig;
	struct secrets secrets;
	struct basepoints basepoints;
	struct pubkey remote_per_commit_point;
	u8 *wscript;
	struct privkey htlc_privkey;
	struct pubkey htlc_pubkey;
	bool option_anchor_outputs;

	if (!fromwire_hsmd_sign_remote_htlc_tx(tmpctx, msg_in,
					      &tx, &wscript,
					      &remote_per_commit_point,
					      &option_anchor_outputs))
		return hsmd_status_malformed_request(c, msg_in);

	tx->chainparams = c->chainparams;
	get_channel_seed(&c->id, c->dbid, &channel_seed);
	derive_basepoints(&channel_seed, NULL, &basepoints, &secrets, NULL);

	if (!derive_simple_privkey(&secrets.htlc_basepoint_secret,
				   &basepoints.htlc,
				   &remote_per_commit_point,
				   &htlc_privkey))
		return hsmd_status_bad_request_fmt(
		    c, msg_in, "Failed deriving htlc privkey");

	if (!derive_simple_key(&basepoints.htlc,
			       &remote_per_commit_point,
			       &htlc_pubkey))
		return hsmd_status_bad_request_fmt(
		    c, msg_in, "Failed deriving htlc pubkey");

	/* BOLT #3:
	 * ## HTLC-Timeout and HTLC-Success Transactions
	 *...
	 * * if `option_anchors` applies to this commitment transaction,
	 *   `SIGHASH_SINGLE|SIGHASH_ANYONECANPAY` is used as described in [BOLT #5]
	 */
	sign_tx_input(tx, 0, NULL, wscript, &htlc_privkey, &htlc_pubkey,
		      option_anchor_outputs
		      ? (SIGHASH_SINGLE|SIGHASH_ANYONECANPAY)
		      : SIGHASH_ALL, &sig);

	return towire_hsmd_sign_tx_reply(NULL, &sig);
}

/*~ This is used by channeld to create signatures for the remote peer's
 * commitment transaction.  It's functionally identical to signing our own,
 * but we expect to do this repeatedly as commitment transactions are
 * updated.
 *
 * The HSM almost certainly *should* do more checks before signing!
 */
/* FIXME: make sure it meets some criteria? */
static u8 *handle_sign_remote_commitment_tx(struct hsmd_client *c, const u8 *msg_in)
{
	struct pubkey remote_funding_pubkey, local_funding_pubkey;
	struct secret channel_seed;
	struct bitcoin_tx *tx;
	struct bitcoin_signature sig;
	struct secrets secrets;
	const u8 *funding_wscript;
	struct pubkey remote_per_commit;
	bool option_static_remotekey;
	u64 commit_num;
	struct simple_htlc **htlc;
	u32 feerate;

	if (!fromwire_hsmd_sign_remote_commitment_tx(tmpctx, msg_in,
						    &tx,
						    &remote_funding_pubkey,
						    &remote_per_commit,
						    &option_static_remotekey,
						    &commit_num,
						    &htlc, &feerate))
		return hsmd_status_malformed_request(c, msg_in);
	tx->chainparams = c->chainparams;

	/* Basic sanity checks. */
	if (tx->wtx->num_inputs != 1)
		return hsmd_status_bad_request_fmt(c, msg_in,
						   "tx must have 1 input");

	if (tx->wtx->num_outputs == 0)
		return hsmd_status_bad_request_fmt(c, msg_in,
						   "tx must have > 0 outputs");

	get_channel_seed(&c->id, c->dbid, &channel_seed);
	derive_basepoints(&channel_seed,
			  &local_funding_pubkey, NULL, &secrets, NULL);

	funding_wscript = bitcoin_redeem_2of2(tmpctx,
					      &local_funding_pubkey,
					      &remote_funding_pubkey);
	sign_tx_input(tx, 0, NULL, funding_wscript,
		      &secrets.funding_privkey,
		      &local_funding_pubkey,
		      SIGHASH_ALL,
		      &sig);

	return towire_hsmd_sign_tx_reply(NULL, &sig);
}

/*~ This is used when the remote peer's commitment transaction is revoked;
 * we can use the revocation secret to spend the outputs.  For simplicity,
 * we do them one at a time, though. */
static u8 *do_sign_penalty_to_us(struct hsmd_client *c,
				 const u8 *msg_in,
				 u32 input_num,
				 const struct node_id *peerid,
				 u64 channel_dbid,
				 const struct secret *revocation_secret,
				 struct bitcoin_tx *tx,
				 const u8 *wscript)
{
	struct secret channel_seed, revocation_basepoint_secret;
	struct pubkey revocation_basepoint;
	struct pubkey point;
	struct privkey privkey;

	tx->chainparams = c->chainparams;

	if (!pubkey_from_secret(revocation_secret, &point))
		return hsmd_status_bad_request_fmt(c, msg_in,
						   "Failed deriving pubkey");

	get_channel_seed(peerid, channel_dbid, &channel_seed);
	if (!derive_revocation_basepoint(&channel_seed,
					 &revocation_basepoint,
					 &revocation_basepoint_secret))
		return hsmd_status_bad_request_fmt(
		    c, msg_in, "Failed deriving revocation basepoint");

	if (!derive_revocation_privkey(&revocation_basepoint_secret,
				       revocation_secret,
				       &revocation_basepoint,
				       &point,
				       &privkey))
		return hsmd_status_bad_request_fmt(
		    c, msg_in, "Failed deriving revocation privkey");

	return handle_sign_to_us_tx(c, msg_in, input_num, tx, &privkey, wscript,
				    SIGHASH_ALL);
}

/*~ Called from onchaind (deprecated) */
static u8 *handle_sign_penalty_to_us(struct hsmd_client *c, const u8 *msg_in)
{
	struct secret revocation_secret;
	struct bitcoin_tx *tx;
	u8 *wscript;

	if (!fromwire_hsmd_sign_penalty_to_us(tmpctx, msg_in,
					     &revocation_secret,
					     &tx, &wscript))
		return hsmd_status_malformed_request(c, msg_in);

	return do_sign_penalty_to_us(c, msg_in, 0, &c->id, c->dbid,
				     &revocation_secret, tx, wscript);
}

/*~ Called from lightningd */
static u8 *handle_sign_any_penalty_to_us(struct hsmd_client *c, const u8 *msg_in)
{
	struct secret revocation_secret;
	struct bitcoin_tx *tx;
	u8 *wscript;
	struct node_id peer_id;
	u64 dbid;
	u32 input_num;

	if (!fromwire_hsmd_sign_any_penalty_to_us(tmpctx, msg_in,
						  &revocation_secret,
						  &tx, &wscript,
						  &input_num, &peer_id, &dbid))
		return hsmd_status_malformed_request(c, msg_in);

	return do_sign_penalty_to_us(c, msg_in, input_num, &peer_id, dbid,
				     &revocation_secret, tx, wscript);
}

/*~ Called from lightningd */
static u8 *handle_sign_anchorspend(struct hsmd_client *c, const u8 *msg_in)
{
	struct node_id peer_id;
	u64 dbid;
	struct utxo **utxos;
	struct wally_psbt *psbt;
	struct secret seed;
	struct pubkey local_funding_pubkey;
	struct secrets secrets;
	int ret;

	/* FIXME: Check output goes to us. */
	if (!fromwire_hsmd_sign_anchorspend(tmpctx, msg_in,
					    &peer_id, &dbid, &utxos, &psbt))
		return hsmd_status_malformed_request(c, msg_in);

	/* Sign all the UTXOs */
	sign_our_inputs(utxos, psbt);

	get_channel_seed(&peer_id, dbid, &seed);
	derive_basepoints(&seed, &local_funding_pubkey, NULL, &secrets, NULL);

	tal_wally_start();
	ret = wally_psbt_sign(psbt, secrets.funding_privkey.secret.data,
			      sizeof(secrets.funding_privkey.secret.data),
			      EC_FLAG_GRIND_R);
	tal_wally_end(psbt);
	if (ret != WALLY_OK) {
		hsmd_status_failed(STATUS_FAIL_INTERNAL_ERROR,
				   "Received wally_err attempting to "
				    "sign anchor key %s. PSBT: %s",
				    fmt_pubkey(tmpctx, &local_funding_pubkey),
				    fmt_wally_psbt(tmpctx, psbt));
	}

	return towire_hsmd_sign_anchorspend_reply(NULL, psbt);
}

/*~ Called from lightningd */
static u8 *handle_sign_htlc_tx_mingle(struct hsmd_client *c, const u8 *msg_in)
{
	struct node_id peer_id;
	u64 dbid;
	struct utxo **utxos;
	struct wally_psbt *psbt;

	/* FIXME: Check output goes to us. */
	if (!fromwire_hsmd_sign_htlc_tx_mingle(tmpctx, msg_in,
					       &peer_id, &dbid, &utxos, &psbt))
		return hsmd_status_malformed_request(c, msg_in);

	/* Sign all the UTXOs (htlc_inout input is already signed with
	 * SIGHASH_SINGLE|SIGHASH_ANYONECANPAY) */
	sign_our_inputs(utxos, psbt);

	return towire_hsmd_sign_htlc_tx_mingle_reply(NULL, psbt);
}

/*~ This is another lightningd-only interface; signing a commit transaction.
 * This is dangerous, since if we sign a revoked commitment tx we'll lose
 * funds, thus it's only available to lightningd.
 *
 *
 * Oh look, another FIXME! */
/* FIXME: Ensure HSM never does this twice for same dbid! */
static u8 *handle_sign_commitment_tx(struct hsmd_client *c, const u8 *msg_in)
{
	struct pubkey remote_funding_pubkey, local_funding_pubkey;
	struct node_id peer_id;
	u64 dbid;
	struct secret channel_seed;
	struct bitcoin_tx *tx;
	struct bitcoin_signature sig;
	u64 commit_num;
	struct secrets secrets;
	const u8 *funding_wscript;

	if (!fromwire_hsmd_sign_commitment_tx(tmpctx, msg_in,
					     &peer_id, &dbid,
					     &tx,
					     &remote_funding_pubkey,
					     &commit_num))
		return hsmd_status_malformed_request(c, msg_in);

	tx->chainparams = c->chainparams;

	/* Basic sanity checks. */
	if (tx->wtx->num_inputs != 1)
		return hsmd_status_bad_request(c, msg_in,
					       "tx must have 1 input");

	if (tx->wtx->num_outputs == 0)
		return hsmd_status_bad_request_fmt(c, msg_in,
						   "tx must have > 0 outputs");

	get_channel_seed(&peer_id, dbid, &channel_seed);
	derive_basepoints(&channel_seed,
			  &local_funding_pubkey, NULL, &secrets, NULL);

	/*~ Bitcoin signatures cover the (part of) the script they're
	 * executing; the rules are a bit complex in general, but for
	 * Segregated Witness it's simply the current script. */
	funding_wscript = bitcoin_redeem_2of2(tmpctx,
					      &local_funding_pubkey,
					      &remote_funding_pubkey);
	sign_tx_input(tx, 0, NULL, funding_wscript,
		      &secrets.funding_privkey,
		      &local_funding_pubkey,
		      SIGHASH_ALL,
		      &sig);

	return towire_hsmd_sign_commitment_tx_reply(NULL, &sig);
}

/* ~This stub implementation is overriden by fully validating signers
 * that need to independently verify the peer's signatures. */
static u8 *handle_validate_commitment_tx(struct hsmd_client *c, const u8 *msg_in)
{
	struct bitcoin_tx *tx;
	struct simple_htlc **htlc;
	u64 commit_num;
	u32 feerate;
	struct bitcoin_signature sig;
	struct bitcoin_signature *htlc_sigs;
	struct secret channel_seed;
	struct sha256 shaseed;
	struct secret *old_secret;
	struct pubkey next_per_commitment_point;

	if (!fromwire_hsmd_validate_commitment_tx(tmpctx, msg_in,
						  &tx, &htlc,
						  &commit_num, &feerate,
						  &sig, &htlc_sigs))
		return hsmd_status_malformed_request(c, msg_in);

	/* Stub implementation */

	/* The signatures are not checked in this stub because they
	 * are already checked by the caller.  However, the returned
	 * old_secret and next_per_commitment_point are used.
	 */

	get_channel_seed(&c->id, c->dbid, &channel_seed);
	if (!derive_shaseed(&channel_seed, &shaseed))
		return hsmd_status_bad_request(c, msg_in, "bad derive_shaseed");

	if (!per_commit_point(&shaseed, &next_per_commitment_point, commit_num + 1))
		return hsmd_status_bad_request_fmt(
		    c, msg_in, "bad per_commit_point %" PRIu64, commit_num + 1);

	/* Don't ever return the old_secret here anymore. The node should
	 * call hsmd_revoke_commitment_tx to transactionally revoke the commitment
	 * and return the secret ...
	 */
	old_secret = NULL;

	return towire_hsmd_validate_commitment_tx_reply(
		NULL, old_secret, &next_per_commitment_point);
}

/* ~This stub implementation is overriden by fully validating signers
 * that need to independently revoke the old local commitment tx and
 * release it's secret.
 * Revoke the old commitment tx by disclosing its secret and also return
 * the next commitiment's per-commitment-point.
 */
static u8 *handle_revoke_commitment_tx(struct hsmd_client *c, const u8 *msg_in)
{
	u64 commit_num;
	struct secret channel_seed;
	struct sha256 shaseed;
	struct secret *old_secret;
	struct pubkey next_per_commitment_point;

	if (!fromwire_hsmd_revoke_commitment_tx(msg_in, &commit_num))
		return hsmd_status_malformed_request(c, msg_in);

	/* Stub implementation */

	/* The signatures are not checked in this stub because they
	 * are already checked by the caller.  However, the returned
	 * old_secret and next_per_commitment_point are used.
	 */

	get_channel_seed(&c->id, c->dbid, &channel_seed);
	if (!derive_shaseed(&channel_seed, &shaseed))
		return hsmd_status_bad_request(c, msg_in, "bad derive_shaseed");

	if (!per_commit_point(&shaseed, &next_per_commitment_point, commit_num + 2))
		return hsmd_status_bad_request_fmt(
		    c, msg_in, "bad per_commit_point %" PRIu64, commit_num + 2);

	old_secret = tal(tmpctx, struct secret);
	if (!per_commit_secret(&shaseed, old_secret, commit_num)) {
		return hsmd_status_bad_request_fmt(
		    c, msg_in, "Cannot derive secret %" PRIu64, commit_num);
	}

	return towire_hsmd_revoke_commitment_tx_reply(
		NULL, old_secret, &next_per_commitment_point);
}

/* This stub implementation is overriden by fully validating signers
 * that need to independently verify that the latest state is
 * commited. */
static u8 *handle_validate_revocation(struct hsmd_client *c, const u8 *msg_in)
{
	u64 revoke_num;
	struct secret old_secret;

	if (!fromwire_hsmd_validate_revocation(msg_in,
					       &revoke_num, &old_secret))
		return hsmd_status_malformed_request(c, msg_in);

	/* Stub implementation, relies on validation in channeld. */

	return towire_hsmd_validate_revocation_reply(NULL);
}

/*~ This is used when a commitment transaction is onchain, and has an HTLC
 * output paying to us (because we have the preimage); this signs that
 * transaction, which lightningd will broadcast to collect the funds. */
static u8 *do_sign_remote_htlc_to_us(struct hsmd_client *c,
				     const u8 *msg_in,
				     u32 input_num,
				     const struct node_id *peerid,
				     u64 channel_dbid,
				     const struct pubkey *remote_per_commitment_point,
				     struct bitcoin_tx *tx,
				     const u8 *wscript,
				     bool option_anchor_outputs)
{
	struct secret channel_seed, htlc_basepoint_secret;
	struct pubkey htlc_basepoint;
	struct privkey privkey;

	tx->chainparams = c->chainparams;
	get_channel_seed(peerid, channel_dbid, &channel_seed);

	if (!derive_htlc_basepoint(&channel_seed, &htlc_basepoint,
				   &htlc_basepoint_secret))
		return hsmd_status_bad_request(c, msg_in,
					       "Failed derive_htlc_basepoint");

	if (!derive_simple_privkey(&htlc_basepoint_secret,
				   &htlc_basepoint,
				   remote_per_commitment_point,
				   &privkey))
		return hsmd_status_bad_request(c, msg_in,
					       "Failed deriving htlc privkey");

	/* BOLT #3:
	 * ## HTLC-Timeout and HTLC-Success Transactions
	 *...
	 * * if `option_anchors` applies to this commitment transaction,
	 *   `SIGHASH_SINGLE|SIGHASH_ANYONECANPAY` is used as described in [BOLT #5]
	 */
	return handle_sign_to_us_tx(
	    c, msg_in, input_num, tx, &privkey, wscript,
	    option_anchor_outputs ? (SIGHASH_SINGLE | SIGHASH_ANYONECANPAY)
				  : SIGHASH_ALL);
}

/*~ When called by onchaind */
static u8 *handle_sign_remote_htlc_to_us(struct hsmd_client *c,
					 const u8 *msg_in)
{
	struct pubkey remote_per_commitment_point;
	struct bitcoin_tx *tx;
	u8 *wscript;
	bool option_anchor_outputs;

	if (!fromwire_hsmd_sign_remote_htlc_to_us(
		tmpctx, msg_in, &remote_per_commitment_point, &tx, &wscript,
		&option_anchor_outputs))
		return hsmd_status_malformed_request(c, msg_in);

	return do_sign_remote_htlc_to_us(c, msg_in, 0, &c->id, c->dbid,
					 &remote_per_commitment_point,
					 tx, wscript,
					 option_anchor_outputs);
}

/*~ When called by lightningd */
static u8 *handle_sign_any_remote_htlc_to_us(struct hsmd_client *c,
					     const u8 *msg_in)
{
	struct pubkey remote_per_commitment_point;
	struct bitcoin_tx *tx;
	u8 *wscript;
	bool option_anchor_outputs;
	struct node_id peer_id;
	u64 dbid;
	u32 input_num;

	if (!fromwire_hsmd_sign_any_remote_htlc_to_us(
		tmpctx, msg_in, &remote_per_commitment_point, &tx, &wscript,
		&option_anchor_outputs, &input_num, &peer_id, &dbid))
		return hsmd_status_malformed_request(c, msg_in);

	return do_sign_remote_htlc_to_us(c, msg_in, input_num, &peer_id, dbid,
					 &remote_per_commitment_point,
					 tx, wscript,
					 option_anchor_outputs);
}

/*~ When we send a commitment transaction onchain (unilateral close), there's
 * a delay before we can spend it.  onchaind does an explicit transaction to
 * transfer it to the wallet so that doesn't need to remember how to spend
 * this complex transaction. */
static u8 *do_sign_delayed_payment_to_us(struct hsmd_client *c,
					 const u8 *msg_in,
					 u32 input_num,
					 const struct node_id *peerid,
					 u64 channel_dbid,
					 u64 commit_num,
					 struct bitcoin_tx *tx,
					 const u8 *wscript)
{
	struct secret channel_seed, basepoint_secret;
	struct pubkey basepoint;
	struct sha256 shaseed;
	struct pubkey per_commitment_point;
	struct privkey privkey;

	tx->chainparams = c->chainparams;
	get_channel_seed(peerid, channel_dbid, &channel_seed);

	/*~ ccan/crypto/shachain how we efficiently derive 2^48 ordered
	 * preimages from a single seed; the twist is that as the preimages
	 * are revealed, you can generate the previous ones yourself, needing
	 * to only keep log(N) of them at any time. */
	if (!derive_shaseed(&channel_seed, &shaseed))
		return hsmd_status_bad_request(c, msg_in, "bad derive_shaseed");

	/*~ BOLT #3 describes exactly how this is used to generate the Nth
	 * per-commitment point. */
	if (!per_commit_point(&shaseed, &per_commitment_point, commit_num))
		return hsmd_status_bad_request_fmt(
		    c, msg_in, "bad per_commitment_point %" PRIu64, commit_num);

	/*~ ... which is combined with the basepoint to generate then N'th key.
	 */
	if (!derive_delayed_payment_basepoint(&channel_seed,
					      &basepoint,
					      &basepoint_secret))
		return hsmd_status_bad_request(c, msg_in,
					       "failed deriving basepoint");

	if (!derive_simple_privkey(&basepoint_secret,
				   &basepoint,
				   &per_commitment_point,
				   &privkey))
		return hsmd_status_bad_request(c, msg_in,
					       "failed deriving privkey");

	return handle_sign_to_us_tx(c, msg_in, input_num, tx, &privkey, wscript,
				    SIGHASH_ALL);
}

/*~ When called by onchaind */
static u8 *handle_sign_delayed_payment_to_us(struct hsmd_client *c,
					     const u8 *msg_in)
{
	u64 commit_num;
	struct bitcoin_tx *tx;
	u8 *wscript;

	/*~ We don't derive the wscript ourselves, but perhaps we should? */
	if (!fromwire_hsmd_sign_delayed_payment_to_us(tmpctx, msg_in,
						     &commit_num,
						     &tx, &wscript))
		return hsmd_status_malformed_request(c, msg_in);

	return do_sign_delayed_payment_to_us(c, msg_in, 0, &c->id, c->dbid,
					     commit_num, tx, wscript);
}

/*~ When called by lightningd */
static u8 *handle_sign_any_delayed_payment_to_us(struct hsmd_client *c,
						 const u8 *msg_in)
{
	u64 commit_num;
	struct bitcoin_tx *tx;
	u8 *wscript;
	struct node_id peer_id;
	u64 dbid;
	u32 input_num;

	/*~ We don't derive the wscript ourselves, but perhaps we should? */
	if (!fromwire_hsmd_sign_any_delayed_payment_to_us(tmpctx, msg_in,
							  &commit_num,
							  &tx, &wscript,
							  &input_num, &peer_id, &dbid))
		return hsmd_status_malformed_request(c, msg_in);

	return do_sign_delayed_payment_to_us(c, msg_in, input_num, &peer_id, dbid,
					     commit_num, tx, wscript);
}

u8 *hsmd_handle_client_message(const tal_t *ctx, struct hsmd_client *client,
			       const u8 *msg)
{
	enum hsmd_wire t = fromwire_peektype(msg);

	hsmd_status_debug("Client: Received message %d from client", t);

	/* Before we do anything else, is this client allowed to do
	 * what he asks for? */
	if (!hsmd_check_client_capabilities(client, t))
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
	case WIRE_HSMD_DEV_PREINIT:
	case WIRE_HSMD_INIT:
	case WIRE_HSMD_CLIENT_HSMFD:
		/* Not implemented yet. Should not have been passed here yet. */
		return hsmd_status_bad_request_fmt(
		    client, msg,
		    "Message of type %s should be handled externally to "
		    "libhsmd",
		    hsmd_wire_name(t));

	case WIRE_HSMD_NEW_CHANNEL:
		return handle_new_channel(client, msg);
	case WIRE_HSMD_SETUP_CHANNEL:
		return handle_setup_channel(client, msg);
	case WIRE_HSMD_CHECK_OUTPOINT:
		return handle_check_outpoint(client, msg);
	case WIRE_HSMD_LOCK_OUTPOINT:
		return handle_lock_outpoint(client, msg);
	case WIRE_HSMD_FORGET_CHANNEL:
		return handle_forget_channel(client, msg);
	case WIRE_HSMD_GET_OUTPUT_SCRIPTPUBKEY:
		return handle_get_output_scriptpubkey(client, msg);
	case WIRE_HSMD_CHECK_FUTURE_SECRET:
		return handle_check_future_secret(client, msg);
	case WIRE_HSMD_ECDH_REQ:
		return handle_ecdh(client, msg);
	case WIRE_HSMD_SIGN_INVOICE:
		return handle_sign_invoice(client, msg);
	case WIRE_HSMD_SIGN_OPTION_WILL_FUND_OFFER:
		return handle_sign_option_will_fund_offer(client, msg);
	case WIRE_HSMD_SIGN_BOLT12:
		return handle_sign_bolt12(client, msg);
	case WIRE_HSMD_SIGN_BOLT12_2:
		return handle_sign_bolt12_2(client, msg);
	case WIRE_HSMD_PREAPPROVE_INVOICE:
	case WIRE_HSMD_PREAPPROVE_INVOICE_CHECK:
		return handle_preapprove_invoice(client, msg);
	case WIRE_HSMD_PREAPPROVE_KEYSEND:
	case WIRE_HSMD_PREAPPROVE_KEYSEND_CHECK:
		return handle_preapprove_keysend(client, msg);
	case WIRE_HSMD_SIGN_MESSAGE:
		return handle_sign_message(client, msg);
	case WIRE_HSMD_GET_CHANNEL_BASEPOINTS:
		return handle_get_channel_basepoints(client, msg);
	case WIRE_HSMD_CANNOUNCEMENT_SIG_REQ:
		return handle_cannouncement_sig(client, msg);
	case WIRE_HSMD_SIGN_ANY_CANNOUNCEMENT_REQ:
		return handle_any_cannouncement_sig(client, msg);
	case WIRE_HSMD_NODE_ANNOUNCEMENT_SIG_REQ:
		return handle_sign_node_announcement(client, msg);
	case WIRE_HSMD_CUPDATE_SIG_REQ:
		return handle_channel_update_sig(client, msg);
	case WIRE_HSMD_GET_PER_COMMITMENT_POINT:
		return handle_get_per_commitment_point(client, msg);
	case WIRE_HSMD_SIGN_WITHDRAWAL:
		return handle_sign_withdrawal_tx(client, msg);
	case WIRE_HSMD_SIGN_MUTUAL_CLOSE_TX:
		return handle_sign_mutual_close_tx(client, msg);
	case WIRE_HSMD_SIGN_SPLICE_TX:
		return handle_sign_splice_tx(client, msg);
	case WIRE_HSMD_SIGN_LOCAL_HTLC_TX:
		return handle_sign_local_htlc_tx(client, msg);
	case WIRE_HSMD_SIGN_REMOTE_HTLC_TX:
		return handle_sign_remote_htlc_tx(client, msg);
	case WIRE_HSMD_SIGN_REMOTE_COMMITMENT_TX:
		return handle_sign_remote_commitment_tx(client, msg);
	case WIRE_HSMD_SIGN_PENALTY_TO_US:
		return handle_sign_penalty_to_us(client, msg);
	case WIRE_HSMD_SIGN_COMMITMENT_TX:
		return handle_sign_commitment_tx(client, msg);
	case WIRE_HSMD_VALIDATE_COMMITMENT_TX:
		return handle_validate_commitment_tx(client, msg);
	case WIRE_HSMD_REVOKE_COMMITMENT_TX:
		return handle_revoke_commitment_tx(client, msg);
	case WIRE_HSMD_VALIDATE_REVOCATION:
		return handle_validate_revocation(client, msg);
	case WIRE_HSMD_SIGN_REMOTE_HTLC_TO_US:
		return handle_sign_remote_htlc_to_us(client, msg);
	case WIRE_HSMD_SIGN_DELAYED_PAYMENT_TO_US:
		return handle_sign_delayed_payment_to_us(client, msg);
	case WIRE_HSMD_DERIVE_SECRET:
		return handle_derive_secret(client, msg);
	case WIRE_HSMD_CHECK_PUBKEY:
		return handle_check_pubkey(client, msg);
	case WIRE_HSMD_SIGN_ANY_DELAYED_PAYMENT_TO_US:
		return handle_sign_any_delayed_payment_to_us(client, msg);
	case WIRE_HSMD_SIGN_ANY_REMOTE_HTLC_TO_US:
		return handle_sign_any_remote_htlc_to_us(client, msg);
	case WIRE_HSMD_SIGN_ANY_LOCAL_HTLC_TX:
		return handle_sign_any_local_htlc_tx(client, msg);
	case WIRE_HSMD_SIGN_ANY_PENALTY_TO_US:
		return handle_sign_any_penalty_to_us(client, msg);
	case WIRE_HSMD_SIGN_ANCHORSPEND:
		return handle_sign_anchorspend(client, msg);
	case WIRE_HSMD_SIGN_HTLC_TX_MINGLE:
		return handle_sign_htlc_tx_mingle(client, msg);

	case WIRE_HSMD_DEV_MEMLEAK:
	case WIRE_HSMD_ECDH_RESP:
	case WIRE_HSMD_DERIVE_SECRET_REPLY:
	case WIRE_HSMD_CANNOUNCEMENT_SIG_REPLY:
	case WIRE_HSMD_CUPDATE_SIG_REPLY:
	case WIRE_HSMD_CLIENT_HSMFD_REPLY:
	case WIRE_HSMD_NEW_CHANNEL_REPLY:
	case WIRE_HSMD_SETUP_CHANNEL_REPLY:
	case WIRE_HSMD_CHECK_OUTPOINT_REPLY:
	case WIRE_HSMD_LOCK_OUTPOINT_REPLY:
 	case WIRE_HSMD_FORGET_CHANNEL_REPLY:
	case WIRE_HSMD_NODE_ANNOUNCEMENT_SIG_REPLY:
	case WIRE_HSMD_SIGN_WITHDRAWAL_REPLY:
	case WIRE_HSMD_SIGN_INVOICE_REPLY:
	case WIRE_HSMD_INIT_REPLY_V4:
	case WIRE_HSMSTATUS_CLIENT_BAD_REQUEST:
	case WIRE_HSMD_SIGN_COMMITMENT_TX_REPLY:
	case WIRE_HSMD_VALIDATE_COMMITMENT_TX_REPLY:
	case WIRE_HSMD_REVOKE_COMMITMENT_TX_REPLY:
	case WIRE_HSMD_VALIDATE_REVOCATION_REPLY:
	case WIRE_HSMD_SIGN_TX_REPLY:
	case WIRE_HSMD_SIGN_OPTION_WILL_FUND_OFFER_REPLY:
	case WIRE_HSMD_GET_PER_COMMITMENT_POINT_REPLY:
	case WIRE_HSMD_CHECK_FUTURE_SECRET_REPLY:
	case WIRE_HSMD_GET_CHANNEL_BASEPOINTS_REPLY:
	case WIRE_HSMD_DEV_MEMLEAK_REPLY:
	case WIRE_HSMD_SIGN_MESSAGE_REPLY:
	case WIRE_HSMD_GET_OUTPUT_SCRIPTPUBKEY_REPLY:
	case WIRE_HSMD_SIGN_BOLT12_REPLY:
	case WIRE_HSMD_SIGN_BOLT12_2_REPLY:
	case WIRE_HSMD_PREAPPROVE_INVOICE_REPLY:
	case WIRE_HSMD_PREAPPROVE_KEYSEND_REPLY:
	case WIRE_HSMD_PREAPPROVE_INVOICE_CHECK_REPLY:
	case WIRE_HSMD_PREAPPROVE_KEYSEND_CHECK_REPLY:
	case WIRE_HSMD_CHECK_PUBKEY_REPLY:
	case WIRE_HSMD_SIGN_ANCHORSPEND_REPLY:
	case WIRE_HSMD_SIGN_HTLC_TX_MINGLE_REPLY:
	case WIRE_HSMD_SIGN_ANY_CANNOUNCEMENT_REPLY:
		break;
	}
	return hsmd_status_bad_request(client, msg, "Unknown request");
}

u8 *hsmd_init(struct secret hsm_secret, const u64 hsmd_version,
	      struct bip32_key_version bip32_key_version)
{
	u8 bip32_seed[BIP32_ENTROPY_LEN_256];
	struct pubkey key, bolt12;
	u32 salt = 0;
	struct ext_key master_extkey, child_extkey;
	struct node_id node_id;
	static const u32 capabilities[] = {
		WIRE_HSMD_CHECK_PUBKEY,
		WIRE_HSMD_SIGN_ANY_DELAYED_PAYMENT_TO_US,
		WIRE_HSMD_SIGN_ANCHORSPEND,
		WIRE_HSMD_SIGN_HTLC_TX_MINGLE,
		WIRE_HSMD_SIGN_SPLICE_TX,
		WIRE_HSMD_CHECK_OUTPOINT,
		WIRE_HSMD_FORGET_CHANNEL,
		WIRE_HSMD_REVOKE_COMMITMENT_TX,
		WIRE_HSMD_SIGN_BOLT12_2,
		WIRE_HSMD_PREAPPROVE_INVOICE_CHECK,
		WIRE_HSMD_PREAPPROVE_KEYSEND_CHECK,
	};
	const u32 *caps;

	/*~ Don't swap this. */
	sodium_mlock(secretstuff.hsm_secret.data,
		     sizeof(secretstuff.hsm_secret.data));
	memcpy(secretstuff.hsm_secret.data, hsm_secret.data, sizeof(hsm_secret.data));

	assert(bip32_key_version.bip32_pubkey_version == BIP32_VER_MAIN_PUBLIC
			|| bip32_key_version.bip32_pubkey_version == BIP32_VER_TEST_PUBLIC);

	assert(bip32_key_version.bip32_privkey_version == BIP32_VER_MAIN_PRIVATE
			|| bip32_key_version.bip32_privkey_version == BIP32_VER_TEST_PRIVATE);

	/* Fill in the BIP32 tree for bitcoin addresses. */
	/* In libwally-core, the version BIP32_VER_TEST_PRIVATE is for testnet/regtest,
	 * and BIP32_VER_MAIN_PRIVATE is for mainnet. For litecoin, we also set it like
	 * bitcoin else.*/
	do {
		hkdf_sha256(bip32_seed, sizeof(bip32_seed),
			    &salt, sizeof(salt),
			    &secretstuff.hsm_secret,
			    sizeof(secretstuff.hsm_secret),
			    "bip32 seed", strlen("bip32 seed"));
		salt++;
	} while (bip32_key_from_seed(bip32_seed, sizeof(bip32_seed),
				     bip32_key_version.bip32_privkey_version,
				     0, &master_extkey) != WALLY_OK);

	/* In --developer mode, we can override with --dev-force-bip32-seed */
	if (dev_force_bip32_seed) {
		if (bip32_key_from_seed(dev_force_bip32_seed->data,
					sizeof(dev_force_bip32_seed->data),
					bip32_key_version.bip32_privkey_version,
					0, &master_extkey) != WALLY_OK)
			hsmd_status_failed(STATUS_FAIL_INTERNAL_ERROR,
					   "Can't derive bip32 master key");
	}

	/* BIP 32:
	 *
	 * The default wallet layout
	 *
	 * An HDW is organized as several 'accounts'. Accounts are numbered,
	 * the default account ("") being number 0. Clients are not required
	 * to support more than one account - if not, they only use the
	 * default account.
	 *
	 * Each account is composed of two keypair chains: an internal and an
	 * external one. The external keychain is used to generate new public
	 * addresses, while the internal keychain is used for all other
	 * operations (change addresses, generation addresses, ..., anything
	 * that doesn't need to be communicated). Clients that do not support
	 * separate keychains for these should use the external one for
	 * everything.
	 *
	 *  - m/iH/0/k corresponds to the k'th keypair of the external chain of
	 * account number i of the HDW derived from master m.
	 */
	/* Hence child 0, then child 0 again to get extkey to derive from. */
	if (bip32_key_from_parent(&master_extkey, 0, BIP32_FLAG_KEY_PRIVATE,
				  &child_extkey) != WALLY_OK)
		/*~ status_failed() is a helper which exits and sends lightningd
		 * a message about what happened.  For hsmd, that's fatal to
		 * lightningd. */
		hsmd_status_failed(STATUS_FAIL_INTERNAL_ERROR,
				   "Can't derive child bip32 key");

	if (bip32_key_from_parent(&child_extkey, 0, BIP32_FLAG_KEY_PRIVATE,
				  &secretstuff.bip32) != WALLY_OK)
		hsmd_status_failed(STATUS_FAIL_INTERNAL_ERROR,
				   "Can't derive private bip32 key");

	/* BIP 33:
	 *
	 * We propose the first level of BIP32 tree structure to be used as
	 * "purpose". This purpose determines the further structure beneath
	 * this node.
	 *
	 *  m / purpose' / *
	 *
	 * Apostrophe indicates that BIP32 hardened derivation is used.
	 *
	 * We encourage different schemes to apply for assigning a separate
	 * BIP number and use the same number for purpose field, so addresses
	 * won't be generated from overlapping BIP32 spaces.
	 *
	 * Example: Scheme described in BIP44 should use 44' (or 0x8000002C)
	 * as purpose.
	 */
	/* Clearly, we should use 9735, the unicode point for lightning! */
	if (bip32_key_from_parent(&master_extkey,
				  BIP32_INITIAL_HARDENED_CHILD|9735,
				  BIP32_FLAG_KEY_PRIVATE,
				  &child_extkey) != WALLY_OK)
		hsmd_status_failed(STATUS_FAIL_INTERNAL_ERROR,
				   "Can't derive bolt12 bip32 key");

	/* libwally says: The private key with prefix byte 0; remove it
	 * for libsecp256k1. */
	memcpy(&secretstuff.bolt12, child_extkey.priv_key+1,
	       sizeof(secretstuff.bolt12));

	/* Now we can consider ourselves initialized, and we won't get
	 * upset if we get a non-init message. */
	initialized = true;

	/*~ We tell lightning our node id and (public) bip32 seed. */
	node_key(NULL, &key);
	node_id_from_pubkey(&node_id, &key);

	/* We also give it the base key for bolt12 payerids */
	if (secp256k1_ec_pubkey_create(secp256k1_ctx, &bolt12.pubkey,
				       secretstuff.bolt12.data) != 1)
		hsmd_status_failed(STATUS_FAIL_INTERNAL_ERROR,
				   "Could derive bolt12 public key.");

	/* We derive the derived_secret key for generating pseudorandom keys
	 * by taking input string from the makesecret RPC */
	hkdf_sha256(&secretstuff.derived_secret, sizeof(struct secret), NULL, 0,
		    &secretstuff.hsm_secret, sizeof(secretstuff.hsm_secret),
		    "derived secrets", strlen("derived secrets"));

	/* Capabilities arg needs to be a tal array */
	if (dev_no_preapprove_check) {
		/* Skip preapprove capabilities */
		caps = tal_dup_arr(tmpctx, u32,
				   capabilities, ARRAY_SIZE(capabilities) - 2,
				   0);
	} else {
		caps = tal_dup_arr(tmpctx, u32,
				   capabilities, ARRAY_SIZE(capabilities), 0);
	}

	/*~ Note: marshalling a bip32 tree only marshals the public side,
	 * not the secrets!  So we're not actually handing them out here!
	 *
	 * And version is 4: we offer limited compatibility (or at least,
	 * incompatibility detection) with alternate implementations.
	 */
	return take(towire_hsmd_init_reply_v4(
			    NULL, hsmd_version, caps,
			    &node_id, &secretstuff.bip32,
			    &bolt12));
}
