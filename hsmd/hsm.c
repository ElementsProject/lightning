#include <bitcoin/address.h>
#include <bitcoin/privkey.h>
#include <bitcoin/pubkey.h>
#include <bitcoin/script.h>
#include <bitcoin/tx.h>
#include <ccan/cast/cast.h>
#include <ccan/container_of/container_of.h>
#include <ccan/crypto/hkdf_sha256/hkdf_sha256.h>
#include <ccan/endian/endian.h>
#include <ccan/fdpass/fdpass.h>
#include <ccan/io/fdpass/fdpass.h>
#include <ccan/io/io.h>
#include <ccan/noerr/noerr.h>
#include <ccan/ptrint/ptrint.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/take/take.h>
#include <common/daemon_conn.h>
#include <common/derive_basepoints.h>
#include <common/funding_tx.h>
#include <common/hash_u5.h>
#include <common/key_derive.h>
#include <common/status.h>
#include <common/subdaemon.h>
#include <common/type_to_string.h>
#include <common/utils.h>
#include <common/version.h>
#include <common/withdraw_tx.h>
#include <errno.h>
#include <fcntl.h>
#include <hsmd/capabilities.h>
#include <hsmd/client.h>
#include <hsmd/gen_hsm_client_wire.h>
#include <inttypes.h>
#include <secp256k1_ecdh.h>
#include <sodium/randombytes.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <wally_bip32.h>
#include <wire/gen_peer_wire.h>
#include <wire/wire_io.h>

/* Nobody will ever find it here! */
static struct {
	struct secret hsm_secret;
	struct ext_key bip32;
} secretstuff;

struct client {
	struct daemon_conn dc;
	struct daemon_conn *master;

	struct pubkey id;
	struct io_plan *(*handle)(struct io_conn *, struct daemon_conn *);

	/* What is this client allowed to ask for? */
	u64 capabilities;
};

/* Function declarations for later */
static void init_hsm(struct daemon_conn *master, const u8 *msg);
static void pass_client_hsmfd(struct daemon_conn *master, const u8 *msg);
static void sign_funding_tx(struct daemon_conn *master, const u8 *msg);
static void sign_invoice(struct daemon_conn *master, const u8 *msg);
static void sign_node_announcement(struct daemon_conn *master, const u8 *msg);
static void sign_withdrawal_tx(struct daemon_conn *master, const u8 *msg);

static void node_key(struct privkey *node_privkey, struct pubkey *node_id)
{
	u32 salt = 0;
	struct privkey unused_s;
	struct pubkey unused_k;

	if (node_privkey == NULL)
		node_privkey = &unused_s;
	else if (node_id == NULL)
		node_id = &unused_k;

	do {
		hkdf_sha256(node_privkey, sizeof(*node_privkey),
			    &salt, sizeof(salt),
			    &secretstuff.hsm_secret,
			    sizeof(secretstuff.hsm_secret),
			    "nodeid", 6);
		salt++;
	} while (!secp256k1_ec_pubkey_create(secp256k1_ctx, &node_id->pubkey,
					     node_privkey->secret.data));
}

static struct client *new_client(struct daemon_conn *master,
				 const struct pubkey *id,
				 const u64 capabilities,
				 struct io_plan *(*handle)(struct io_conn *,
							   struct daemon_conn *),
				 int fd)
{
	struct client *c = tal(master, struct client);

	if (id) {
		c->id = *id;
	} else {
		memset(&c->id, 0, sizeof(c->id));
	}

	c->handle = handle;
	c->master = master;
	c->capabilities = capabilities;
	daemon_conn_init(c, &c->dc, fd, handle, NULL);

	/* Free the connection if we exit everything. */
	tal_steal(master, c->dc.conn);
	/* Free client when connection freed. */
	tal_steal(c->dc.conn, c);
	return c;
}

static struct io_plan *handle_ecdh(struct io_conn *conn, struct daemon_conn *dc)
{
	struct client *c = container_of(dc, struct client, dc);
	struct privkey privkey;
	struct pubkey point;
	struct secret ss;

	if (!fromwire_hsm_ecdh_req(dc->msg_in, &point)) {
		daemon_conn_send(c->master,
				 take(towire_hsmstatus_client_bad_request(NULL,
								&c->id,
								dc->msg_in)));
		return io_close(conn);
	}

	node_key(&privkey, NULL);
	if (secp256k1_ecdh(secp256k1_ctx, ss.data, &point.pubkey,
			   privkey.secret.data) != 1) {
		status_broken("secp256k1_ecdh fail for client %s",
			      type_to_string(tmpctx, struct pubkey, &c->id));
		daemon_conn_send(c->master,
				 take(towire_hsmstatus_client_bad_request(NULL,
								&c->id,
								dc->msg_in)));
		return io_close(conn);
	}

	daemon_conn_send(dc, take(towire_hsm_ecdh_resp(NULL, &ss)));
	return daemon_conn_read_next(conn, dc);
}

static struct io_plan *handle_cannouncement_sig(struct io_conn *conn,
						struct daemon_conn *dc)
{
	/* First 2 + 256 byte are the signatures and msg type, skip them */
	size_t offset = 258;
	struct privkey node_pkey;
	secp256k1_ecdsa_signature node_sig;
	struct sha256_double hash;
	u8 *reply;
	u8 *ca;
	struct pubkey bitcoin_id;

	if (!fromwire_hsm_cannouncement_sig_req(tmpctx, dc->msg_in,
						&bitcoin_id, &ca)) {
		status_broken("Failed to parse cannouncement_sig_req: %s",
			      tal_hex(tmpctx, dc->msg_in));
		return io_close(conn);
	}

	if (tal_len(ca) < offset) {
		status_broken("bad cannounce length %zu", tal_len(ca));
		return io_close(conn);
	}

	/* TODO(cdecker) Check that this is actually a valid
	 * channel_announcement */
	node_key(&node_pkey, NULL);
	sha256_double(&hash, ca + offset, tal_len(ca) - offset);

	sign_hash(&node_pkey, &hash, &node_sig);

	reply = towire_hsm_cannouncement_sig_reply(NULL, &node_sig);
	daemon_conn_send(dc, take(reply));

	return daemon_conn_read_next(conn, dc);
}

static struct io_plan *handle_channel_update_sig(struct io_conn *conn,
						 struct daemon_conn *dc)
{
	/* 2 bytes msg type + 64 bytes signature */
	size_t offset = 66;
	struct privkey node_pkey;
	struct sha256_double hash;
	secp256k1_ecdsa_signature sig;
	struct short_channel_id scid;
	u32 timestamp, fee_base_msat, fee_proportional_mill;
	u64 htlc_minimum_msat;
	u16 flags, cltv_expiry_delta;
	struct bitcoin_blkid chain_hash;
	u8 *cu;

	if (!fromwire_hsm_cupdate_sig_req(tmpctx, dc->msg_in, &cu)) {
		status_broken("Failed to parse %s: %s",
			      hsm_client_wire_type_name(fromwire_peektype(dc->msg_in)),
			      tal_hex(tmpctx, dc->msg_in));
		return io_close(conn);
	}

	if (!fromwire_channel_update(cu, &sig, &chain_hash,
				     &scid, &timestamp, &flags,
				     &cltv_expiry_delta, &htlc_minimum_msat,
				     &fee_base_msat, &fee_proportional_mill)) {
		status_broken("Failed to parse inner channel_update: %s",
			      tal_hex(tmpctx, dc->msg_in));
		return io_close(conn);
	}
	if (tal_len(cu) < offset) {
		status_broken("inner channel_update too short: %s",
			      tal_hex(tmpctx, dc->msg_in));
		return io_close(conn);
	}

	node_key(&node_pkey, NULL);
	sha256_double(&hash, cu + offset, tal_len(cu) - offset);

	sign_hash(&node_pkey, &hash, &sig);

	cu = towire_channel_update(tmpctx, &sig, &chain_hash,
				   &scid, timestamp, flags,
				   cltv_expiry_delta, htlc_minimum_msat,
				   fee_base_msat, fee_proportional_mill);

	daemon_conn_send(dc, take(towire_hsm_cupdate_sig_reply(NULL, cu)));
	return daemon_conn_read_next(conn, dc);
}

static bool check_client_capabilities(struct client *client,
				      enum hsm_client_wire_type t)
{
	switch (t) {
	case WIRE_HSM_ECDH_REQ:
		return (client->capabilities & HSM_CAP_ECDH) != 0;

	case WIRE_HSM_CANNOUNCEMENT_SIG_REQ:
	case WIRE_HSM_CUPDATE_SIG_REQ:
	case WIRE_HSM_NODE_ANNOUNCEMENT_SIG_REQ:
		return (client->capabilities & HSM_CAP_SIGN_GOSSIP) != 0;

	case WIRE_HSM_INIT:
	case WIRE_HSM_CLIENT_HSMFD:
	case WIRE_HSM_SIGN_FUNDING:
	case WIRE_HSM_SIGN_WITHDRAWAL:
	case WIRE_HSM_SIGN_INVOICE:
		return (client->capabilities & HSM_CAP_MASTER) != 0;

	/* These are messages sent by the HSM so we should never receive them */
	case WIRE_HSM_ECDH_RESP:
	case WIRE_HSM_CANNOUNCEMENT_SIG_REPLY:
	case WIRE_HSM_CUPDATE_SIG_REPLY:
	case WIRE_HSM_CLIENT_HSMFD_REPLY:
	case WIRE_HSM_SIGN_FUNDING_REPLY:
	case WIRE_HSM_NODE_ANNOUNCEMENT_SIG_REPLY:
	case WIRE_HSM_SIGN_WITHDRAWAL_REPLY:
	case WIRE_HSM_SIGN_INVOICE_REPLY:
	case WIRE_HSM_INIT_REPLY:
	case WIRE_HSMSTATUS_CLIENT_BAD_REQUEST:
		break;
	}
	return false;
}

static struct io_plan *handle_client(struct io_conn *conn,
				     struct daemon_conn *dc)
{
	struct client *c = container_of(dc, struct client, dc);
	enum hsm_client_wire_type t = fromwire_peektype(dc->msg_in);

	status_debug("Client: Received message %d from client", t);

	/* Before we do anything else, is this client allowed to do
	 * what he asks for? */
	if (!check_client_capabilities(c, t)) {
		status_broken("Client does not have the required capability to run %d", t);
		daemon_conn_send(c->master,
				 take(towire_hsmstatus_client_bad_request(
				     NULL, &c->id, dc->msg_in)));
		return io_close(conn);
	}

	/* Now actually go and do what the client asked for */
	switch (t) {
	case WIRE_HSM_INIT:
		init_hsm(dc, dc->msg_in);
		return daemon_conn_read_next(conn, dc);

	case WIRE_HSM_CLIENT_HSMFD:
		pass_client_hsmfd(dc, dc->msg_in);
		return daemon_conn_read_next(conn, dc);

	case WIRE_HSM_ECDH_REQ:
		return handle_ecdh(conn, dc);

	case WIRE_HSM_CANNOUNCEMENT_SIG_REQ:
		return handle_cannouncement_sig(conn, dc);

	case WIRE_HSM_CUPDATE_SIG_REQ:
		return handle_channel_update_sig(conn, dc);

	case WIRE_HSM_SIGN_FUNDING:
		sign_funding_tx(dc, dc->msg_in);
		return daemon_conn_read_next(conn, dc);

	case WIRE_HSM_NODE_ANNOUNCEMENT_SIG_REQ:
		sign_node_announcement(dc, dc->msg_in);
		return daemon_conn_read_next(conn, dc);

	case WIRE_HSM_SIGN_INVOICE:
		sign_invoice(dc, dc->msg_in);
		return daemon_conn_read_next(conn, dc);

	case WIRE_HSM_SIGN_WITHDRAWAL:
		sign_withdrawal_tx(dc, dc->msg_in);
		return daemon_conn_read_next(conn, dc);

	case WIRE_HSM_ECDH_RESP:
	case WIRE_HSM_CANNOUNCEMENT_SIG_REPLY:
	case WIRE_HSM_CUPDATE_SIG_REPLY:
	case WIRE_HSM_CLIENT_HSMFD_REPLY:
	case WIRE_HSM_SIGN_FUNDING_REPLY:
	case WIRE_HSM_NODE_ANNOUNCEMENT_SIG_REPLY:
	case WIRE_HSM_SIGN_WITHDRAWAL_REPLY:
	case WIRE_HSM_SIGN_INVOICE_REPLY:
	case WIRE_HSM_INIT_REPLY:
	case WIRE_HSMSTATUS_CLIENT_BAD_REQUEST:
		break;
	}

	daemon_conn_send(c->master,
			 take(towire_hsmstatus_client_bad_request(NULL,
								  &c->id,
								  dc->msg_in)));
	return io_close(conn);
}

/**
 * hsm_peer_secret_base -- Derive the base secret seed for per-peer seeds
 *
 * This secret is shared by all channels/peers for the client. The
 * per-peer seeds will be generated from it by mixing in the
 * channel_id and the peer node_id.
 */
static void hsm_peer_secret_base(struct secret *peer_seed_base)
{
	hkdf_sha256(peer_seed_base, sizeof(struct secret), NULL, 0,
		    &secretstuff.hsm_secret, sizeof(secretstuff.hsm_secret),
		    "peer seed", strlen("peer seed"));
}

static void send_init_response(struct daemon_conn *master)
{
	struct pubkey node_id;
	struct secret peer_seed;
	u8 *msg;

	hsm_peer_secret_base(&peer_seed);
	node_key(NULL, &node_id);

	msg = towire_hsm_init_reply(NULL, &node_id, &peer_seed,
				    &secretstuff.bip32);
	daemon_conn_send(master, take(msg));
}

static void populate_secretstuff(void)
{
	u8 bip32_seed[BIP32_ENTROPY_LEN_256];
	u32 salt = 0;
	struct ext_key master_extkey, child_extkey;

	/* Fill in the BIP32 tree for bitcoin addresses. */
	do {
		hkdf_sha256(bip32_seed, sizeof(bip32_seed),
			    &salt, sizeof(salt),
			    &secretstuff.hsm_secret,
			    sizeof(secretstuff.hsm_secret),
			    "bip32 seed", strlen("bip32 seed"));
		salt++;
	} while (bip32_key_from_seed(bip32_seed, sizeof(bip32_seed),
				     BIP32_VER_TEST_PRIVATE,
				     0, &master_extkey) != WALLY_OK);

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
	 *  - m/iH/0/k corresponds to the k'th keypair of the external chain of account number i of the HDW derived from master m.
	 */
	/* Hence child 0, then child 0 again to get extkey to derive from. */
	if (bip32_key_from_parent(&master_extkey, 0, BIP32_FLAG_KEY_PRIVATE,
				  &child_extkey) != WALLY_OK)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Can't derive child bip32 key");

	if (bip32_key_from_parent(&child_extkey, 0, BIP32_FLAG_KEY_PRIVATE,
				  &secretstuff.bip32) != WALLY_OK)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Can't derive private bip32 key");
}

static void bitcoin_pubkey(struct pubkey *pubkey, u32 index)
{
	struct ext_key ext;

	if (index >= BIP32_INITIAL_HARDENED_CHILD)
		status_failed(STATUS_FAIL_MASTER_IO,
			      "Index %u too great", index);

	if (bip32_key_from_parent(&secretstuff.bip32, index,
				  BIP32_FLAG_KEY_PUBLIC, &ext) != WALLY_OK)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "BIP32 of %u failed", index);

	if (!secp256k1_ec_pubkey_parse(secp256k1_ctx, &pubkey->pubkey,
				       ext.pub_key, sizeof(ext.pub_key)))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Parse of BIP32 child %u pubkey failed", index);
}

static void bitcoin_keypair(struct privkey *privkey,
			    struct pubkey *pubkey,
			    u32 index)
{
	struct ext_key ext;

	if (index >= BIP32_INITIAL_HARDENED_CHILD)
		status_failed(STATUS_FAIL_MASTER_IO,
			      "Index %u too great", index);

	if (bip32_key_from_parent(&secretstuff.bip32, index,
				  BIP32_FLAG_KEY_PRIVATE, &ext) != WALLY_OK)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "BIP32 of %u failed", index);

	/* libwally says: The private key with prefix byte 0 */
	memcpy(privkey->secret.data, ext.priv_key+1, 32);
	if (!secp256k1_ec_pubkey_create(secp256k1_ctx, &pubkey->pubkey,
					privkey->secret.data))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "BIP32 pubkey %u create failed", index);
}

static void maybe_create_new_hsm(void)
{
	int fd = open("hsm_secret", O_CREAT|O_EXCL|O_WRONLY, 0400);
	if (fd < 0) {
		if (errno == EEXIST)
			return;
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "creating: %s", strerror(errno));
	}

	randombytes_buf(&secretstuff.hsm_secret, sizeof(secretstuff.hsm_secret));
	if (!write_all(fd, &secretstuff.hsm_secret, sizeof(secretstuff.hsm_secret))) {
		unlink_noerr("hsm_secret");
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "writing: %s", strerror(errno));
	}
	if (fsync(fd) != 0) {
		unlink_noerr("hsm_secret");
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "fsync: %s", strerror(errno));
	}
	if (close(fd) != 0) {
		unlink_noerr("hsm_secret");
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "closing: %s", strerror(errno));
	}
	fd = open(".", O_RDONLY);
	if (fd < 0) {
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "opening: %s", strerror(errno));
	}
	if (fsync(fd) != 0) {
		unlink_noerr("hsm_secret");
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "fsyncdir: %s", strerror(errno));
	}
	close(fd);
	status_unusual("HSM: created new hsm_secret file");
}

static void load_hsm(void)
{
	int fd = open("hsm_secret", O_RDONLY);
	if (fd < 0)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "opening: %s", strerror(errno));
	if (!read_all(fd, &secretstuff.hsm_secret, sizeof(secretstuff.hsm_secret)))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "reading: %s", strerror(errno));
	close(fd);

	populate_secretstuff();
}

static void init_hsm(struct daemon_conn *master, const u8 *msg)
{

	if (!fromwire_hsm_init(msg))
		master_badmsg(WIRE_HSM_INIT, msg);

	maybe_create_new_hsm();
	load_hsm();

	send_init_response(master);
}

static void pass_client_hsmfd(struct daemon_conn *master, const u8 *msg)
{
	int fds[2];
	u64 capabilities;
	struct pubkey id;

	if (!fromwire_hsm_client_hsmfd(msg, &id, &capabilities))
		master_badmsg(WIRE_HSM_CLIENT_HSMFD, msg);

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0)
		status_failed(STATUS_FAIL_INTERNAL_ERROR, "creating fds: %s", strerror(errno));

	new_client(master, &id, capabilities, handle_client, fds[0]);
	daemon_conn_send(master,
			 take(towire_hsm_client_hsmfd_reply(NULL)));
	daemon_conn_send_fd(master, fds[1]);
}


static void derive_peer_seed(struct privkey *peer_seed, struct privkey *peer_seed_base,
		      const struct pubkey *peer_id, const u64 channel_id)
{
	u8 input[PUBKEY_DER_LEN + sizeof(channel_id)];
	char *info = "per-peer seed";
	pubkey_to_der(input, peer_id);
	memcpy(input + PUBKEY_DER_LEN, &channel_id, sizeof(channel_id));

	hkdf_sha256(peer_seed, sizeof(*peer_seed),
		    input, sizeof(input),
		    peer_seed_base, sizeof(*peer_seed_base),
		    info, strlen(info));
}

static void hsm_unilateral_close_privkey(struct privkey *dst,
					 struct unilateral_close_info *info)
{
	struct privkey peer_seed, peer_seed_base;
	struct basepoints basepoints;
	struct secrets secrets;
	hsm_peer_secret_base(&peer_seed_base.secret);
	derive_peer_seed(&peer_seed, &peer_seed_base, &info->peer_id, info->channel_id);
	derive_basepoints(&peer_seed, NULL, &basepoints, &secrets, NULL);

	if (!derive_simple_privkey(&secrets.payment_basepoint_secret,
				   &basepoints.payment, &info->commitment_point,
				   dst)) {
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Deriving unilateral_close_privkey");
	}
}

/**
 * hsm_key_for_utxo - generate the keypair matching the utxo
 */
static void hsm_key_for_utxo(struct privkey *privkey, struct pubkey *pubkey,
			     const struct utxo *utxo)
{
	if (utxo->close_info != NULL) {
		/* This is a their_unilateral_close/to-us output, so
		 * we need to derive the secret the long way */
		status_debug("Unilateral close output, deriving secrets");
		hsm_unilateral_close_privkey(privkey, utxo->close_info);
		pubkey_from_privkey(privkey, pubkey);
		status_debug("Derived public key %s from unilateral close", type_to_string(tmpctx, struct pubkey, pubkey));
	} else {
		/* Simple case: just get derive via HD-derivation */
		bitcoin_keypair(privkey, pubkey, utxo->keyindex);
	}
}

/* Note that it's the main daemon that asks for the funding signature so it
 * can broadcast it. */
static void sign_funding_tx(struct daemon_conn *master, const u8 *msg)
{
	u64 satoshi_out, change_out;
	u32 change_keyindex;
	struct pubkey local_pubkey, remote_pubkey;
	struct utxo **utxomap;
	struct bitcoin_tx *tx;
	u16 outnum;
	size_t i;
	struct pubkey *changekey;
	u8 **scriptSigs;

	/* FIXME: Check fee is "reasonable" */
	if (!fromwire_hsm_sign_funding(tmpctx, msg,
				       &satoshi_out, &change_out,
				       &change_keyindex, &local_pubkey,
				       &remote_pubkey, &utxomap))
		master_badmsg(WIRE_HSM_SIGN_FUNDING, msg);

	if (change_out) {
		changekey = tal(tmpctx, struct pubkey);
		bitcoin_pubkey(changekey, change_keyindex);
	} else
		changekey = NULL;

	tx = funding_tx(tmpctx, &outnum,
			cast_const2(const struct utxo **, utxomap),
			satoshi_out, &local_pubkey, &remote_pubkey,
			change_out, changekey,
			NULL);

	scriptSigs = tal_arr(tmpctx, u8*, tal_count(utxomap));
	for (i = 0; i < tal_count(utxomap); i++) {
		struct pubkey inkey;
		struct privkey inprivkey;
		const struct utxo *in = utxomap[i];
		u8 *subscript;
		secp256k1_ecdsa_signature sig;

		hsm_key_for_utxo(&inprivkey, &inkey, in);

		if (in->is_p2sh)
			subscript = bitcoin_redeem_p2sh_p2wpkh(tmpctx, &inkey);
		else
			subscript = NULL;
		u8 *wscript = p2wpkh_scriptcode(tmpctx, &inkey);

		sign_tx_input(tx, i, subscript, wscript, &inprivkey, &inkey,
			      &sig);

		tx->input[i].witness = bitcoin_witness_p2wpkh(tx, &sig, &inkey);

		if (utxomap[i]->is_p2sh)
			scriptSigs[i] = bitcoin_scriptsig_p2sh_p2wpkh(tx, &inkey);
		else
			scriptSigs[i] = NULL;
	}

	/* Now complete the transaction by attaching the scriptSigs where necessary */
	for (size_t i=0; i<tal_count(utxomap); i++)
		tx->input[i].script = scriptSigs[i];

	daemon_conn_send(master,
			 take(towire_hsm_sign_funding_reply(NULL, tx)));
}

/**
 * sign_withdrawal_tx - Generate and sign a withdrawal transaction from the master
 */
static void sign_withdrawal_tx(struct daemon_conn *master, const u8 *msg)
{
	u64 satoshi_out, change_out;
	u32 change_keyindex;
	struct utxo **utxos;
	u8 **scriptSigs;
	struct bitcoin_tx *tx;
	struct ext_key ext;
	struct pubkey changekey;
	u8 *scriptpubkey;

	if (!fromwire_hsm_sign_withdrawal(tmpctx, msg, &satoshi_out,
					  &change_out, &change_keyindex,
					  &scriptpubkey, &utxos)) {
		status_broken("Failed to parse sign_withdrawal: %s",
			      tal_hex(tmpctx, msg));
		return;
	}

	if (bip32_key_from_parent(&secretstuff.bip32, change_keyindex,
				  BIP32_FLAG_KEY_PUBLIC, &ext) != WALLY_OK) {
		status_broken("Failed to parse sign_withdrawal: %s",
			      tal_hex(tmpctx, msg));
		return;
	}

	pubkey_from_der(ext.pub_key, sizeof(ext.pub_key), &changekey);
	tx = withdraw_tx(
		tmpctx, cast_const2(const struct utxo **, utxos),
		scriptpubkey, satoshi_out,
		&changekey, change_out, NULL);

	scriptSigs = tal_arr(tmpctx, u8*, tal_count(utxos));
	for (size_t i = 0; i < tal_count(utxos); i++) {
		struct pubkey inkey;
		struct privkey inprivkey;
		const struct utxo *in = utxos[i];
		u8 *subscript;
		secp256k1_ecdsa_signature sig;

		hsm_key_for_utxo(&inprivkey, &inkey, in);

		if (in->is_p2sh || in->close_info != NULL)
			subscript = bitcoin_redeem_p2sh_p2wpkh(tmpctx, &inkey);
		else
			subscript = NULL;
		u8 *wscript = p2wpkh_scriptcode(tmpctx, &inkey);

		sign_tx_input(tx, i, subscript, wscript, &inprivkey, &inkey,
			      &sig);

		tx->input[i].witness = bitcoin_witness_p2wpkh(tx, &sig, &inkey);

		if (utxos[i]->is_p2sh)
			scriptSigs[i] = bitcoin_scriptsig_p2sh_p2wpkh(tx, &inkey);
		else
			scriptSigs[i] = NULL;
	}

	/* Now complete the transaction by attaching the scriptSigs where necessary */
	for (size_t i=0; i<tal_count(utxos); i++)
		tx->input[i].script = scriptSigs[i];

	daemon_conn_send(master,
			 take(towire_hsm_sign_withdrawal_reply(NULL, tx)));
}

/**
 * sign_invoice - Sign an invoice with our key.
 */
static void sign_invoice(struct daemon_conn *master, const u8 *msg)
{
	u5 *u5bytes;
	u8 *hrpu8;
	char *hrp;
	struct sha256 sha;
        secp256k1_ecdsa_recoverable_signature rsig;
	struct hash_u5 hu5;
	struct privkey node_pkey;

	if (!fromwire_hsm_sign_invoice(tmpctx, msg, &u5bytes, &hrpu8)) {
		status_broken("Failed to parse sign_invoice: %s",
			      tal_hex(tmpctx, msg));
		return;
	}

	/* FIXME: Check invoice! */

	hrp = tal_dup_arr(tmpctx, char, (char *)hrpu8, tal_len(hrpu8), 1);
	hrp[tal_len(hrpu8)] = '\0';

	hash_u5_init(&hu5, hrp);
	hash_u5(&hu5, u5bytes, tal_len(u5bytes));
	hash_u5_done(&hu5, &sha);

	node_key(&node_pkey, NULL);
        if (!secp256k1_ecdsa_sign_recoverable(secp256k1_ctx, &rsig,
                                              (const u8 *)&sha,
                                              node_pkey.secret.data,
                                              NULL, NULL)) {
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Failed to sign invoice: %s",
			      tal_hex(tmpctx, msg));
	}

	daemon_conn_send(master,
			 take(towire_hsm_sign_invoice_reply(NULL, &rsig)));
}

static void sign_node_announcement(struct daemon_conn *master, const u8 *msg)
{
	/* 2 bytes msg type + 64 bytes signature */
	size_t offset = 66;
	struct sha256_double hash;
	struct privkey node_pkey;
	secp256k1_ecdsa_signature sig;
	u8 *reply;
	u8 *ann;

	if (!fromwire_hsm_node_announcement_sig_req(msg, msg, &ann)) {
		status_failed(STATUS_FAIL_GOSSIP_IO,
			      "Failed to parse node_announcement_sig_req: %s",
			     tal_hex(tmpctx, msg));
	}

	if (tal_len(ann) < offset) {
		status_failed(STATUS_FAIL_GOSSIP_IO,
			      "Node announcement too short: %s",
			      tal_hex(tmpctx, msg));
	}

	/* FIXME(cdecker) Check the node announcement's content */
	node_key(&node_pkey, NULL);
	sha256_double(&hash, ann + offset, tal_len(ann) - offset);

	sign_hash(&node_pkey, &hash, &sig);

	reply = towire_hsm_node_announcement_sig_reply(NULL, &sig);
	daemon_conn_send(master, take(reply));
}

#ifndef TESTING
/* FIXME: This is used by debug.c, but doesn't apply to us. */
extern void dev_disconnect_init(int fd);
void dev_disconnect_init(int fd UNUSED)
{
}

static void master_gone(struct io_conn *unused UNUSED, struct daemon_conn *dc UNUSED)
{
	/* Can't tell master, it's gone. */
	exit(2);
}

int main(int argc, char *argv[])
{
	setup_locale();

	struct client *client;

	subdaemon_setup(argc, argv);

	client = new_client(NULL, NULL, HSM_CAP_MASTER | HSM_CAP_SIGN_GOSSIP, handle_client, STDIN_FILENO);

	/* We're our own master! */
	client->master = &client->dc;
	io_set_finish(client->dc.conn, master_gone, &client->dc);

	status_setup_async(&client->dc);

	/* When conn closes, everything is freed. */
	tal_steal(client->dc.conn, client);
	io_loop(NULL, NULL);
	daemon_shutdown();

	return 0;
}
#endif
