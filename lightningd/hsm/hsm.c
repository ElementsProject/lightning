#include <bitcoin/address.h>
#include <bitcoin/privkey.h>
#include <bitcoin/pubkey.h>
#include <bitcoin/script.h>
#include <bitcoin/tx.h>
#include <ccan/breakpoint/breakpoint.h>
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
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <lightningd/build_utxos.h>
#include <lightningd/daemon_conn.h>
#include <lightningd/funding_tx.h>
#include <lightningd/hsm/client.h>
#include <lightningd/hsm/gen_hsm_client_wire.h>
#include <lightningd/hsm/gen_hsm_wire.h>
#include <lightningd/status.h>
#include <lightningd/withdraw_tx.h>
#include <permute_tx.h>
#include <secp256k1_ecdh.h>
#include <sodium/randombytes.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <utils.h>
#include <version.h>
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

	u64 id;
	struct io_plan *(*handle)(struct io_conn *, struct daemon_conn *);
};

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
				 u64 id,
				 struct io_plan *(*handle)(struct io_conn *,
							   struct daemon_conn *),
				 int fd)
{
	struct client *c = tal(master, struct client);
	c->id = id;
	c->handle = handle;
	c->master = master;
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

	if (!fromwire_hsm_ecdh_req(dc->msg_in, NULL, &point)) {
		daemon_conn_send(c->master,
				 take(towire_hsmstatus_client_bad_request(c,
								c->id,
								dc->msg_in)));
		return io_close(conn);
	}

	node_key(&privkey, NULL);
	if (secp256k1_ecdh(secp256k1_ctx, ss.data, &point.pubkey,
			   privkey.secret.data) != 1) {
		status_trace("secp256k1_ecdh fail for client %"PRIu64, c->id);
		daemon_conn_send(c->master,
				 take(towire_hsmstatus_client_bad_request(c,
								c->id,
								dc->msg_in)));
		return io_close(conn);
	}

	daemon_conn_send(dc, take(towire_hsm_ecdh_resp(c, &ss)));
	return daemon_conn_read_next(conn, dc);
}

static struct io_plan *handle_cannouncement_sig(struct io_conn *conn,
						struct daemon_conn *dc)
{
	tal_t *ctx = tal_tmpctx(conn);
	/* First 2 + 256 byte are the signatures and msg type, skip them */
	size_t offset = 258;
	struct privkey node_pkey;
	secp256k1_ecdsa_signature node_sig;
	struct sha256_double hash;
	u8 *reply;
	u8 *ca;
	struct pubkey bitcoin_id;

	if (!fromwire_hsm_cannouncement_sig_req(ctx, dc->msg_in, NULL,
						&bitcoin_id, &ca)) {
		status_trace("Failed to parse cannouncement_sig_req: %s",
			     tal_hex(trc, dc->msg_in));
		return io_close(conn);
	}

	if (tal_len(ca) < offset) {
		status_trace("bad cannounce length %zu", tal_len(ca));
		return io_close(conn);
	}

	/* TODO(cdecker) Check that this is actually a valid
	 * channel_announcement */
	node_key(&node_pkey, NULL);
	sha256_double(&hash, ca + offset, tal_len(ca) - offset);

	sign_hash(&node_pkey, &hash, &node_sig);

	reply = towire_hsm_cannouncement_sig_reply(ca, &node_sig);
	daemon_conn_send(dc, take(reply));

	tal_free(ctx);
	return daemon_conn_read_next(conn, dc);
}

static struct io_plan *handle_channel_update_sig(struct io_conn *conn,
						 struct daemon_conn *dc)
{
	tal_t *tmpctx = tal_tmpctx(conn);
	/* 2 bytes msg type + 64 bytes signature */
	size_t offset = 66;
	struct privkey node_pkey;
	struct sha256_double hash;
	secp256k1_ecdsa_signature sig;
	struct short_channel_id scid;
	u32 timestamp, fee_base_msat, fee_proportional_mill;
	u64 htlc_minimum_msat;
	u16 flags, cltv_expiry_delta;
	u8 *cu;

	if (!fromwire_hsm_cupdate_sig_req(tmpctx, dc->msg_in, NULL, &cu)) {
		status_trace("Failed to parse %s: %s",
			     hsm_client_wire_type_name(fromwire_peektype(dc->msg_in)),
			     tal_hex(trc, dc->msg_in));
		return io_close(conn);
	}

	if (!fromwire_channel_update(cu, NULL, &sig, &scid, &timestamp, &flags,
				     &cltv_expiry_delta, &htlc_minimum_msat,
				     &fee_base_msat, &fee_proportional_mill)) {
		status_trace("Failed to parse inner channel_update: %s",
			     tal_hex(trc, dc->msg_in));
		return io_close(conn);
	}
	if (tal_len(cu) < offset) {
		status_trace("inner channel_update too short: %s",
			     tal_hex(trc, dc->msg_in));
		return io_close(conn);
	}

	node_key(&node_pkey, NULL);
	sha256_double(&hash, cu + offset, tal_len(cu) - offset);

	sign_hash(&node_pkey, &hash, &sig);

	cu = towire_channel_update(tmpctx, &sig, &scid, timestamp, flags,
				   cltv_expiry_delta, htlc_minimum_msat,
				   fee_base_msat, fee_proportional_mill);

	daemon_conn_send(dc, take(towire_hsm_cupdate_sig_reply(tmpctx, cu)));
	tal_free(tmpctx);
	return daemon_conn_read_next(conn, dc);
}

static struct io_plan *handle_channeld(struct io_conn *conn,
				       struct daemon_conn *dc)
{
	struct client *c = container_of(dc, struct client, dc);
	enum hsm_client_wire_type t = fromwire_peektype(dc->msg_in);

	switch (t) {
	case WIRE_HSM_ECDH_REQ:
		return handle_ecdh(conn, dc);
	case WIRE_HSM_CANNOUNCEMENT_SIG_REQ:
		return handle_cannouncement_sig(conn, dc);
	case WIRE_HSM_CUPDATE_SIG_REQ:
		return handle_channel_update_sig(conn, dc);

	case WIRE_HSM_ECDH_RESP:
	case WIRE_HSM_CANNOUNCEMENT_SIG_REPLY:
	case WIRE_HSM_CUPDATE_SIG_REPLY:
		break;
	}

	daemon_conn_send(c->master,
			 take(towire_hsmstatus_client_bad_request(c,
								  c->id,
								  dc->msg_in)));
	return io_close(conn);
}

/* Control messages */
static void send_init_response(struct daemon_conn *master)
{
	struct pubkey node_id;
	struct secret peer_seed;
	u8 *serialized_extkey = tal_arr(master, u8, BIP32_SERIALIZED_LEN), *msg;

	hkdf_sha256(&peer_seed, sizeof(peer_seed), NULL, 0,
		    &secretstuff.hsm_secret,
		    sizeof(secretstuff.hsm_secret),
		    "peer seed", strlen("peer seed"));

	node_key(NULL, &node_id);
	if (bip32_key_serialize(&secretstuff.bip32, BIP32_FLAG_KEY_PUBLIC,
				serialized_extkey, tal_len(serialized_extkey))
	    != WALLY_OK)
		status_failed(WIRE_HSMSTATUS_KEY_FAILED,
			      "Can't serialize bip32 public key");

	msg = towire_hsmctl_init_reply(master, &node_id, &peer_seed,
				       serialized_extkey);
	tal_free(serialized_extkey);
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
		status_failed(WIRE_HSMSTATUS_KEY_FAILED,
			      "Can't derive child bip32 key");

	if (bip32_key_from_parent(&child_extkey, 0, BIP32_FLAG_KEY_PRIVATE,
				  &secretstuff.bip32) != WALLY_OK)
		status_failed(WIRE_HSMSTATUS_KEY_FAILED,
			      "Can't derive private bip32 key");
}

static void bitcoin_pubkey(struct pubkey *pubkey, u32 index)
{
	struct ext_key ext;

	if (index >= BIP32_INITIAL_HARDENED_CHILD)
		status_failed(WIRE_HSMSTATUS_KEY_FAILED,
			      "Index %u too great", index);

	if (bip32_key_from_parent(&secretstuff.bip32, index,
				  BIP32_FLAG_KEY_PUBLIC, &ext) != WALLY_OK)
		status_failed(WIRE_HSMSTATUS_KEY_FAILED,
			      "BIP32 of %u failed", index);

	if (!secp256k1_ec_pubkey_parse(secp256k1_ctx, &pubkey->pubkey,
				       ext.pub_key, sizeof(ext.pub_key)))
		status_failed(WIRE_HSMSTATUS_KEY_FAILED,
			      "Parse of BIP32 child %u pubkey failed", index);
}

static void bitcoin_keypair(struct privkey *privkey,
			    struct pubkey *pubkey,
			    u32 index)
{
	struct ext_key ext;

	if (index >= BIP32_INITIAL_HARDENED_CHILD)
		status_failed(WIRE_HSMSTATUS_KEY_FAILED,
			      "Index %u too great", index);

	if (bip32_key_from_parent(&secretstuff.bip32, index,
				  BIP32_FLAG_KEY_PRIVATE, &ext) != WALLY_OK)
		status_failed(WIRE_HSMSTATUS_KEY_FAILED,
			      "BIP32 of %u failed", index);

	/* libwally says: The private key with prefix byte 0 */
	memcpy(privkey->secret.data, ext.priv_key+1, 32);
	if (!secp256k1_ec_pubkey_create(secp256k1_ctx, &pubkey->pubkey,
					privkey->secret.data))
		status_failed(WIRE_HSMSTATUS_KEY_FAILED,
			      "BIP32 pubkey %u create failed", index);
}

static void create_new_hsm(struct daemon_conn *master)
{
	int fd = open("hsm_secret", O_CREAT|O_EXCL|O_WRONLY, 0400);
	if (fd < 0)
		status_failed(WIRE_HSMSTATUS_INIT_FAILED,
			      "creating: %s", strerror(errno));

	randombytes_buf(&secretstuff.hsm_secret, sizeof(secretstuff.hsm_secret));
	if (!write_all(fd, &secretstuff.hsm_secret, sizeof(secretstuff.hsm_secret))) {
		unlink_noerr("hsm_secret");
		status_failed(WIRE_HSMSTATUS_INIT_FAILED,
			      "writing: %s", strerror(errno));
	}
	if (fsync(fd) != 0) {
		unlink_noerr("hsm_secret");
		status_failed(WIRE_HSMSTATUS_INIT_FAILED,
			      "fsync: %s", strerror(errno));
	}
	if (close(fd) != 0) {
		unlink_noerr("hsm_secret");
		status_failed(WIRE_HSMSTATUS_INIT_FAILED,
			      "closing: %s", strerror(errno));
	}
	fd = open(".", O_RDONLY);
	if (fsync(fd) != 0) {
		unlink_noerr("hsm_secret");
		status_failed(WIRE_HSMSTATUS_INIT_FAILED,
			      "fsyncdir: %s", strerror(errno));
	}
	close(fd);

	populate_secretstuff();
}

static void load_hsm(struct daemon_conn *master)
{
	int fd = open("hsm_secret", O_RDONLY);
	if (fd < 0)
		status_failed(WIRE_HSMSTATUS_INIT_FAILED,
			      "opening: %s", strerror(errno));
	if (!read_all(fd, &secretstuff.hsm_secret, sizeof(secretstuff.hsm_secret)))
		status_failed(WIRE_HSMSTATUS_INIT_FAILED,
			      "reading: %s", strerror(errno));
	close(fd);

	populate_secretstuff();
}

static void init_hsm(struct daemon_conn *master, const u8 *msg)
{
	bool new;

	if (!fromwire_hsmctl_init(msg, NULL, &new))
		status_failed(WIRE_HSMSTATUS_BAD_REQUEST, "hsmctl_init: %s",
			      tal_hex(msg, msg));
	if (new)
		create_new_hsm(master);
	else
		load_hsm(master);

	send_init_response(master);
}

static void pass_hsmfd_ecdh(struct daemon_conn *master, const u8 *msg)
{
	int fds[2];
	u64 id;

	if (!fromwire_hsmctl_hsmfd_ecdh(msg, NULL, &id))
		status_failed(WIRE_HSMSTATUS_BAD_REQUEST, "bad HSMFD_ECDH");

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0)
		status_failed(WIRE_HSMSTATUS_FD_FAILED,
			      "creating fds: %s", strerror(errno));

	new_client(master, id, handle_ecdh, fds[0]);
	daemon_conn_send(master,
			 take(towire_hsmctl_hsmfd_ecdh_fd_reply(master)));
	daemon_conn_send_fd(master, fds[1]);
}

/* Reply to an incoming request for an HSMFD for a channeld. */
static void pass_hsmfd_channeld(struct daemon_conn *master, const u8 *msg)
{
	int fds[2];
	u64 id;

	if (!fromwire_hsmctl_hsmfd_channeld(msg, NULL, &id))
		status_failed(WIRE_HSMSTATUS_BAD_REQUEST, "bad HSMFD_CHANNELD");

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0)
		status_failed(WIRE_HSMSTATUS_FD_FAILED,
			      "creating fds: %s", strerror(errno));

	new_client(master, id, handle_channeld, fds[0]);
	daemon_conn_send(master,
			 take(towire_hsmctl_hsmfd_channeld_reply(master)));
	daemon_conn_send_fd(master, fds[1]);
}

/* Note that it's the main daemon that asks for the funding signature so it
 * can broadcast it. */
static void sign_funding_tx(struct daemon_conn *master, const u8 *msg)
{
	const tal_t *tmpctx = tal_tmpctx(master);
	u64 satoshi_out, change_out;
	u32 change_keyindex;
	struct pubkey local_pubkey, remote_pubkey;
	struct utxo *inputs;
	const struct utxo **utxomap;
	struct bitcoin_tx *tx;
	u8 *wscript;
	secp256k1_ecdsa_signature *sig;
	u16 outnum;
	size_t i;
	struct pubkey changekey;

	/* FIXME: Check fee is "reasonable" */
	if (!fromwire_hsmctl_sign_funding(tmpctx, msg, NULL,
					  &satoshi_out, &change_out,
					  &change_keyindex, &local_pubkey,
					  &remote_pubkey, &inputs))
		status_failed(WIRE_HSMSTATUS_BAD_REQUEST, "Bad SIGN_FUNDING");

	utxomap = to_utxoptr_arr(tmpctx, inputs);

	if (change_out)
		bitcoin_pubkey(&changekey, change_keyindex);

	tx = funding_tx(tmpctx, &outnum, utxomap,
			satoshi_out, &local_pubkey, &remote_pubkey,
			change_out, &changekey,
			NULL);

	/* Now generate signatures. */
	sig = tal_arr(tmpctx, secp256k1_ecdsa_signature, tal_count(inputs));
	for (i = 0; i < tal_count(inputs); i++) {
		struct pubkey inkey;
		struct privkey inprivkey;
		const struct utxo *in = utxomap[i];
		u8 *subscript;

		bitcoin_keypair(&inprivkey, &inkey, in->keyindex);
		if (in->is_p2sh)
			subscript = bitcoin_redeem_p2sh_p2wpkh(tmpctx, &inkey);
		else
			subscript = NULL;
		wscript = p2wpkh_scriptcode(tmpctx, &inkey);

		sign_tx_input(tx, i, subscript, wscript,
			      &inprivkey, &inkey, &sig[i]);
	}

	daemon_conn_send(master,
			 take(towire_hsmctl_sign_funding_reply(tmpctx, sig)));
	tal_free(tmpctx);
}

/**
 * sign_withdrawal_tx - Generate and sign a withdrawal transaction from the master
 */
static void sign_withdrawal_tx(struct daemon_conn *master, const u8 *msg)
{
	const tal_t *tmpctx = tal_tmpctx(master);
	u64 satoshi_out, change_out;
	u32 change_keyindex;
	struct bitcoin_address destination;
	struct utxo *utxos;
	secp256k1_ecdsa_signature *sigs;
	u8 *wscript;
	struct bitcoin_tx *tx;
	struct ext_key ext;
	struct pubkey changekey;

	if (!fromwire_hsmctl_sign_withdrawal(tmpctx, msg, NULL, &satoshi_out,
					     &change_out, &change_keyindex,
					     destination.addr.u.u8, &utxos)) {
		status_trace("Failed to parse sign_withdrawal: %s",
			     tal_hex(trc, msg));
		return;
	}

	if (bip32_key_from_parent(&secretstuff.bip32, change_keyindex,
				  BIP32_FLAG_KEY_PUBLIC, &ext) != WALLY_OK) {
		status_trace("Failed to parse sign_withdrawal: %s",
			     tal_hex(trc, msg));
		return;
	}

	pubkey_from_der(ext.pub_key, sizeof(ext.pub_key), &changekey);
	tx = withdraw_tx(
		tmpctx, to_utxoptr_arr(tmpctx, utxos), &destination, satoshi_out,
		&changekey, change_out, NULL);

	/* Now generate signatures. */
	sigs = tal_arr(tmpctx, secp256k1_ecdsa_signature, tal_count(utxos));
	for (size_t i = 0; i < tal_count(utxos); i++) {
		struct pubkey inkey;
		struct privkey inprivkey;
		const struct utxo *in = &utxos[i];
		u8 *subscript;

		bitcoin_keypair(&inprivkey, &inkey, in->keyindex);
		/* We know these are p2sh since that's the only kind we handle */
		subscript = bitcoin_redeem_p2sh_p2wpkh(tmpctx, &inkey);
		wscript = p2wpkh_scriptcode(tmpctx, &inkey);

		sign_tx_input(tx, i, subscript, wscript,
			      &inprivkey, &inkey, &sigs[i]);
	}

	daemon_conn_send(master,
			 take(towire_hsmctl_sign_withdrawal_reply(tmpctx, sigs)));
	tal_free(tmpctx);
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

	if (!fromwire_hsmctl_node_announcement_sig_req(msg, msg, NULL, &ann)) {
		status_trace("Failed to parse node_announcement_sig_req: %s",
			     tal_hex(trc, msg));
		return;
	}

	if (tal_len(ann) < offset) {
		status_trace("Node announcement too short: %s", tal_hex(trc, msg));
		return;
	}

	/* FIXME(cdecker) Check the node announcement's content */
	node_key(&node_pkey, NULL);
	sha256_double(&hash, ann + offset, tal_len(ann) - offset);

	sign_hash(&node_pkey, &hash, &sig);

	reply = towire_hsmctl_node_announcement_sig_reply(msg, &sig);
	daemon_conn_send(master, take(reply));
}

static struct io_plan *control_received_req(struct io_conn *conn,
					    struct daemon_conn *master)
{
	enum hsm_wire_type t = fromwire_peektype(master->msg_in);

	status_trace("Control: type %s len %zu",
		     hsm_wire_type_name(t), tal_count(master->msg_in));

	switch (t) {
	case WIRE_HSMCTL_INIT:
		init_hsm(master, master->msg_in);
		return daemon_conn_read_next(conn, master);
	case WIRE_HSMCTL_HSMFD_ECDH:
		pass_hsmfd_ecdh(master, master->msg_in);
		return daemon_conn_read_next(conn, master);
	case WIRE_HSMCTL_HSMFD_CHANNELD:
		pass_hsmfd_channeld(master, master->msg_in);
		return daemon_conn_read_next(conn, master);
	case WIRE_HSMCTL_SIGN_FUNDING:
		sign_funding_tx(master, master->msg_in);
		return daemon_conn_read_next(conn, master);

	case WIRE_HSMCTL_SIGN_WITHDRAWAL:
		sign_withdrawal_tx(master, master->msg_in);
		return daemon_conn_read_next(conn, master);

	case WIRE_HSMCTL_NODE_ANNOUNCEMENT_SIG_REQ:
		sign_node_announcement(master, master->msg_in);
		return daemon_conn_read_next(conn, master);

	case WIRE_HSMCTL_INIT_REPLY:
	case WIRE_HSMCTL_HSMFD_ECDH_FD_REPLY:
	case WIRE_HSMCTL_HSMFD_CHANNELD_REPLY:
	case WIRE_HSMCTL_SIGN_FUNDING_REPLY:
	case WIRE_HSMCTL_SIGN_WITHDRAWAL_REPLY:
	case WIRE_HSMSTATUS_INIT_FAILED:
	case WIRE_HSMSTATUS_WRITEMSG_FAILED:
	case WIRE_HSMSTATUS_BAD_REQUEST:
	case WIRE_HSMSTATUS_FD_FAILED:
	case WIRE_HSMSTATUS_KEY_FAILED:
	case WIRE_HSMSTATUS_CLIENT_BAD_REQUEST:
	case WIRE_HSMCTL_NODE_ANNOUNCEMENT_SIG_REPLY:
		break;
	}

	/* Control shouldn't give bad requests. */
	status_failed(WIRE_HSMSTATUS_BAD_REQUEST, "%i", t);
}

#ifndef TESTING
static void master_gone(struct io_conn *unused, struct daemon_conn *dc)
{
	/* Can't tell master, it's gone. */
	exit(2);
}

int main(int argc, char *argv[])
{
	struct daemon_conn *master;

	if (argc == 2 && streq(argv[1], "--version")) {
		printf("%s\n", version());
		exit(0);
	}

	breakpoint();
	secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY
						 | SECP256K1_CONTEXT_SIGN);

	master = tal(NULL, struct daemon_conn);
	daemon_conn_init(master, master, STDIN_FILENO, control_received_req,
			 master_gone);
	status_setup_async(master);

	/* When conn closes, everything is freed. */
	tal_steal(master->conn, master);
	io_loop(NULL, NULL);
	return 0;
}
#endif
