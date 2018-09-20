#include <bitcoin/address.h>
#include <bitcoin/privkey.h>
#include <bitcoin/pubkey.h>
#include <bitcoin/script.h>
#include <bitcoin/tx.h>
#include <ccan/array_size/array_size.h>
#include <ccan/cast/cast.h>
#include <ccan/container_of/container_of.h>
#include <ccan/crypto/hkdf_sha256/hkdf_sha256.h>
#include <ccan/endian/endian.h>
#include <ccan/fdpass/fdpass.h>
#include <ccan/intmap/intmap.h>
#include <ccan/io/fdpass/fdpass.h>
#include <ccan/io/io.h>
#include <ccan/noerr/noerr.h>
#include <ccan/ptrint/ptrint.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/take/take.h>
#include <ccan/tal/str/str.h>
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

#define REQ_FD 3

/* Nobody will ever find it here! */
static struct {
	struct secret hsm_secret;
	struct ext_key bip32;
} secretstuff;

struct client {
	struct daemon_conn dc;
	struct daemon_conn *master;

	struct pubkey id;
	u64 dbid;

	/* What is this client allowed to ask for? */
	u64 capabilities;
};

/* We keep a map of nonzero dbid -> clients */
static UINTMAP(struct client *) clients;
/* We get three zero-dbid clients: master, gossipd and connnectd. */
static struct client *dbid_zero_clients[3];
static size_t num_dbid_zero_clients;

/* For reporting issues. */
static struct daemon_conn *status_conn;

/* FIXME: This is used by debug.c, but doesn't apply to us. */
extern void dev_disconnect_init(int fd);
void dev_disconnect_init(int fd UNUSED) { }

/* Pre-declare this, due to mutual recursion */
static struct client *new_client(struct daemon_conn *master,
				 const struct pubkey *id,
				 u64 dbid,
				 const u64 capabilities,
				 int fd);

static PRINTF_FMT(4,5)
	struct io_plan *bad_req_fmt(struct io_conn *conn,
				    struct client *c,
				    const u8 *msg_in,
				    const char *fmt, ...)
{
	va_list ap;
	char *str;

	va_start(ap, fmt);
	str = tal_fmt(tmpctx, fmt, ap);
	va_end(ap);

	/* If the client was actually lightningd, it's Game Over. */
	if (&c->dc == c->master) {
		status_broken("%s", str);
		master_badmsg(fromwire_peektype(msg_in), msg_in);
	}

	daemon_conn_send(status_conn,
			 take(towire_hsmstatus_client_bad_request(NULL,
								  &c->id,
								  str,
								  msg_in)));
	return io_close(conn);
}

static struct io_plan *bad_req(struct io_conn *conn,
			       struct client *c,
			       const u8 *msg_in)
{
	return bad_req_fmt(conn, c, msg_in, "could not parse request");
}

static struct io_plan *req_reply(struct io_conn *conn,
				 struct client *c,
				 const u8 *msg_out TAKES)
{
	daemon_conn_send(&c->dc, msg_out);
	return daemon_conn_read_next(conn, &c->dc);
}

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

/**
 * hsm_channel_secret_base -- Derive the base secret seed for per-channel seeds
 *
 * This secret is the basis for all per-channel secrets: the per-channel seeds
 * will be generated mixing in the channel_id and the peer node_id.
 */
static void hsm_channel_secret_base(struct secret *channel_seed_base)
{
	hkdf_sha256(channel_seed_base, sizeof(struct secret), NULL, 0,
		    &secretstuff.hsm_secret, sizeof(secretstuff.hsm_secret),
		    "peer seed", strlen("peer seed"));
}

static void get_channel_seed(const struct pubkey *peer_id, u64 dbid,
			     struct secret *channel_seed)
{
	struct secret channel_base;
	u8 input[PUBKEY_DER_LEN + sizeof(dbid)];
	const char *info = "per-peer seed";

	hsm_channel_secret_base(&channel_base);
	pubkey_to_der(input, peer_id);
	memcpy(input + PUBKEY_DER_LEN, &dbid, sizeof(dbid));

	hkdf_sha256(channel_seed, sizeof(*channel_seed),
		    input, sizeof(input),
		    &channel_base, sizeof(channel_base),
		    info, strlen(info));
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

/* If privkey is NULL, we don't fill it in */
static void bitcoin_key(struct privkey *privkey, struct pubkey *pubkey,
			u32 index)
{
	struct ext_key ext;
	struct privkey unused_priv;

	if (privkey == NULL)
		privkey = &unused_priv;

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

static struct io_plan *init_hsm(struct io_conn *conn,
				struct client *c,
				const u8 *msg_in)
{
	struct pubkey node_id;

	/* This must be the master. */
	assert(&c->dc == c->master);

	if (!fromwire_hsm_init(msg_in))
		return bad_req(conn, c, msg_in);

	maybe_create_new_hsm();
	load_hsm();

	node_key(NULL, &node_id);
	return req_reply(conn, c,
			 take(towire_hsm_init_reply(NULL, &node_id,
						    &secretstuff.bip32)));
}

static struct io_plan *handle_ecdh(struct io_conn *conn,
				   struct client *c,
				   const u8 *msg_in)
{
	struct privkey privkey;
	struct pubkey point;
	struct secret ss;

	if (!fromwire_hsm_ecdh_req(msg_in, &point))
		return bad_req(conn, c, msg_in);

	node_key(&privkey, NULL);
	if (secp256k1_ecdh(secp256k1_ctx, ss.data, &point.pubkey,
			   privkey.secret.data) != 1) {
		return bad_req_fmt(conn, c, msg_in, "secp256k1_ecdh fail");
	}

	return req_reply(conn, c, take(towire_hsm_ecdh_resp(NULL, &ss)));
}

static struct io_plan *handle_cannouncement_sig(struct io_conn *conn,
						struct client *c,
						const u8 *msg_in)
{
	/* First 2 + 256 byte are the signatures and msg type, skip them */
	size_t offset = 258;
	struct privkey node_pkey;
	secp256k1_ecdsa_signature node_sig, bitcoin_sig;
	struct sha256_double hash;
	u8 *reply;
	u8 *ca;
	struct pubkey funding_pubkey;
	struct privkey funding_privkey;
	struct secret channel_seed;

	/* FIXME: We should cache these. */
	get_channel_seed(&c->id, c->dbid, &channel_seed);
	derive_funding_key(&channel_seed, &funding_pubkey, &funding_privkey);

	if (!fromwire_hsm_cannouncement_sig_req(tmpctx, msg_in, &ca))
		return bad_req(conn, c, msg_in);

	if (tal_count(ca) < offset)
		return bad_req_fmt(conn, c, msg_in,
				   "bad cannounce length %zu",
				   tal_count(ca));

	/* TODO(cdecker) Check that this is actually a valid
	 * channel_announcement */
	node_key(&node_pkey, NULL);
	sha256_double(&hash, ca + offset, tal_count(ca) - offset);

	sign_hash(&node_pkey, &hash, &node_sig);
	sign_hash(&funding_privkey, &hash, &bitcoin_sig);

	reply = towire_hsm_cannouncement_sig_reply(NULL, &node_sig,
						   &bitcoin_sig);
	return req_reply(conn, c, take(reply));
}

static struct io_plan *handle_channel_update_sig(struct io_conn *conn,
						 struct client *c,
						 const u8 *msg_in)
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

	if (!fromwire_hsm_cupdate_sig_req(tmpctx, msg_in, &cu))
		return bad_req(conn, c, msg_in);

	if (!fromwire_channel_update(cu, &sig, &chain_hash,
				     &scid, &timestamp, &flags,
				     &cltv_expiry_delta, &htlc_minimum_msat,
				     &fee_base_msat, &fee_proportional_mill)) {
		return bad_req_fmt(conn, c, msg_in, "Bad inner channel_update");
	}
	if (tal_count(cu) < offset)
		return bad_req_fmt(conn, c, msg_in,
				   "inner channel_update too short");

	node_key(&node_pkey, NULL);
	sha256_double(&hash, cu + offset, tal_count(cu) - offset);

	sign_hash(&node_pkey, &hash, &sig);

	cu = towire_channel_update(tmpctx, &sig, &chain_hash,
				   &scid, timestamp, flags,
				   cltv_expiry_delta, htlc_minimum_msat,
				   fee_base_msat, fee_proportional_mill);
	return req_reply(conn, c, take(towire_hsm_cupdate_sig_reply(NULL, cu)));
}

static struct io_plan *handle_get_channel_basepoints(struct io_conn *conn,
						     struct client *c,
						     const u8 *msg_in)
{
	struct pubkey peer_id;
	u64 dbid;
	struct secret seed;
	struct basepoints basepoints;
	struct pubkey funding_pubkey;

	if (!fromwire_hsm_get_channel_basepoints(msg_in, &peer_id, &dbid))
		return bad_req(conn, c, msg_in);

	get_channel_seed(&peer_id, dbid, &seed);
	derive_basepoints(&seed, &funding_pubkey, &basepoints, NULL, NULL);

	return req_reply(conn, c,
			 take(towire_hsm_get_channel_basepoints_reply(NULL,
							      &basepoints,
							      &funding_pubkey)));
}

/* FIXME: Ensure HSM never does this twice for same dbid! */
static struct io_plan *handle_sign_commitment_tx(struct io_conn *conn,
						 struct client *c,
						 const u8 *msg_in)
{
	struct pubkey peer_id, remote_funding_pubkey, local_funding_pubkey;
	u64 dbid, funding_amount;
	struct secret channel_seed;
	struct bitcoin_tx *tx;
	secp256k1_ecdsa_signature sig;
	struct secrets secrets;
	const u8 *funding_wscript;

	if (!fromwire_hsm_sign_commitment_tx(tmpctx, msg_in,
					     &peer_id, &dbid,
					     &tx,
					     &remote_funding_pubkey,
					     &funding_amount))
		return bad_req(conn, c, msg_in);

	get_channel_seed(&peer_id, dbid, &channel_seed);
	derive_basepoints(&channel_seed,
			  &local_funding_pubkey, NULL, &secrets, NULL);

	funding_wscript = bitcoin_redeem_2of2(tmpctx,
					      &local_funding_pubkey,
					      &remote_funding_pubkey);
	/* Need input amount for signing */
	tx->input[0].amount = tal_dup(tx->input, u64, &funding_amount);
	sign_tx_input(tx, 0, NULL, funding_wscript,
		      &secrets.funding_privkey,
		      &local_funding_pubkey,
		      &sig);

	return req_reply(conn, c,
			 take(towire_hsm_sign_commitment_tx_reply(NULL, &sig)));
}

/* FIXME: make sure it meets some criteria? */
static struct io_plan *handle_sign_remote_commitment_tx(struct io_conn *conn,
							struct client *c,
							const u8 *msg_in)
{
	struct pubkey remote_funding_pubkey, local_funding_pubkey;
	u64 funding_amount;
	struct secret channel_seed;
	struct bitcoin_tx *tx;
	secp256k1_ecdsa_signature sig;
	struct secrets secrets;
	const u8 *funding_wscript;

	if (!fromwire_hsm_sign_remote_commitment_tx(tmpctx, msg_in,
						    &tx,
						    &remote_funding_pubkey,
						    &funding_amount))
		bad_req(conn, c, msg_in);

	get_channel_seed(&c->id, c->dbid, &channel_seed);
	derive_basepoints(&channel_seed,
			  &local_funding_pubkey, NULL, &secrets, NULL);

	funding_wscript = bitcoin_redeem_2of2(tmpctx,
					      &local_funding_pubkey,
					      &remote_funding_pubkey);
	/* Need input amount for signing */
	tx->input[0].amount = tal_dup(tx->input, u64, &funding_amount);
	sign_tx_input(tx, 0, NULL, funding_wscript,
		      &secrets.funding_privkey,
		      &local_funding_pubkey,
		      &sig);

	return req_reply(conn, c, take(towire_hsm_sign_tx_reply(NULL, &sig)));
}

static struct io_plan *handle_sign_remote_htlc_tx(struct io_conn *conn,
						  struct client *c,
						  const u8 *msg_in)
{
	struct secret channel_seed;
	struct bitcoin_tx *tx;
	secp256k1_ecdsa_signature sig;
	struct secrets secrets;
	struct basepoints basepoints;
	struct pubkey remote_per_commit_point;
	u64 amount;
	u8 *wscript;
	struct privkey htlc_privkey;
	struct pubkey htlc_pubkey;

	if (!fromwire_hsm_sign_remote_htlc_tx(tmpctx, msg_in,
					      &tx, &wscript, &amount,
					      &remote_per_commit_point))
		return bad_req(conn, c, msg_in);

	get_channel_seed(&c->id, c->dbid, &channel_seed);
	derive_basepoints(&channel_seed, NULL, &basepoints, &secrets, NULL);

	if (!derive_simple_privkey(&secrets.htlc_basepoint_secret,
				   &basepoints.htlc,
				   &remote_per_commit_point,
				   &htlc_privkey))
		return bad_req_fmt(conn, c, msg_in,
				   "Failed deriving htlc privkey");

	if (!derive_simple_key(&basepoints.htlc,
			       &remote_per_commit_point,
			       &htlc_pubkey))
		return bad_req_fmt(conn, c, msg_in,
				   "Failed deriving htlc pubkey");

	/* Need input amount for signing */
	tx->input[0].amount = tal_dup(tx->input, u64, &amount);
	sign_tx_input(tx, 0, NULL, wscript, &htlc_privkey, &htlc_pubkey, &sig);

	return req_reply(conn, c, take(towire_hsm_sign_tx_reply(NULL, &sig)));
}

/* FIXME: Derive output address for this client, and check it here! */
static struct io_plan *handle_sign_to_us_tx(struct io_conn *conn,
					    struct client *c,
					    const u8 *msg_in,
					    struct bitcoin_tx *tx,
					    const struct privkey *privkey,
					    const u8 *wscript,
					    u64 input_amount)
{
	secp256k1_ecdsa_signature sig;
	struct pubkey pubkey;

	if (!pubkey_from_privkey(privkey, &pubkey))
		return bad_req_fmt(conn, c, msg_in, "bad pubkey_from_privkey");

	if (tal_count(tx->input) != 1)
		return bad_req_fmt(conn, c, msg_in, "bad txinput count");

	tx->input[0].amount = tal_dup(tx->input, u64, &input_amount);
	sign_tx_input(tx, 0, NULL, wscript, privkey, &pubkey, &sig);

	return req_reply(conn, c, take(towire_hsm_sign_tx_reply(NULL, &sig)));
}

static struct io_plan *handle_sign_delayed_payment_to_us(struct io_conn *conn,
							 struct client *c,
							 const u8 *msg_in)
{
	u64 commit_num, input_amount;
	struct secret channel_seed, basepoint_secret;
	struct pubkey basepoint;
	struct bitcoin_tx *tx;
	struct sha256 shaseed;
	struct pubkey per_commitment_point;
	struct privkey privkey;
	u8 *wscript;

	if (!fromwire_hsm_sign_delayed_payment_to_us(tmpctx, msg_in,
						     &commit_num,
						     &tx, &wscript,
						     &input_amount))
		return bad_req(conn, c, msg_in);

	get_channel_seed(&c->id, c->dbid, &channel_seed);

	if (!derive_shaseed(&channel_seed, &shaseed))
		return bad_req_fmt(conn, c, msg_in, "bad derive_shaseed");

	if (!per_commit_point(&shaseed, &per_commitment_point, commit_num))
		return bad_req_fmt(conn, c, msg_in,
				   "bad per_commitment_point %"PRIu64,
				   commit_num);

	if (!derive_delayed_payment_basepoint(&channel_seed,
					      &basepoint,
					      &basepoint_secret))
		return bad_req_fmt(conn, c, msg_in, "failed deriving basepoint");

	if (!derive_simple_privkey(&basepoint_secret,
				   &basepoint,
				   &per_commitment_point,
				   &privkey))
		return bad_req_fmt(conn, c, msg_in, "failed deriving privkey");

	return handle_sign_to_us_tx(conn, c, msg_in,
				    tx, &privkey, wscript, input_amount);
}

static struct io_plan *handle_sign_remote_htlc_to_us(struct io_conn *conn,
						     struct client *c,
						     const u8 *msg_in)
{
	u64 input_amount;
	struct secret channel_seed, htlc_basepoint_secret;
	struct pubkey htlc_basepoint;
	struct bitcoin_tx *tx;
	struct pubkey remote_per_commitment_point;
	struct privkey privkey;
	u8 *wscript;

	if (!fromwire_hsm_sign_remote_htlc_to_us(tmpctx, msg_in,
						 &remote_per_commitment_point,
						 &tx, &wscript,
						 &input_amount))
		return bad_req(conn, c, msg_in);

	get_channel_seed(&c->id, c->dbid, &channel_seed);

	if (!derive_htlc_basepoint(&channel_seed, &htlc_basepoint,
				   &htlc_basepoint_secret))
		return bad_req_fmt(conn, c, msg_in,
				   "Failed derive_htlc_basepoint");

	if (!derive_simple_privkey(&htlc_basepoint_secret,
				   &htlc_basepoint,
				   &remote_per_commitment_point,
				   &privkey))
		return bad_req_fmt(conn, c, msg_in,
				   "Failed deriving htlc privkey");

	return handle_sign_to_us_tx(conn, c, msg_in,
				    tx, &privkey, wscript, input_amount);
}

static struct io_plan *handle_sign_penalty_to_us(struct io_conn *conn,
						 struct client *c,
						 const u8 *msg_in)
{
	u64 input_amount;
	struct secret channel_seed, revocation_secret, revocation_basepoint_secret;
	struct pubkey revocation_basepoint;
	struct bitcoin_tx *tx;
	struct pubkey point;
	struct privkey privkey;
	u8 *wscript;

	if (!fromwire_hsm_sign_penalty_to_us(tmpctx, msg_in,
					     &revocation_secret,
					     &tx, &wscript,
					     &input_amount))
		return bad_req(conn, c, msg_in);

	if (!pubkey_from_secret(&revocation_secret, &point))
		return bad_req_fmt(conn, c, msg_in, "Failed deriving pubkey");

	get_channel_seed(&c->id, c->dbid, &channel_seed);
	if (!derive_revocation_basepoint(&channel_seed,
					 &revocation_basepoint,
					 &revocation_basepoint_secret))
		return bad_req_fmt(conn, c, msg_in,
				   "Failed deriving revocation basepoint");

	if (!derive_revocation_privkey(&revocation_basepoint_secret,
				       &revocation_secret,
				       &revocation_basepoint,
				       &point,
				       &privkey))
		return bad_req_fmt(conn, c, msg_in,
				   "Failed deriving revocation privkey");

	return handle_sign_to_us_tx(conn, c, msg_in,
				    tx, &privkey, wscript, input_amount);
}

static struct io_plan *handle_sign_local_htlc_tx(struct io_conn *conn,
						 struct client *c,
						 const u8 *msg_in)
{
	u64 commit_num, input_amount;
	struct secret channel_seed, htlc_basepoint_secret;
	struct sha256 shaseed;
	struct pubkey per_commitment_point, htlc_basepoint;
	struct bitcoin_tx *tx;
	u8 *wscript;
	secp256k1_ecdsa_signature sig;
	struct privkey htlc_privkey;
	struct pubkey htlc_pubkey;

	if (!fromwire_hsm_sign_local_htlc_tx(tmpctx, msg_in,
					     &commit_num, &tx, &wscript,
					     &input_amount))
		return bad_req(conn, c, msg_in);

	get_channel_seed(&c->id, c->dbid, &channel_seed);

	if (!derive_shaseed(&channel_seed, &shaseed))
		return bad_req_fmt(conn, c, msg_in, "bad derive_shaseed");

	if (!per_commit_point(&shaseed, &per_commitment_point, commit_num))
		return bad_req_fmt(conn, c, msg_in,
				   "bad per_commitment_point %"PRIu64,
				   commit_num);

	if (!derive_htlc_basepoint(&channel_seed,
				   &htlc_basepoint,
				   &htlc_basepoint_secret))
		return bad_req_fmt(conn, c, msg_in,
				   "Failed deriving htlc basepoint");

	if (!derive_simple_privkey(&htlc_basepoint_secret,
				   &htlc_basepoint,
				   &per_commitment_point,
				   &htlc_privkey))
		return bad_req_fmt(conn, c, msg_in,
				   "Failed deriving htlc privkey");

	if (!pubkey_from_privkey(&htlc_privkey, &htlc_pubkey))
		return bad_req_fmt(conn, c, msg_in, "bad pubkey_from_privkey");

	if (tal_count(tx->input) != 1)
		return bad_req_fmt(conn, c, msg_in, "bad txinput count");

	/* FIXME: Check that output script is correct! */
	tx->input[0].amount = tal_dup(tx->input, u64, &input_amount);
	sign_tx_input(tx, 0, NULL, wscript, &htlc_privkey, &htlc_pubkey, &sig);

	return req_reply(conn, c, take(towire_hsm_sign_tx_reply(NULL, &sig)));
}

static struct io_plan *handle_get_per_commitment_point(struct io_conn *conn,
						       struct client *c,
						       const u8 *msg_in)
{
	struct secret channel_seed;
	struct sha256 shaseed;
	struct pubkey per_commitment_point;
	u64 n;
	struct secret *old_secret;

	if (!fromwire_hsm_get_per_commitment_point(msg_in, &n))
		return bad_req(conn, c, msg_in);

	get_channel_seed(&c->id, c->dbid, &channel_seed);
	if (!derive_shaseed(&channel_seed, &shaseed))
		return bad_req_fmt(conn, c, msg_in, "bad derive_shaseed");

	if (!per_commit_point(&shaseed, &per_commitment_point, n))
		return bad_req_fmt(conn, c, msg_in,
				   "bad per_commit_point %"PRIu64, n);

	if (n >= 2) {
		old_secret = tal(tmpctx, struct secret);
		if (!per_commit_secret(&shaseed, old_secret, n - 2)) {
			return bad_req_fmt(conn, c, msg_in,
					   "Cannot derive secret %"PRIu64,
					   n - 2);
		}
	} else
		old_secret = NULL;

	return req_reply(conn, c,
			 take(towire_hsm_get_per_commitment_point_reply(NULL,
									&per_commitment_point,
									old_secret)));
}

static struct io_plan *handle_check_future_secret(struct io_conn *conn,
						  struct client *c,
						  const u8 *msg_in)
{
	struct secret channel_seed;
	struct sha256 shaseed;
	u64 n;
	struct secret secret, suggested;

	if (!fromwire_hsm_check_future_secret(msg_in, &n, &suggested))
		return bad_req(conn, c, msg_in);

	get_channel_seed(&c->id, c->dbid, &channel_seed);
	if (!derive_shaseed(&channel_seed, &shaseed))
		return bad_req_fmt(conn, c, msg_in, "bad derive_shaseed");

	if (!per_commit_secret(&shaseed, &secret, n))
		return bad_req_fmt(conn, c, msg_in,
				   "bad commit secret #%"PRIu64, n);

	return req_reply(conn, c,
			 take(towire_hsm_check_future_secret_reply(NULL,
				   secret_eq_consttime(&secret, &suggested))));
}

static struct io_plan *handle_sign_mutual_close_tx(struct io_conn *conn,
						   struct client *c,
						   const u8 *msg_in)
{
	struct secret channel_seed;
	struct bitcoin_tx *tx;
	struct pubkey remote_funding_pubkey, local_funding_pubkey;
	secp256k1_ecdsa_signature sig;
	struct secrets secrets;
	u64 funding_amount;
	const u8 *funding_wscript;

	if (!fromwire_hsm_sign_mutual_close_tx(tmpctx, msg_in,
					       &tx,
					       &remote_funding_pubkey,
					       &funding_amount))
		return bad_req(conn, c, msg_in);

	/* FIXME: We should know dust level, decent fee range and
	 * balances, and final_keyindex, and thus be able to check tx
	 * outputs! */
	get_channel_seed(&c->id, c->dbid, &channel_seed);
	derive_basepoints(&channel_seed,
			  &local_funding_pubkey, NULL, &secrets, NULL);

	funding_wscript = bitcoin_redeem_2of2(tmpctx,
					      &local_funding_pubkey,
					      &remote_funding_pubkey);
	/* Need input amount for signing */
	tx->input[0].amount = tal_dup(tx->input, u64, &funding_amount);
	sign_tx_input(tx, 0, NULL, funding_wscript,
		      &secrets.funding_privkey,
		      &local_funding_pubkey,
		      &sig);

	return req_reply(conn, c, take(towire_hsm_sign_tx_reply(NULL, &sig)));
}

static struct io_plan *pass_client_hsmfd(struct io_conn *conn,
					 struct client *c,
					 const u8 *msg_in)
{
	int fds[2];
	u64 dbid, capabilities;
	struct pubkey id;

	/* This must be the master. */
	assert(&c->dc == c->master);

	if (!fromwire_hsm_client_hsmfd(msg_in, &id, &dbid, &capabilities))
		return bad_req(conn, c, msg_in);

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0)
		status_failed(STATUS_FAIL_INTERNAL_ERROR, "creating fds: %s", strerror(errno));

	new_client(&c->dc, &id, dbid, capabilities, fds[0]);
	daemon_conn_send(&c->dc, take(towire_hsm_client_hsmfd_reply(NULL)));
	daemon_conn_send_fd(&c->dc, fds[1]);
	return daemon_conn_read_next(conn, &c->dc);
}

static void hsm_unilateral_close_privkey(struct privkey *dst,
					 struct unilateral_close_info *info)
{
	struct secret channel_seed;
	struct basepoints basepoints;
	struct secrets secrets;

	get_channel_seed(&info->peer_id, info->channel_id, &channel_seed);
	derive_basepoints(&channel_seed, NULL, &basepoints, &secrets, NULL);

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
		bitcoin_key(privkey, pubkey, utxo->keyindex);
	}
}

/* Note that it's the main daemon that asks for the funding signature so it
 * can broadcast it. */
static struct io_plan *handle_sign_funding_tx(struct io_conn *conn,
					      struct client *c,
					      const u8 *msg_in)
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
	if (!fromwire_hsm_sign_funding(tmpctx, msg_in,
				       &satoshi_out, &change_out,
				       &change_keyindex, &local_pubkey,
				       &remote_pubkey, &utxomap))
		return bad_req(conn, c, msg_in);

	if (change_out) {
		changekey = tal(tmpctx, struct pubkey);
		bitcoin_key(NULL, changekey, change_keyindex);
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

	return req_reply(conn, c, take(towire_hsm_sign_funding_reply(NULL, tx)));
}

/**
 * sign_withdrawal_tx - Generate and sign a withdrawal transaction from the master
 */
static struct io_plan *handle_sign_withdrawal_tx(struct io_conn *conn,
						 struct client *c,
						 const u8 *msg_in)
{
	u64 satoshi_out, change_out;
	u32 change_keyindex;
	struct utxo **utxos;
	u8 **scriptSigs;
	struct bitcoin_tx *tx;
	struct ext_key ext;
	struct pubkey changekey;
	u8 *scriptpubkey;

	if (!fromwire_hsm_sign_withdrawal(tmpctx, msg_in, &satoshi_out,
					  &change_out, &change_keyindex,
					  &scriptpubkey, &utxos))
		return bad_req(conn, c, msg_in);

	if (bip32_key_from_parent(&secretstuff.bip32, change_keyindex,
				  BIP32_FLAG_KEY_PUBLIC, &ext) != WALLY_OK)
		return bad_req_fmt(conn, c, msg_in,
				   "Failed to get key %u", change_keyindex);

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

	return req_reply(conn, c,
			 take(towire_hsm_sign_withdrawal_reply(NULL, tx)));
}

/**
 * sign_invoice - Sign an invoice with our key.
 */
static struct io_plan *handle_sign_invoice(struct io_conn *conn,
					   struct client *c,
					   const u8 *msg_in)
{
	u5 *u5bytes;
	u8 *hrpu8;
	char *hrp;
	struct sha256 sha;
        secp256k1_ecdsa_recoverable_signature rsig;
	struct hash_u5 hu5;
	struct privkey node_pkey;

	if (!fromwire_hsm_sign_invoice(tmpctx, msg_in, &u5bytes, &hrpu8))
		return bad_req(conn, c, msg_in);

	/* FIXME: Check invoice! */

	hrp = tal_dup_arr(tmpctx, char, (char *)hrpu8, tal_count(hrpu8), 1);
	hrp[tal_count(hrpu8)] = '\0';

	hash_u5_init(&hu5, hrp);
	hash_u5(&hu5, u5bytes, tal_count(u5bytes));
	hash_u5_done(&hu5, &sha);

	node_key(&node_pkey, NULL);
        if (!secp256k1_ecdsa_sign_recoverable(secp256k1_ctx, &rsig,
                                              (const u8 *)&sha,
                                              node_pkey.secret.data,
                                              NULL, NULL)) {
		return bad_req_fmt(conn, c, msg_in, "Failed to sign invoice");
	}

	return req_reply(conn, c,
			 take(towire_hsm_sign_invoice_reply(NULL, &rsig)));
}

static struct io_plan *handle_sign_node_announcement(struct io_conn *conn,
						     struct client *c,
						     const u8 *msg_in)
{
	/* 2 bytes msg type + 64 bytes signature */
	size_t offset = 66;
	struct sha256_double hash;
	struct privkey node_pkey;
	secp256k1_ecdsa_signature sig;
	u8 *reply;
	u8 *ann;

	if (!fromwire_hsm_node_announcement_sig_req(tmpctx, msg_in, &ann))
		return bad_req(conn, c, msg_in);

	if (tal_count(ann) < offset)
		return bad_req_fmt(conn, c, msg_in,
				   "Node announcement too short");

	/* FIXME(cdecker) Check the node announcement's content */
	node_key(&node_pkey, NULL);
	sha256_double(&hash, ann + offset, tal_count(ann) - offset);

	sign_hash(&node_pkey, &hash, &sig);

	reply = towire_hsm_node_announcement_sig_reply(NULL, &sig);
	return req_reply(conn, c, take(reply));
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

	case WIRE_HSM_SIGN_DELAYED_PAYMENT_TO_US:
	case WIRE_HSM_SIGN_REMOTE_HTLC_TO_US:
	case WIRE_HSM_SIGN_PENALTY_TO_US:
	case WIRE_HSM_SIGN_LOCAL_HTLC_TX:
		return (client->capabilities & HSM_CAP_SIGN_ONCHAIN_TX) != 0;

	case WIRE_HSM_GET_PER_COMMITMENT_POINT:
	case WIRE_HSM_CHECK_FUTURE_SECRET:
		return (client->capabilities & HSM_CAP_COMMITMENT_POINT) != 0;

	case WIRE_HSM_SIGN_REMOTE_COMMITMENT_TX:
	case WIRE_HSM_SIGN_REMOTE_HTLC_TX:
		return (client->capabilities & HSM_CAP_SIGN_REMOTE_TX) != 0;

	case WIRE_HSM_SIGN_MUTUAL_CLOSE_TX:
		return (client->capabilities & HSM_CAP_SIGN_CLOSING_TX) != 0;

	case WIRE_HSM_INIT:
	case WIRE_HSM_CLIENT_HSMFD:
	case WIRE_HSM_SIGN_FUNDING:
	case WIRE_HSM_SIGN_WITHDRAWAL:
	case WIRE_HSM_SIGN_INVOICE:
	case WIRE_HSM_SIGN_COMMITMENT_TX:
	case WIRE_HSM_GET_CHANNEL_BASEPOINTS:
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
	case WIRE_HSM_SIGN_COMMITMENT_TX_REPLY:
	case WIRE_HSM_SIGN_TX_REPLY:
	case WIRE_HSM_GET_PER_COMMITMENT_POINT_REPLY:
	case WIRE_HSM_CHECK_FUTURE_SECRET_REPLY:
	case WIRE_HSM_GET_CHANNEL_BASEPOINTS_REPLY:
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
	if (!check_client_capabilities(c, t))
		return bad_req_fmt(conn, c, dc->msg_in,
				   "does not have capability to run %d", t);

	/* Now actually go and do what the client asked for */
	switch (t) {
	case WIRE_HSM_INIT:
		return init_hsm(conn, c, dc->msg_in);

	case WIRE_HSM_CLIENT_HSMFD:
		return pass_client_hsmfd(conn, c, dc->msg_in);

	case WIRE_HSM_GET_CHANNEL_BASEPOINTS:
		return handle_get_channel_basepoints(conn, c, dc->msg_in);

	case WIRE_HSM_ECDH_REQ:
		return handle_ecdh(conn, c, dc->msg_in);

	case WIRE_HSM_CANNOUNCEMENT_SIG_REQ:
		return handle_cannouncement_sig(conn, c, dc->msg_in);

	case WIRE_HSM_CUPDATE_SIG_REQ:
		return handle_channel_update_sig(conn, c, dc->msg_in);

	case WIRE_HSM_SIGN_FUNDING:
		return handle_sign_funding_tx(conn, c, dc->msg_in);

	case WIRE_HSM_NODE_ANNOUNCEMENT_SIG_REQ:
		return handle_sign_node_announcement(conn, c, dc->msg_in);

	case WIRE_HSM_SIGN_INVOICE:
		return handle_sign_invoice(conn, c, dc->msg_in);

	case WIRE_HSM_SIGN_WITHDRAWAL:
		return handle_sign_withdrawal_tx(conn, c, dc->msg_in);

	case WIRE_HSM_SIGN_COMMITMENT_TX:
		return handle_sign_commitment_tx(conn, c, dc->msg_in);

	case WIRE_HSM_SIGN_DELAYED_PAYMENT_TO_US:
		return handle_sign_delayed_payment_to_us(conn, c, dc->msg_in);

	case WIRE_HSM_SIGN_REMOTE_HTLC_TO_US:
		return handle_sign_remote_htlc_to_us(conn, c, dc->msg_in);

	case WIRE_HSM_SIGN_PENALTY_TO_US:
		return handle_sign_penalty_to_us(conn, c, dc->msg_in);

	case WIRE_HSM_SIGN_LOCAL_HTLC_TX:
		return handle_sign_local_htlc_tx(conn, c, dc->msg_in);

	case WIRE_HSM_GET_PER_COMMITMENT_POINT:
		return handle_get_per_commitment_point(conn, c, dc->msg_in);

	case WIRE_HSM_CHECK_FUTURE_SECRET:
		return handle_check_future_secret(conn, c, dc->msg_in);

	case WIRE_HSM_SIGN_REMOTE_COMMITMENT_TX:
		return handle_sign_remote_commitment_tx(conn, c, dc->msg_in);

	case WIRE_HSM_SIGN_REMOTE_HTLC_TX:
		return handle_sign_remote_htlc_tx(conn, c, dc->msg_in);

	case WIRE_HSM_SIGN_MUTUAL_CLOSE_TX:
		return handle_sign_mutual_close_tx(conn, c, dc->msg_in);

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
	case WIRE_HSM_SIGN_COMMITMENT_TX_REPLY:
	case WIRE_HSM_SIGN_TX_REPLY:
	case WIRE_HSM_GET_PER_COMMITMENT_POINT_REPLY:
	case WIRE_HSM_CHECK_FUTURE_SECRET_REPLY:
	case WIRE_HSM_GET_CHANNEL_BASEPOINTS_REPLY:
		break;
	}

	return bad_req_fmt(conn, c, dc->msg_in, "Unknown request");
}

static void destroy_client(struct client *c)
{
	if (!uintmap_del(&clients, c->dbid))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Failed to remove client dbid %"PRIu64, c->dbid);
}

static struct client *new_client(struct daemon_conn *master,
				 const struct pubkey *id,
				 u64 dbid,
				 const u64 capabilities,
				 int fd)
{
	struct client *c = tal(master, struct client);

	if (id) {
		c->id = *id;
	} else {
		memset(&c->id, 0, sizeof(c->id));
	}
	c->dbid = dbid;

	c->master = master;
	c->capabilities = capabilities;
	daemon_conn_init(c, &c->dc, fd, handle_client, NULL);

	/* Free the connection if we exit everything. */
	tal_steal(master, c->dc.conn);
	/* Free client when connection freed. */
	tal_steal(c->dc.conn, c);

	if (dbid == 0) {
		assert(num_dbid_zero_clients < ARRAY_SIZE(dbid_zero_clients));
		dbid_zero_clients[num_dbid_zero_clients++] = c;
	} else {
		struct client *old_client = uintmap_get(&clients, dbid);

		/* Close conn and free any old client of this dbid. */
		if (old_client)
			io_close(old_client->dc.conn);

		if (!uintmap_add(&clients, dbid, c))
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "Failed inserting dbid %"PRIu64, dbid);
		tal_add_destructor(c, destroy_client);
	}

	return c;
}

static void master_gone(struct io_conn *unused UNUSED, struct daemon_conn *dc UNUSED)
{
	daemon_shutdown();
	/* Can't tell master, it's gone. */
	exit(2);
}

int main(int argc, char *argv[])
{
	struct client *master;

	setup_locale();

	subdaemon_setup(argc, argv);

	/* A trivial daemon_conn just for writing. */
	status_conn = tal(NULL, struct daemon_conn);
	daemon_conn_init(status_conn, status_conn, STDIN_FILENO,
			 (void *)io_never, NULL);
	status_setup_async(status_conn);
	uintmap_init(&clients);

	master = new_client(NULL, NULL, 0, HSM_CAP_MASTER | HSM_CAP_SIGN_GOSSIP,
			    REQ_FD);

	/* We're our own master! */
	master->master = &master->dc;

	/* When conn closes, everything is freed. */
	io_set_finish(master->dc.conn, master_gone, &master->dc);

	io_loop(NULL, NULL);
	abort();
}
