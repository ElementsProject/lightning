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
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <lightningd/hsm/client.h>
#include <lightningd/hsm/gen_hsm_client_wire.h>
#include <lightningd/hsm/gen_hsm_control_wire.h>
#include <lightningd/hsm/gen_hsm_status_wire.h>
#include <permute_tx.h>
#include <secp256k1_ecdh.h>
#include <sodium/randombytes.h>
#include <status.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <utils.h>
#include <version.h>
#include <wally_bip32.h>
#include <wire/wire_io.h>

/* Nobody will ever find it here! */
static struct {
	struct privkey hsm_secret;
	struct ext_key bip32;
} secretstuff;

struct conn_info {
	struct io_plan *(*received_req)(struct io_conn *, struct conn_info *);
	u8 *in;
	u8 *out;
	int out_fd;
};

struct client {
	struct conn_info ci;
	u64 id;
	u8 *(*handle)(struct client *c, const tal_t *data);
};

static void node_key(struct privkey *node_secret, struct pubkey *node_id)
{
	u32 salt = 0;
	struct privkey unused_s;
	struct pubkey unused_k;

	if (node_secret == NULL)
		node_secret = &unused_s;
	else if (node_id == NULL)
		node_id = &unused_k;

	do {
		hkdf_sha256(node_secret, sizeof(*node_secret),
			    &salt, sizeof(salt),
			    &secretstuff.hsm_secret,
			    sizeof(secretstuff.hsm_secret),
			    "nodeid", 6);
		salt++;
	} while (!secp256k1_ec_pubkey_create(secp256k1_ctx, &node_id->pubkey,
					     node_secret->secret));
}

static void conn_info_init(struct conn_info *ci,
			   struct io_plan *(*received_req)(struct io_conn *conn,
							   struct conn_info *ci))
{
	ci->received_req = received_req;
	ci->in = ci->out = NULL;
	ci->out_fd = -1;
}

static struct io_plan *sent_resp(struct io_conn *conn, struct conn_info *ci);

/* Client operations */
static struct io_plan *client_received_req(struct io_conn *conn,
					   struct conn_info *ci)
{
	struct client *c = container_of(ci, struct client, ci);

	status_trace("Client %"PRIu64": type %s len %zu",
		     c->id,
		     hsm_client_wire_type_name(fromwire_peektype(ci->in)),
		     tal_count(ci->in));

	ci->out = c->handle(c, ci->in);
	if (!ci->out) {
		status_send(towire_hsmstatus_client_bad_request(c, c->id,
								ci->in));
		return io_close(conn);
	}
	ci->in = tal_free(ci->in);
	return io_write_wire(conn, ci->out, sent_resp, ci);
}

static struct client *new_client(const tal_t *ctx,
				 u64 id,
				 u8 *(*handle)(struct client *c,
					       const tal_t *data))
{
	struct client *c = tal(ctx, struct client);
	c->id = id;
	c->handle = handle;
	conn_info_init(&c->ci, client_received_req);

	return c;
}

static u8 *handle_ecdh(struct client *c, const void *data)
{
	struct privkey privkey;
	struct pubkey point;
	struct sha256 ss;

	if (!fromwire_hsm_ecdh_req(data, NULL, &point))
		return NULL;

	node_key(&privkey, NULL);
	if (secp256k1_ecdh(secp256k1_ctx, ss.u.u8, &point.pubkey,
			   privkey.secret) != 1)
		return NULL;

	return towire_hsm_ecdh_resp(c, &ss);
}

/* Control messages */
static u8 *init_response(struct conn_info *control)
{
	struct pubkey node_id;
	u8 *serialized_extkey = tal_arr(control, u8, BIP32_SERIALIZED_LEN), *msg;

	node_key(NULL, &node_id);
	if (bip32_key_serialize(&secretstuff.bip32, BIP32_FLAG_KEY_PUBLIC,
				serialized_extkey, tal_len(serialized_extkey))
	    != WALLY_OK)
		status_failed(WIRE_HSMSTATUS_KEY_FAILED,
			      "Can't serialize bip32 public key");

	msg = towire_hsmctl_init_response(control, &node_id, serialized_extkey);
	tal_free(serialized_extkey);
	return msg;
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
	memcpy(privkey->secret, ext.priv_key+1, 32);
	if (!secp256k1_ec_pubkey_create(secp256k1_ctx, &pubkey->pubkey,
					privkey->secret))
		status_failed(WIRE_HSMSTATUS_KEY_FAILED,
			      "BIP32 pubkey %u create failed", index);
}

static u8 *create_new_hsm(struct conn_info *control)
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

	return init_response(control);
}

static u8 *load_hsm(struct conn_info *control)
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

	return init_response(control);
}

static struct io_plan *recv_req(struct io_conn *conn, struct conn_info *ci)
{
	return io_read_wire(conn, ci, &ci->in, ci->received_req, ci);
}

static struct io_plan *sent_out_fd(struct io_conn *conn, struct conn_info *ci)
{
	ci->out_fd = -1;
	return recv_req(conn, ci);
}

static struct io_plan *sent_resp(struct io_conn *conn, struct conn_info *ci)
{
	ci->out = tal_free(ci->out);
	if (ci->out_fd != -1)
		return io_send_fd(conn, ci->out_fd, sent_out_fd, ci);
	return recv_req(conn, ci);
}

static struct io_plan *ecdh_client(struct io_conn *conn, struct client *c)
{
	tal_steal(conn, c);
	return recv_req(conn, &c->ci);
}

static u8 *pass_hsmfd_ecdh(struct io_conn *conn,
			   struct conn_info *control,
			   const tal_t *data,
			   int *fd_to_pass)
{
	int fds[2];
	u64 id;
	struct client *c;

	if (!fromwire_hsmctl_hsmfd_ecdh(data, NULL, &id))
		status_failed(WIRE_HSMSTATUS_BAD_REQUEST, "bad HSMFD_ECDH");

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0)
		status_failed(WIRE_HSMSTATUS_FD_FAILED,
			      "creating fds: %s", strerror(errno));

	c = new_client(control, id, handle_ecdh);
	io_new_conn(control, fds[0], ecdh_client, c);

	*fd_to_pass = fds[1];
	return towire_hsmctl_hsmfd_fd_response(control);
}

/* Note that it's the main daemon that asks for the funding signature so it
 * can broadcast it. */
static u8 *sign_funding_tx(const tal_t *ctx, const u8 *data)
{
	const tal_t *tmpctx = tal_tmpctx(ctx);
	u64 satoshi_out, change_out;
	u32 change_keyindex;
	struct privkey local_privkey;
	struct pubkey local_pubkey, remote_pubkey;
	struct utxo *inputs;
	struct bitcoin_tx *tx;
	u8 *wscript, *msg_out;
	secp256k1_ecdsa_signature *sig;
	const void **inmap;
	size_t i;

	/* FIXME: Check fee is "reasonable" */
	if (!fromwire_hsmctl_sign_funding(tmpctx, data, NULL,
					  &satoshi_out, &change_out,
					  &change_keyindex, &local_privkey,
					  &local_pubkey, &inputs))
		status_failed(WIRE_HSMSTATUS_BAD_REQUEST, "Bad SIGN_FUNDING");

	if (!secp256k1_ec_pubkey_create(secp256k1_ctx,
					&local_pubkey.pubkey,
					local_privkey.secret))
		status_failed(WIRE_HSMSTATUS_BAD_REQUEST,
			      "Bad SIGN_FUNDING privkey");

	tx = bitcoin_tx(tmpctx, tal_count(inputs), 1 + !!change_out);
	inmap = tal_arr(tmpctx, const void *, tal_count(inputs));
	for (i = 0; i < tal_count(inputs); i++) {
		tx->input[i].txid = inputs[i].txid;
		tx->input[i].index = inputs[i].outnum;
		tx->input[i].amount = tal_dup(tx->input, u64, &inputs[i].amount);
		inmap[i] = int2ptr(i);
	}
	tx->output[0].amount = satoshi_out;
	wscript = bitcoin_redeem_2of2(tx, &local_pubkey, &remote_pubkey);
	tx->output[0].script = scriptpubkey_p2wsh(tx, wscript);
	if (change_out) {
		struct pubkey changekey;
		bitcoin_pubkey(&changekey, change_keyindex);

		tx->output[1].amount = change_out;
		tx->output[1].script = scriptpubkey_p2wpkh(tx, &changekey);
	}

	/* Now permute. */
	permute_outputs(tx->output, tal_count(tx->output), NULL);
	permute_inputs(tx->input, tal_count(tx->input), inmap);

	/* Now generate signatures. */
	sig = tal_arr(tmpctx, secp256k1_ecdsa_signature, tal_count(inputs));
	for (i = 0; i < tal_count(inputs); i++) {
		struct pubkey inkey;
		struct privkey inprivkey;
		const struct utxo *in = &inputs[ptr2int(inmap[i])];
		u8 *subscript;

		bitcoin_keypair(&inprivkey, &inkey, in->keyindex);
		if (in->is_p2sh)
			subscript = bitcoin_redeem_p2wpkh(tmpctx, &inkey);
		else
			subscript = NULL;
		wscript = p2wpkh_scriptcode(tmpctx, &inkey);

		sign_tx_input(tx, i, subscript, wscript,
			      &inprivkey, &inkey, &sig[i]);
	}

	msg_out = towire_hsmctl_sign_funding_response(ctx, sig);
	tal_free(tmpctx);
	return msg_out;
}

static struct io_plan *control_received_req(struct io_conn *conn,
					    struct conn_info *control)
{
	enum hsm_control_wire_type t = fromwire_peektype(control->in);

	status_trace("Control: type %s len %zu",
		     hsm_control_wire_type_name(t), tal_count(control->in));

	switch (t) {
	case WIRE_HSMCTL_INIT_NEW:
		control->out = create_new_hsm(control);
		goto send_out;
	case WIRE_HSMCTL_INIT_LOAD:
		control->out = load_hsm(control);
		goto send_out;
	case WIRE_HSMCTL_HSMFD_ECDH:
		control->out = pass_hsmfd_ecdh(conn, control, control->in,
					       &control->out_fd);
		goto send_out;
	case WIRE_HSMCTL_SIGN_FUNDING:
		control->out = sign_funding_tx(control, control->in);
		goto send_out;

	case WIRE_HSMCTL_INIT_RESPONSE:
	case WIRE_HSMCTL_HSMFD_FD_RESPONSE:
	case WIRE_HSMCTL_SIGN_FUNDING_RESPONSE:
		break;
	}

	/* Control shouldn't give bad requests. */
	status_failed(WIRE_HSMSTATUS_BAD_REQUEST, "%i", t);

send_out:
	if (control->out)
		return io_write_wire(conn, control->out, sent_resp, control);
	else
		return sent_resp(conn, control);
}

static struct io_plan *control_init(struct io_conn *conn,
				    struct conn_info *control)
{
	return recv_req(conn, control);
}

/* Exit when control fd closes. */
static void control_finish(struct io_conn *conn, struct conn_info *control)
{
	io_break(control);
}

#ifndef TESTING
int main(int argc, char *argv[])
{
	struct conn_info *control;

	if (argc == 2 && streq(argv[1], "--version")) {
		printf("%s\n", version());
		exit(0);
	}

	breakpoint();
	secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY
						 | SECP256K1_CONTEXT_SIGN);

	control = tal(NULL, struct conn_info);
	conn_info_init(control, control_received_req);

	/* Stdout == status, stdin == requests */
	status_setup(STDOUT_FILENO);

	io_set_finish(io_new_conn(control, STDIN_FILENO, control_init, control),
		      control_finish, control);

	io_loop(NULL, NULL);

	tal_free(control);
	return 0;
}
#endif
