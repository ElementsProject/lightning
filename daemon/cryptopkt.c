#include "bitcoin/shadouble.h"
#include "bitcoin/signature.h"
#include "cryptopkt.h"
#include "lightning.pb-c.h"
#include "lightningd.h"
#include "log.h"
#include "names.h"
#include "peer.h"
#include "peer_internal.h"
#include "protobuf_convert.h"
#include "secrets.h"
#include "utils.h"
#include <ccan/build_assert/build_assert.h>
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/endian/endian.h>
#include <ccan/mem/mem.h>
#include <ccan/short_types/short_types.h>
#include <ccan/structeq/structeq.h>
#include <inttypes.h>
#include <secp256k1.h>
#include <secp256k1_ecdh.h>
#include <sodium/crypto_aead_chacha20poly1305.h>
#include <sodium/randombytes.h>

#define MAX_PKT_LEN (1024 * 1024)

/* FIXME-OLD#1:
   `length` is a 4-byte little-endian field indicating the size of the unencrypted body.
 */

struct crypto_pkt {
	le32 length;
	u8 auth_tag[crypto_aead_chacha20poly1305_ABYTES];

	/* ... contents... */
	u8 data[];
};

/* Temporary structure for negotiation */
struct key_negotiate {
	struct lightningd_state *dstate;

	/* Our session secret key. */
	u8 seckey[32];

	/* Our pubkey, their pubkey. */
	le32 keylen;
	u8 our_sessionpubkey[33], their_sessionpubkey[33];

	/* After DH key exchange, we create io_data to check auth. */
	struct io_data *iod;

	/* Logging structure we're using. */
	struct log *log;

	/* Did we expect a particular ID? */
	const struct pubkey *expected_id;

	/* Callback once it's all done. */
	struct io_plan *(*cb)(struct io_conn *conn,
			      struct lightningd_state *dstate,
			      struct io_data *iod,
			      struct log *log,
			      const struct pubkey *id,
			      void *arg);
	void *arg;
};

struct enckey {
	struct sha256 k;
};


/* FIXME-OLD #1:
 * * sending-key: SHA256(shared-secret || sending-node-session-pubkey)
 * * receiving-key: SHA256(shared-secret || receiving-node-session-pubkey)
 */
static struct enckey enckey_from_secret(const unsigned char secret[32],
					const unsigned char serial_pubkey[33])
{
	struct sha256_ctx ctx;
	struct enckey enckey;

	sha256_init(&ctx);
	sha256_update(&ctx, memcheck(secret, 32), 32);
	sha256_update(&ctx, memcheck(serial_pubkey, 33), 33);
	sha256_done(&ctx, &enckey.k);

	return enckey;
}

struct dir_state {
	u64 nonce;
	struct enckey enckey;

	/* Current packet (encrypted). */
	struct crypto_pkt *cpkt;
	size_t pkt_len;
};

static void setup_crypto(struct dir_state *dir,
			 u8 shared_secret[32], u8 serial_pubkey[33])
{
	/* FIXME-OLD #1: Nonces...MUST begin at 0 */
	dir->nonce = 0;

	dir->enckey = enckey_from_secret(shared_secret, serial_pubkey);

	dir->cpkt = NULL;
}

struct io_data {
	/* Stuff we need to keep around to talk to peer. */
	struct dir_state in, out;

	/* Callback once packet decrypted. */
	struct io_plan *(*cb)(struct io_conn *, struct peer *);

	/* Once peer is assigned, this is set. */
	struct peer *peer;

	/* Length we're currently reading. */
	struct crypto_pkt hdr_in;
};

static void *proto_tal_alloc(void *allocator_data, size_t size)
{
	return tal_arr(allocator_data, char, size);
}

static void proto_tal_free(void *allocator_data, void *pointer)
{
	tal_free(pointer);
}

static void le64_nonce(unsigned char *npub, u64 nonce)
{
	/* FIXME-OLD #1: Nonces are 64-bit little-endian numbers */
	le64 le_nonce = cpu_to_le64(nonce);
	memcpy(npub, &le_nonce, sizeof(le_nonce));
	BUILD_ASSERT(crypto_aead_chacha20poly1305_NPUBBYTES == sizeof(le_nonce));
}

/* Encrypts data..data + len - 1 inclusive into data..data + len - 1 and
 * then writes the authentication tag at data+len.
 *
 * This increments nonce every time.
 */
static void encrypt_in_place(void *data, size_t len,
			     u64 *nonce, const struct enckey *enckey)
{
	int ret;
	unsigned long long clen;
	unsigned char npub[crypto_aead_chacha20poly1305_NPUBBYTES];

	le64_nonce(npub, *nonce);
	ret = crypto_aead_chacha20poly1305_encrypt(data, &clen,
						   memcheck(data, len), len,
						   NULL, 0, NULL,
						   npub, enckey->k.u.u8);
	assert(ret == 0);
	assert(clen == len + crypto_aead_chacha20poly1305_ABYTES);
	(*nonce)++;
}

/* Checks authentication tag at data+len, then
 * decrypts data..data + len - 1 inclusive into data..data + len - 1.
 *
 * This increments nonce every time.
 */
static bool decrypt_in_place(void *data, size_t len,
			     u64 *nonce, const struct enckey *enckey)
{
	int ret;
	unsigned long long mlen;
	unsigned char npub[crypto_aead_chacha20poly1305_NPUBBYTES];

	le64_nonce(npub, *nonce);
	mlen = len + crypto_aead_chacha20poly1305_ABYTES;

	ret = crypto_aead_chacha20poly1305_decrypt(data, &mlen, NULL,
						   memcheck(data, mlen), mlen,
						   NULL, 0,
						   npub, enckey->k.u.u8);
	if (ret == 0) {
		assert(mlen == len);
		(*nonce)++;
		return true;
	}
	return false;
}

static Pkt *decrypt_body(const tal_t *ctx, struct io_data *iod, struct log *log)
{
	struct ProtobufCAllocator prototal;
	Pkt *ret;
	size_t data_len = le32_to_cpu(iod->hdr_in.length);

	if (!decrypt_in_place(iod->in.cpkt->data, data_len,
			      &iod->in.nonce, &iod->in.enckey)) {
		/* Free encrypted packet. */
		iod->in.cpkt = tal_free(iod->in.cpkt);
		log_unusual(log, "Body decryption failed");
		return NULL;
	}

	/* De-protobuf it. */
	prototal.alloc = proto_tal_alloc;
	prototal.free = proto_tal_free;
	prototal.allocator_data = tal(ctx, char);

	ret = pkt__unpack(&prototal, data_len, iod->in.cpkt->data);
	if (!ret) {
		log_unusual(log, "Packet failed to unpack!");
		tal_free(prototal.allocator_data);
	} else {
		/* Make sure packet owns contents */
		tal_steal(ctx, ret);
		tal_steal(ret, prototal.allocator_data);

		log_debug(log, "Received packet LEN=%zu, type=%s",
			  data_len,
			  ret->pkt_case == PKT__PKT_AUTH ? "PKT_AUTH"
			  : pkt_name(ret->pkt_case));
	}

	/* Free encrypted packet. */
	iod->in.cpkt = tal_free(iod->in.cpkt);

	return ret;
}

static struct crypto_pkt *encrypt_pkt(struct io_data *iod, const Pkt *pkt,
				      size_t *totlen)
{
	struct crypto_pkt *cpkt;
	size_t len;

	len = pkt__get_packed_size(pkt);
	*totlen = sizeof(*cpkt) + len + crypto_aead_chacha20poly1305_ABYTES;

	cpkt = (struct crypto_pkt *)tal_arr(iod, char, *totlen);
	cpkt->length = cpu_to_le32(len);

	/* Encrypt header. */
	encrypt_in_place(cpkt, sizeof(cpkt->length),
			 &iod->out.nonce, &iod->out.enckey);

	/* Encrypt body. */
	pkt__pack(pkt, cpkt->data);
	encrypt_in_place(cpkt->data, len, &iod->out.nonce, &iod->out.enckey);

	return cpkt;
}

static struct io_plan *recv_body(struct io_conn *conn, struct peer *peer)
{
	struct io_data *iod = peer->io_data;

	assert(!peer->inpkt);

	/* We have full packet. */
	peer->inpkt = decrypt_body(iod, iod, peer->log);
	if (!peer->inpkt)
		return io_close(conn);

	return iod->cb(conn, peer);
}

static bool decrypt_header(struct log *log, struct io_data *iod,
			   size_t *body_len)
{
	/* We have length: Check it. */
	if (!decrypt_in_place(&iod->hdr_in.length, sizeof(iod->hdr_in.length),
			      &iod->in.nonce, &iod->in.enckey)) {
		log_unusual(log, "Header decryption failed");
		return false;
	}
	log_debug(log, "Decrypted header len %u",
		  le32_to_cpu(iod->hdr_in.length));

	/* FIXME-OLD #1: `length` MUST NOT exceed 1MB (1048576 bytes). */
	if (le32_to_cpu(iod->hdr_in.length) > MAX_PKT_LEN) {
		log_unusual(log,
			    "Packet overlength: %"PRIu64,
			    le64_to_cpu(iod->hdr_in.length));
		return false;
	}

	/* Allocate room for body, copy header. */
	*body_len = le32_to_cpu(iod->hdr_in.length)
		+ crypto_aead_chacha20poly1305_ABYTES;

	iod->in.cpkt = (struct crypto_pkt *)
		tal_arr(iod, char, sizeof(iod->hdr_in) + *body_len);
	*iod->in.cpkt = iod->hdr_in;
	return true;
}

static struct io_plan *recv_header(struct io_conn *conn, struct peer *peer)
{
	struct io_data *iod = peer->io_data;
	size_t body_len;

	if (!decrypt_header(peer->log, iod, &body_len))
		return io_close(conn);

	return io_read(conn, iod->in.cpkt->data, body_len, recv_body, peer);
}

struct io_plan *peer_read_packet(struct io_conn *conn,
				 struct peer *peer,
				 struct io_plan *(*cb)(struct io_conn *,
						       struct peer *))
{
	struct io_data *iod = peer->io_data;

	iod->cb = cb;
	return io_read(conn, &iod->hdr_in, sizeof(iod->hdr_in),
		       recv_header, peer);
}

/* Caller must free data! */
struct io_plan *peer_write_packet(struct io_conn *conn,
				  struct peer *peer,
				  const Pkt *pkt,
				  struct io_plan *(*next)(struct io_conn *,
							  struct peer *))
{
	struct io_data *iod = peer->io_data;
	size_t totlen;

	/* We free previous packet here, rather than doing indirection
	 * via io_write */
	tal_free(iod->out.cpkt);

	iod->out.cpkt = encrypt_pkt(iod, pkt, &totlen);
	/* Free unencrypted packet. */
	tal_free(pkt);

	return io_write(conn, iod->out.cpkt, totlen, next, peer);
}

static void *pkt_unwrap(Pkt *inpkt, struct log *log, Pkt__PktCase which)
{
	size_t i;
	const ProtobufCMessage *base;

	if (inpkt->pkt_case != which) {
		log_unusual(log, "Expected %u, got %u",
			    which, inpkt->pkt_case);
		return NULL;
	}

	/* It's a union, and each member starts with base.  Pick one */
	base = &inpkt->error->base;

	/* Look for unknown fields.  Remember, "It's OK to be odd!" */
	for (i = 0; i < base->n_unknown_fields; i++) {
		log_debug(log, "Unknown field in %u: %u",
			  which, base->unknown_fields[i].tag);
			/* Odd is OK */
			if (base->unknown_fields[i].tag & 1)
				continue;
			log_unusual(log, "Unknown field %u in %u",
				    base->unknown_fields[i].tag, which);
			return NULL;
	}
	return inpkt->error;
}

static bool check_proof(struct key_negotiate *neg, struct log *log,
			Pkt *inpkt,
			const struct pubkey *expected_id,
			struct pubkey *id)
{
	struct sha256_double sha;
	secp256k1_ecdsa_signature sig;
	Authenticate *auth;

	auth = pkt_unwrap(inpkt, log, PKT__PKT_AUTH);
	if (!auth)
		return false;

	/* FIXME-OLD #1:
	 *
	 * The receiving node MUST check that:
	 *
	 * 1. `node_id` is the expected value for the sending node.
	 */
	if (!proto_to_pubkey(auth->node_id, id)) {
		log_unusual(log, "Invalid auth id");
		return false;
	}

	if (expected_id && !structeq(id, expected_id)) {
		log_unusual(log, "Incorrect auth id");
		return false;
	}

	/* FIXME-OLD #1:
	 *
	 * 2. `session_sig` is a valid secp256k1 ECDSA signature encoded as
	 *     a 32-byte big endian R value, followed by a 32-byte big
	 *     endian S value.
	 */
	if (!proto_to_signature(auth->session_sig, &sig)) {
		log_unusual(log, "Invalid auth signature");
		return false;
	}


	/* FIXME-OLD #1:
	 *
	 * 3. `session_sig` is the signature of the SHA256 of SHA256 of the
	 *     its own sessionpubkey, using the secret key corresponding to
	 *     the sender's `node_id`.
	 */
	sha256_double(&sha, neg->our_sessionpubkey,
		      sizeof(neg->our_sessionpubkey));

	if (!check_signed_hash(&sha, &sig, id)) {
		log_unusual(log, "Bad auth signature");
		return false;
	}

	return true;
}

static struct io_plan *recv_body_negotiate(struct io_conn *conn,
					   struct key_negotiate *neg)
{
	struct io_data *iod = neg->iod;
	struct io_plan *plan;
	Pkt *pkt;
	struct pubkey id;

	/* We have full packet. */
	pkt = decrypt_body(neg, iod, neg->log);
	if (!pkt)
		return io_close(conn);

	if (!check_proof(neg, neg->log, pkt, neg->expected_id, &id))
		return io_close(conn);

	/* Steal so that the callback may not accidentally free it for us */
	tal_steal(NULL, neg);

	plan = neg->cb(conn, neg->dstate, neg->iod, neg->log, &id, neg->arg);
	tal_free(neg);
	return plan;
}

static struct io_plan *recv_header_negotiate(struct io_conn *conn,
					     struct key_negotiate *neg)
{
	size_t body_len;
	struct io_data *iod = neg->iod;

	if (!decrypt_header(neg->log, iod, &body_len))
		return io_close(conn);

	return io_read(conn, iod->in.cpkt->data, body_len, recv_body_negotiate,
		       neg);
}

static struct io_plan *receive_proof(struct io_conn *conn,
				     struct key_negotiate *neg)
{
	return io_read(conn, &neg->iod->hdr_in, sizeof(neg->iod->hdr_in),
		       recv_header_negotiate, neg);
}

/* Steals w onto the returned Pkt */
static Pkt *pkt_wrap(const tal_t *ctx, void *w, Pkt__PktCase pkt_case)
{
	Pkt *pkt = tal(ctx, Pkt);
	pkt__init(pkt);
	pkt->pkt_case = pkt_case;
	/* Union, so any will do */
	pkt->error = tal_steal(pkt, w);
	return pkt;
}

static Pkt *authenticate_pkt(const tal_t *ctx,
			     const struct pubkey *node_id,
			     const secp256k1_ecdsa_signature *sig)
{
	Authenticate *auth = tal(ctx, Authenticate);
	authenticate__init(auth);
	auth->node_id = pubkey_to_proto(auth, node_id);
	auth->session_sig = signature_to_proto(auth, sig);
	return pkt_wrap(ctx, auth, PKT__PKT_AUTH);
}

static struct io_plan *keys_exchanged(struct io_conn *conn,
				      struct key_negotiate *neg)
{
	u8 shared_secret[32];
	struct pubkey sessionkey;
	secp256k1_ecdsa_signature sig;
	Pkt *auth;
	size_t totlen;

	if (!pubkey_from_der(neg->their_sessionpubkey,
			     sizeof(neg->their_sessionpubkey),
			     &sessionkey)) {
		log_unusual_blob(neg->log,  "Bad sessionkey %s",
				 neg->their_sessionpubkey,
				 sizeof(neg->their_sessionpubkey));
		return io_close(conn);
	}

	/* Derive shared secret. */
	if (!secp256k1_ecdh(secp256k1_ctx, shared_secret,
			    &sessionkey.pubkey, neg->seckey)) {
		log_unusual(neg->log, "Bad ECDH");
		return io_close(conn);
	}

	/* Each side combines with their OWN session key to SENDING crypto. */
	neg->iod = tal(neg, struct io_data);
	setup_crypto(&neg->iod->in, shared_secret, neg->their_sessionpubkey);
	setup_crypto(&neg->iod->out, shared_secret, neg->our_sessionpubkey);

	/* FIXME-OLD #1:
	 *
	 * `session_sig` is the signature of the SHA256 of SHA256 of the its
	 * own sessionpubkey, using the secret key corresponding to the
	 * sender's `node_id`.
	 */
	privkey_sign(neg->dstate, neg->their_sessionpubkey,
		     sizeof(neg->their_sessionpubkey), &sig);

	auth = authenticate_pkt(neg, &neg->dstate->id, &sig);

	neg->iod->out.cpkt = encrypt_pkt(neg->iod, auth, &totlen);
	return io_write(conn, neg->iod->out.cpkt, totlen, receive_proof, neg);
}

/* Read and ignore any extra bytes... */
static struct io_plan *discard_extra(struct io_conn *conn,
				     struct key_negotiate *neg)
{
	size_t len = le32_to_cpu(neg->keylen);

	/* FIXME-OLD#1: Additional fields MAY be added, and MUST be
	 * included in the `length` field.  These MUST be ignored by
	 * implementations which do not understand them. */
	if (len > sizeof(neg->their_sessionpubkey)) {
		char *discard;

		len -= sizeof(neg->their_sessionpubkey);
		discard = tal_arr(neg, char, len);
		log_unusual(neg->log,
			    "Ignoring %zu extra handshake bytes",
			    len);
		return io_read(conn, discard, len, keys_exchanged, neg);
	}

	return keys_exchanged(conn, neg);
}

static struct io_plan *session_key_receive(struct io_conn *conn,
					   struct key_negotiate *neg)
{
	/* FIXME-OLD#1: The `length` field is the length after the field
	   itself, and MUST be 33 or greater. */
	if (le32_to_cpu(neg->keylen) < sizeof(neg->their_sessionpubkey)) {
		log_unusual(neg->log, "short session key length %u",
			    le32_to_cpu(neg->keylen));
		return io_close(conn);
	}

	/* FIXME-OLD#1: `length` MUST NOT exceed 1MB (1048576 bytes). */
	if (le32_to_cpu(neg->keylen) > 1048576) {
		log_unusual(neg->log,
			    "Oversize session key length %u",
			    le32_to_cpu(neg->keylen));
		return io_close(conn);
	}

	log_debug(neg->log, "Session key length %u", le32_to_cpu(neg->keylen));

	/* Now read their key. */
	return io_read(conn, neg->their_sessionpubkey,
		       sizeof(neg->their_sessionpubkey), discard_extra, neg);
}

static struct io_plan *session_key_len_receive(struct io_conn *conn,
					       struct key_negotiate *neg)
{
	/* Read the amount of data they will send.. */
	return io_read(conn, &neg->keylen, sizeof(neg->keylen),
		       session_key_receive, neg);
}

static void gen_sessionkey(u8 seckey[32],
			   secp256k1_pubkey *pubkey)
{
	do {
		randombytes_buf(seckey, 32);
	} while (!secp256k1_ec_pubkey_create(secp256k1_ctx, pubkey, seckey));
}

static struct io_plan *write_sessionkey(struct io_conn *conn,
					struct key_negotiate *neg)
{
	return io_write(conn, neg->our_sessionpubkey,
			sizeof(neg->our_sessionpubkey),
			session_key_len_receive, neg);
}

struct io_plan *peer_crypto_setup_(struct io_conn *conn,
				   struct lightningd_state *dstate,
				   const struct pubkey *id,
				   struct log *log,
				   struct io_plan *(*cb)(struct io_conn *conn,
						 struct lightningd_state *dstate,
						 struct io_data *iod,
						 struct log *log,
						 const struct pubkey *id,
						 void *arg),
				   void *arg)
{
	size_t outputlen;
	secp256k1_pubkey sessionkey;
	struct key_negotiate *neg;

	/* FIXME-OLD #1:
	 *
	 * The 4-byte length for each message is encrypted separately
	 * (resulting in a 20 byte header when the authentication tag
	 * is appended) */
	BUILD_ASSERT(sizeof(struct crypto_pkt) == 20);

	/* We store negotiation state here. */
	neg = tal(conn, struct key_negotiate);
	neg->cb = cb;
	neg->arg = arg;
	neg->dstate = dstate;
	neg->expected_id = id;
	neg->log = log;

	gen_sessionkey(neg->seckey, &sessionkey);

	outputlen = sizeof(neg->our_sessionpubkey);
	secp256k1_ec_pubkey_serialize(secp256k1_ctx,
				      neg->our_sessionpubkey, &outputlen,
				      &sessionkey,
				      SECP256K1_EC_COMPRESSED);
	assert(outputlen == sizeof(neg->our_sessionpubkey));
	neg->keylen = cpu_to_le32(sizeof(neg->our_sessionpubkey));
	return io_write(conn, &neg->keylen, sizeof(neg->keylen),
			write_sessionkey, neg);
}
