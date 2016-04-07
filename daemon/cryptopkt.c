#include "bitcoin/shadouble.h"
#include "bitcoin/signature.h"
#include "cryptopkt.h"
#include "lightning.pb-c.h"
#include "lightningd.h"
#include "log.h"
#include "names.h"
#include "peer.h"
#include "protobuf_convert.h"
#include "secrets.h"
#include <ccan/build_assert/build_assert.h>
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/endian/endian.h>
#include <ccan/mem/mem.h>
#include <ccan/short_types/short_types.h>
#include <inttypes.h>
#include <sodium/crypto_aead_chacha20poly1305.h>
#include <sodium/randombytes.h>
#include <secp256k1.h>
#include <secp256k1_ecdh.h>

#define MAX_PKT_LEN (1024 * 1024)

/* BOLT#1:
   The header consists of the following fields in order:

   * `acknowledge`: an 8-byte little-endian field indicating the number of non-`authenticate` messages received and processed so far.
   * `length`: a 4-byte little-endian field indicating the size of the unencrypted body.
 */

/* Do NOT take sizeof() this, since there's extra padding at the end! */
struct crypto_pkt {
	le64 acknowledge;
	le32 length;
	u8 auth_tag[crypto_aead_chacha20poly1305_ABYTES];

	/* ... contents... */
	u8 data[];
};

/* Use this instead of sizeof(struct crypto_pkt) */
#define CRYPTO_HDR_LEN_NOTAG (8 + 4)
#define CRYPTO_HDR_LEN (CRYPTO_HDR_LEN_NOTAG + crypto_aead_chacha20poly1305_ABYTES)

/* Temporary structure for negotiation (peer->io_data->neg) */
struct key_negotiate {
	/* Our session secret key. */
	u8 seckey[32];

	/* Our pubkey, their pubkey. */
	le32 keylen;
	u8 our_sessionpubkey[33], their_sessionpubkey[33];

	/* Callback once it's all done. */
	struct io_plan *(*cb)(struct io_conn *, struct peer *);
};

struct enckey {
	struct sha256 k;
};


/* BOLT #1:
 * sending-key: SHA256(shared-secret || sending-node-id)
 * receiving-key: SHA256(shared-secret || receiving-node-id)
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

	/* Non-`authenticate` packets sent/seen */
	u64 count;
	
	/* Current packet (encrypted). */
	struct crypto_pkt *cpkt;
	size_t pkt_len;
};

static void setup_crypto(struct dir_state *dir,
			 u8 shared_secret[32], u8 serial_pubkey[33])
{
	/* BOLT #1: Nonces...MUST begin at 0 */
	dir->nonce = 0;

	dir->enckey = enckey_from_secret(shared_secret, serial_pubkey);

	dir->count = 0;
	dir->cpkt = NULL;
}

struct ack {
	struct list_node list;
	u64 pktnum;
	void (*ack_cb)(struct peer *peer, void *);
	void *ack_arg;
};

struct io_data {
	/* Stuff we need to keep around to talk to peer. */
	struct dir_state in, out;

	/* Header we're currently reading. */
	struct crypto_pkt hdr_in;

	/* Callback once packet decrypted. */
	struct io_plan *(*cb)(struct io_conn *, struct peer *);
	
	/* For negotiation phase. */
	struct key_negotiate *neg;

	/* Tracking what needs acks. */
	struct list_head acks;
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
	/* BOLT #1: Nonces are 64-bit little-endian numbers */
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

static Pkt *decrypt_pkt(struct peer *peer, struct crypto_pkt *cpkt,
			size_t data_len)
{
	struct io_data *iod = peer->io_data;
	struct ProtobufCAllocator prototal;
	Pkt *ret;

	if (!decrypt_in_place(cpkt->data, data_len,
			      &iod->in.nonce, &iod->in.enckey)) {
		log_unusual(peer->log, "Body decryption failed");
		return NULL;
	}

	/* De-protobuf it. */
	prototal.alloc = proto_tal_alloc;
	prototal.free = proto_tal_free;
	prototal.allocator_data = tal(iod, char);

	ret = pkt__unpack(&prototal, data_len, cpkt->data);
	if (!ret) {
		log_unusual(peer->log, "Packet failed to unpack!");
		tal_free(prototal.allocator_data);
	} else
		/* Make sure packet owns contents */
		tal_steal(ret, prototal.allocator_data);
	return ret;
}

static struct crypto_pkt *encrypt_pkt(struct peer *peer, const Pkt *pkt, u64 ack,
				      size_t *totlen)
{
	struct crypto_pkt *cpkt;
	size_t len;
	struct io_data *iod = peer->io_data;

	len = pkt__get_packed_size(pkt);
	*totlen = CRYPTO_HDR_LEN + len + crypto_aead_chacha20poly1305_ABYTES;

	cpkt = (struct crypto_pkt *)tal_arr(peer, char, *totlen);
	cpkt->acknowledge = cpu_to_le64(ack);
	cpkt->length = cpu_to_le32(len);

	/* Encrypt header. */
	encrypt_in_place(cpkt, CRYPTO_HDR_LEN_NOTAG,
			 &iod->out.nonce, &iod->out.enckey);

	/* Encrypt body. */
	pkt__pack(pkt, cpkt->data);
	encrypt_in_place(cpkt->data, len, &iod->out.nonce, &iod->out.enckey);

	return cpkt;
}

static struct io_plan *decrypt_body(struct io_conn *conn, struct peer *peer)
{
	struct io_data *iod = peer->io_data;
	struct ack *ack;

	/* We have full packet. */
	peer->inpkt = decrypt_pkt(peer, iod->in.cpkt,
				  le32_to_cpu(iod->hdr_in.length));
	if (!peer->inpkt)
		return io_close(conn);

	/* Increment count if it wasn't an authenticate packet */
	if (peer->inpkt->pkt_case != PKT__PKT_AUTH)
		iod->in.count++;

	log_debug(peer->log, "Received packet ACK=%"PRIu64" LEN=%u, type=%s",
		  le64_to_cpu(iod->hdr_in.acknowledge),
		  le32_to_cpu(iod->hdr_in.length),
		  peer->inpkt->pkt_case == PKT__PKT_AUTH ? "PKT_AUTH"
		  : input_name(peer->inpkt->pkt_case));

	/* Do callbacks for any packets it acknowledged receiving. */
	while ((ack = list_top(&iod->acks, struct ack, list)) != NULL) {
		if (le64_to_cpu(iod->hdr_in.acknowledge) < ack->pktnum)
			break;
		ack->ack_cb(peer, ack->ack_arg);
		list_del_from(&iod->acks, &ack->list);
		tal_free(ack);
	}

	return iod->cb(conn, peer);
}

static struct io_plan *decrypt_header(struct io_conn *conn, struct peer *peer)
{
	struct io_data *iod = peer->io_data;
	size_t body_len;

	/* We have header: Check it. */
	if (!decrypt_in_place(&iod->hdr_in, CRYPTO_HDR_LEN_NOTAG,
			      &iod->in.nonce, &iod->in.enckey)) {
		log_unusual(peer->log, "Header decryption failed");
		return io_close(conn);
	}
	log_debug(peer->log, "Decrypted header len %u",
		  le32_to_cpu(iod->hdr_in.length));

	/* BOLT #1: `length` MUST NOT exceed 1MB (1048576 bytes). */
	if (le32_to_cpu(iod->hdr_in.length) > MAX_PKT_LEN) {
		log_unusual(peer->log,
			    "Packet overlength: %"PRIu64,
			    le64_to_cpu(iod->hdr_in.length));
		return io_close(conn);
	}

	/* Allocate room for body, copy header. */
	body_len = le32_to_cpu(iod->hdr_in.length)
		+ crypto_aead_chacha20poly1305_ABYTES;

	iod->in.cpkt = (struct crypto_pkt *)tal_arr(peer, char,
						    CRYPTO_HDR_LEN + body_len);
	memcpy(iod->in.cpkt, &iod->hdr_in, CRYPTO_HDR_LEN);

	return io_read(conn, iod->in.cpkt->data, body_len, decrypt_body, peer);
}

struct io_plan *peer_read_packet(struct io_conn *conn,
				 struct peer *peer,
				 struct io_plan *(*cb)(struct io_conn *,
						       struct peer *))
{
	struct io_data *iod = peer->io_data;

	iod->cb = cb;
	return io_read(conn, &iod->hdr_in, CRYPTO_HDR_LEN,
		       decrypt_header, peer);
}

/* Caller must free data! */
struct io_plan *peer_write_packet_(struct io_conn *conn,
				   struct peer *peer,
				   const Pkt *pkt,
				   void (*ack_cb)(struct peer *peer, void *),
				   void *ack_arg,
				   struct io_plan *(*next)(struct io_conn *,
							   struct peer *))
{
	struct io_data *iod = peer->io_data;
	size_t totlen;

	/* We free previous packet here, rather than doing indirection
	 * via io_write */
	tal_free(iod->out.cpkt);

	iod->out.cpkt = encrypt_pkt(peer, pkt, peer->io_data->in.count, &totlen);

	/* Set up ack callback if any. */
	if (ack_cb) {
		struct ack *ack = tal(peer, struct ack);
		ack->pktnum = peer->io_data->out.count;
		ack->ack_cb = ack_cb;
		ack->ack_arg = ack_arg;
		list_add_tail(&iod->acks, &ack->list);
	}

	/* We don't add to count for authenticate case. */
	if (pkt->pkt_case != PKT__PKT_AUTH)
		peer->io_data->out.count++;

	return io_write(conn, iod->out.cpkt, totlen, next, peer);
}

static void *pkt_unwrap(struct peer *peer, Pkt__PktCase which)
{
	size_t i;
	const ProtobufCMessage *base;

	if (peer->inpkt->pkt_case != which) {
		log_unusual(peer->log, "Expected %u, got %u",
			    which, peer->inpkt->pkt_case);
		return NULL;
	}

	/* It's a union, and each member starts with base.  Pick one */
	base = &peer->inpkt->error->base;

	/* Look for unknown fields.  Remember, "It's OK to be odd!" */
	for (i = 0; i < base->n_unknown_fields; i++) {
		log_debug(peer->log, "Unknown field in %u: %u",
			  which, base->unknown_fields[i].tag);
			/* Odd is OK */
			if (base->unknown_fields[i].tag & 1)
				continue;
			log_unusual(peer->log, "Unknown field %u in %u",
				    base->unknown_fields[i].tag, which);
			return NULL;
	}
	return peer->inpkt->error;
}

static struct io_plan *check_proof(struct io_conn *conn, struct peer *peer)
{
	struct key_negotiate *neg = peer->io_data->neg;
	struct sha256_double sha;
	struct signature sig;
	struct io_plan *(*cb)(struct io_conn *, struct peer *);
	Authenticate *auth;

	auth = pkt_unwrap(peer, PKT__PKT_AUTH);
	if (!auth)
		return io_close(conn);

	if (!proto_to_signature(auth->session_sig, &sig)) {
		log_unusual(peer->log, "Invalid auth signature");
		return io_close(conn);
	}

	if (!proto_to_pubkey(peer->dstate->secpctx, auth->node_id, &peer->id)) {
		log_unusual(peer->log, "Invalid auth id");
		return io_close(conn);
	}

	/* Signature covers *our* session key. */
	sha256_double(&sha,
		      neg->our_sessionpubkey, sizeof(neg->our_sessionpubkey));

	if (!check_signed_hash(peer->dstate->secpctx, &sha, &sig, &peer->id)) {
		log_unusual(peer->log, "Bad auth signature");
		return io_close(conn);
	}

	tal_free(auth);

	/* Auth messages don't add to count. */
	assert(peer->io_data->in.count == 0);

	/* BOLT #1:
	 * The receiver MUST NOT examine the `acknowledge` value until
	 * after the authentication fields have been successfully
	 * validated.  The `acknowledge` field MUST BE set to the
	 * number of non-authenticate messages received and processed.
	 */
	/* FIXME: Handle reconnects. */
	if (le64_to_cpu(peer->io_data->hdr_in.acknowledge) != 0) {
		log_unusual(peer->log, "FIXME: non-zero acknowledge %"PRIu64,
			    le64_to_cpu(peer->io_data->hdr_in.acknowledge));
		return io_close(conn);
	}

	/* All complete, return to caller. */
	cb = neg->cb;
	peer->io_data->neg = tal_free(neg);
	return cb(conn, peer);
}

static struct io_plan *receive_proof(struct io_conn *conn, struct peer *peer)
{
	/* The sent auth message doesn't add to count. */
	assert(peer->io_data->out.count == 0);

	return peer_read_packet(conn, peer, check_proof);
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
			     const struct signature *sig)
{
	Authenticate *auth = tal(ctx, Authenticate);
	authenticate__init(auth);
	auth->node_id = pubkey_to_proto(auth, node_id);
	auth->session_sig = signature_to_proto(auth, sig);
	return pkt_wrap(ctx, auth, PKT__PKT_AUTH);
}

static struct io_plan *keys_exchanged(struct io_conn *conn, struct peer *peer)
{
	u8 shared_secret[32];
	struct pubkey sessionkey;
	struct signature sig;
	struct key_negotiate *neg = peer->io_data->neg;
	Pkt *auth;

	if (!pubkey_from_der(peer->dstate->secpctx,
			     neg->their_sessionpubkey,
			     sizeof(neg->their_sessionpubkey),
			     &sessionkey)) {
		/* FIXME: Dump key in this case. */
		log_unusual(peer->log, "Bad sessionkey");
		return io_close(conn);
	}

	/* Derive shared secret. */
	if (!secp256k1_ecdh(peer->dstate->secpctx, shared_secret,
			    &sessionkey.pubkey, neg->seckey)) {
		log_unusual(peer->log, "Bad ECDH");
		return io_close(conn);
	}

	/* Each side combines with their OWN session key to SENDING crypto. */
	setup_crypto(&peer->io_data->in, shared_secret,
		     neg->their_sessionpubkey);
	setup_crypto(&peer->io_data->out, shared_secret,
		     neg->our_sessionpubkey);

	/* Now sign their session key to prove who we are. */
	privkey_sign(peer, neg->their_sessionpubkey,
		     sizeof(neg->their_sessionpubkey), &sig);

	/* FIXME: Free auth afterwards. */
	auth = authenticate_pkt(peer, &peer->dstate->id, &sig);
	return peer_write_packet(conn, peer, auth, NULL, NULL, receive_proof);
}

/* Read and ignore any extra bytes... */
static struct io_plan *discard_extra(struct io_conn *conn, struct peer *peer)
{
	struct key_negotiate *neg = peer->io_data->neg;
	size_t len = le32_to_cpu(neg->keylen);

	/* BOLT#1: Additional fields MAY be added, and MUST be
	 * included in the `length` field.  These MUST be ignored by
	 * implementations which do not understand them. */
	if (len > sizeof(neg->their_sessionpubkey)) {
		char *discard;

		len -= sizeof(neg->their_sessionpubkey);
		discard = tal_arr(neg, char, len);
		return io_read(conn, discard, len, keys_exchanged, peer);
	}

	return keys_exchanged(conn, peer);
}

static struct io_plan *session_key_receive(struct io_conn *conn,
					   struct peer *peer)
{
	struct key_negotiate *neg = peer->io_data->neg;

	/* BOLT#1: The `length` field is the length after the field
	   itself, and MUST be 33 or greater. */
	if (le32_to_cpu(neg->keylen) < sizeof(neg->their_sessionpubkey)) {
		log_unusual(peer->log, "short session key length %u",
			    le32_to_cpu(neg->keylen));
		return io_close(conn);
	}

	/* BOLT#1: `length` MUST NOT exceed 1MB (1048576 bytes). */
	if (le32_to_cpu(neg->keylen) > 1048576) {
		log_unusual(peer->log, "Oversize session key length %u",
			    le32_to_cpu(neg->keylen));
		return io_close(conn);
	}

	log_debug(peer->log, "Session key length %u", le32_to_cpu(neg->keylen));

	/* Now read their key. */
	return io_read(conn, neg->their_sessionpubkey,
		       sizeof(neg->their_sessionpubkey), discard_extra, peer);
}

static struct io_plan *session_key_len_receive(struct io_conn *conn,
					       struct peer *peer)
{
	struct key_negotiate *neg = peer->io_data->neg;
	/* Read the amount of data they will send.. */
	return io_read(conn, &neg->keylen, sizeof(neg->keylen),
		       session_key_receive, peer);
}

static void gen_sessionkey(secp256k1_context *ctx,
			   u8 seckey[32],
			   secp256k1_pubkey *pubkey)
{
	do {
		randombytes_buf(seckey, 32);
	} while (!secp256k1_ec_pubkey_create(ctx, pubkey, seckey));
}

static struct io_plan *write_sessionkey(struct io_conn *conn, struct peer *peer)
{
	struct key_negotiate *neg = peer->io_data->neg;

	return io_write(conn, neg->our_sessionpubkey,
			sizeof(neg->our_sessionpubkey),
			session_key_len_receive, peer);
}

struct io_plan *peer_crypto_setup(struct io_conn *conn, struct peer *peer,
				  struct io_plan *(*cb)(struct io_conn *,
							struct peer *))
{
	size_t outputlen;
	secp256k1_pubkey sessionkey;
	struct key_negotiate *neg;

	BUILD_ASSERT(CRYPTO_HDR_LEN == offsetof(struct crypto_pkt, data));

	peer->io_data = tal(peer, struct io_data);
	list_head_init(&peer->io_data->acks);

	/* We store negotiation state here. */
	neg = peer->io_data->neg = tal(peer->io_data, struct key_negotiate);
	neg->cb = cb;

	gen_sessionkey(peer->dstate->secpctx, neg->seckey, &sessionkey);

	secp256k1_ec_pubkey_serialize(peer->dstate->secpctx,
				      neg->our_sessionpubkey, &outputlen,
				      &sessionkey,
				      SECP256K1_EC_COMPRESSED);
	assert(outputlen == sizeof(neg->our_sessionpubkey));
	neg->keylen = cpu_to_le32(sizeof(neg->our_sessionpubkey));
	return io_write(conn, &neg->keylen, sizeof(neg->keylen),
			write_sessionkey, peer);
}
