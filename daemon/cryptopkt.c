#include "bitcoin/shadouble.h"
#include "bitcoin/signature.h"
#include "cryptopkt.h"
#include "lightning.pb-c.h"
#include "lightningd.h"
#include "log.h"
#include "peer.h"
#include "protobuf_convert.h"
#include "secrets.h"
#include <ccan/build_assert/build_assert.h>
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/endian/endian.h>
#include <ccan/io/io_plan.h>
#include <ccan/mem/mem.h>
#include <ccan/short_types/short_types.h>
#include <inttypes.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <secp256k1.h>
#include <secp256k1_ecdh.h>

#define MAX_PKT_LEN (1024 * 1024)

#define ROUNDUP(x,a) (((x) + ((a)-1)) & ~((a)-1))

struct crypto_pkt {
	/* HMAC */
	struct sha256 hmac;
	/* Total length transmitted. */
	le64 totlen;
	/* ... contents... */
	u8 data[];
};

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

#define ENCKEY_SEED 0
#define HMACKEY_SEED 1
#define IV_SEED 2

struct enckey {
	struct sha256 k;
};

struct hmackey {
	struct sha256 k;
};

struct iv {
	unsigned char iv[AES_BLOCK_SIZE];
};

static void sha_with_seed(const unsigned char secret[32],
			  const unsigned char serial_pubkey[33],
			  unsigned char seed,
			  struct sha256 *res)
{
	struct sha256_ctx ctx;

	sha256_init(&ctx);
	sha256_update(&ctx, memcheck(secret, 32), 32);
	sha256_update(&ctx, memcheck(serial_pubkey, 33), 33);
	sha256_u8(&ctx, seed);
	sha256_done(&ctx, res);
}

static struct enckey enckey_from_secret(const unsigned char secret[32],
					const unsigned char serial_pubkey[33])
{
	struct enckey enckey;
	sha_with_seed(secret, serial_pubkey, ENCKEY_SEED, &enckey.k);
	return enckey;
}

static struct hmackey hmackey_from_secret(const unsigned char secret[32],
					  const unsigned char serial_pubkey[33])
{
	struct hmackey hmackey;
	sha_with_seed(secret, serial_pubkey, HMACKEY_SEED, &hmackey.k);
	return hmackey;
}

static struct iv iv_from_secret(const unsigned char secret[32],
				const unsigned char serial_pubkey[33])
{
	struct sha256 sha;
	struct iv iv;

	sha_with_seed(secret, serial_pubkey, IV_SEED, &sha);
	memcpy(iv.iv, sha.u.u8, sizeof(iv.iv));
	return iv;
}

struct dir_state {
	u64 totlen;
	struct hmackey hmackey;
	EVP_CIPHER_CTX evpctx;

	/* Current packet. */
	struct crypto_pkt *cpkt;
};

static bool setup_crypto(struct dir_state *dir,
			 u8 shared_secret[32], u8 serial_pubkey[33])
{
	struct iv iv;
	struct enckey enckey;

	dir->totlen = 0;	
	dir->hmackey = hmackey_from_secret(shared_secret, serial_pubkey);
	dir->cpkt = NULL;
	
	iv = iv_from_secret(shared_secret, serial_pubkey);
	enckey = enckey_from_secret(shared_secret, serial_pubkey);

	return EVP_EncryptInit(&dir->evpctx, EVP_aes_128_ctr(),
			       memcheck(enckey.k.u.u8, sizeof(enckey.k)),
			       memcheck(iv.iv, sizeof(iv.iv))) == 1;
}

struct io_data {
	/* Stuff we need to keep around to talk to peer. */
	struct dir_state in, out;

	/* Header we're currently reading. */
	size_t len_in;
	struct crypto_pkt hdr_in;

	/* For negotiation phase. */
	struct key_negotiate *neg;
};

static void *proto_tal_alloc(void *allocator_data, size_t size)
{
	return tal_arr(allocator_data, char, size);
}

static void proto_tal_free(void *allocator_data, void *pointer)
{
	tal_free(pointer);
}

static Pkt *decrypt_pkt(struct peer *peer, struct crypto_pkt *cpkt,
			size_t data_len)
{
	size_t full_len;
	struct sha256 hmac;
	int outlen;
	struct io_data *iod = peer->io_data;
	struct ProtobufCAllocator prototal;
	Pkt *ret;

	full_len = ROUNDUP(data_len, AES_BLOCK_SIZE);

	HMAC(EVP_sha256(), iod->in.hmackey.k.u.u8, sizeof(iod->in.hmackey),
	     (unsigned char *)&cpkt->totlen, sizeof(cpkt->totlen) + full_len,
	     hmac.u.u8, NULL);

	if (CRYPTO_memcmp(&hmac, &cpkt->hmac, sizeof(hmac)) != 0) {
		log_unusual(peer->log, "Packet has bad HMAC");
		return NULL;
	}

	/* FIXME: Assumes we can decrypt in place! */
	EVP_DecryptUpdate(&iod->in.evpctx, cpkt->data, &outlen,
			  memcheck(cpkt->data, full_len), full_len);
	assert(outlen == full_len);

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

static struct crypto_pkt *encrypt_pkt(struct peer *peer,
				      const Pkt *pkt,
				      size_t *total_len)
{
	static unsigned char zeroes[AES_BLOCK_SIZE-1];
	struct crypto_pkt *cpkt;
	unsigned char *dout;
	size_t len, full_len;
	int outlen;
	struct io_data *iod = peer->io_data;

	len = pkt__get_packed_size(pkt);
	full_len = ROUNDUP(len, AES_BLOCK_SIZE);
	*total_len = sizeof(*cpkt) + full_len;

	cpkt = (struct crypto_pkt *)tal_arr(peer, char, *total_len);
	iod->out.totlen += len;
	cpkt->totlen = cpu_to_le64(iod->out.totlen);
	
	dout = cpkt->data;
	/* FIXME: Assumes we can encrypt in place! */
	pkt__pack(pkt, dout);
	EVP_EncryptUpdate(&iod->out.evpctx, dout, &outlen,
			  memcheck(dout, len), len);
	dout += outlen;

	/* Now encrypt tail, padding with zeroes if necessary. */
	EVP_EncryptUpdate(&iod->out.evpctx, dout, &outlen, zeroes,
			  full_len - len);
	assert(dout + outlen == cpkt->data + full_len);

	HMAC(EVP_sha256(), iod->out.hmackey.k.u.u8, sizeof(iod->out.hmackey),
	     (unsigned char *)&cpkt->totlen, sizeof(cpkt->totlen) + full_len,
	     cpkt->hmac.u.u8, NULL);

	return cpkt;
}

static int do_read_packet(int fd, struct io_plan_arg *arg)
{
	struct peer *peer = arg->u1.vp;
	struct io_data *iod = peer->io_data;
	u64 max;
	size_t data_off, data_len;
	int ret;

	/* Still reading header? */
	if (iod->len_in < sizeof(iod->hdr_in)) {
		ret = read(fd, (char *)&iod->hdr_in + iod->len_in,
			   sizeof(iod->hdr_in) - iod->len_in);
		if (ret <= 0)
			return -1;
		iod->len_in += ret;
		/* We don't ever send empty packets, so don't check for
		 * that here. */
		return 0;
	}

	max = ROUNDUP(le64_to_cpu(iod->hdr_in.totlen) - iod->in.totlen,
		      AES_BLOCK_SIZE);

	if (iod->len_in == sizeof(iod->hdr_in)) {
		/* FIXME: Handle re-xmit. */
		if (le64_to_cpu(iod->hdr_in.totlen) < iod->in.totlen) {
			log_unusual(peer->log,
				    "Packet went backwards: %"PRIu64
				    " -> %"PRIu64,
				    iod->in.totlen,
				    le64_to_cpu(iod->hdr_in.totlen));
			return -1;
		}
		if (le64_to_cpu(iod->hdr_in.totlen)
		    > iod->in.totlen + MAX_PKT_LEN) {
			log_unusual(peer->log,
				    "Packet overlength: %"PRIu64" -> %"PRIu64,
				    iod->in.totlen,
				    le64_to_cpu(iod->hdr_in.totlen));
			return -1;
		}
		iod->in.cpkt = (struct crypto_pkt *)
			tal_arr(iod, u8, sizeof(struct crypto_pkt) + max);
		memcpy(iod->in.cpkt, &iod->hdr_in, sizeof(iod->hdr_in));
	}

	data_off = iod->len_in - sizeof(struct crypto_pkt);
	ret = read(fd, iod->in.cpkt->data + data_off, max - data_off);
	if (ret <= 0)
		return -1;

	iod->len_in += ret;
	if (iod->len_in <= max)
		return 0;

	/* Can't overflow len arg: packet can't be more than MAX_PKT_LEN */
	data_len = le64_to_cpu(iod->hdr_in.totlen) - iod->in.totlen;
	peer->inpkt = decrypt_pkt(peer, iod->in.cpkt, data_len);
	iod->in.cpkt = tal_free(iod->in.cpkt);

	if (!peer->inpkt)
		return -1;
	iod->in.totlen += data_len;
	return 1;
}

struct io_plan *peer_read_packet(struct io_conn *conn,
				 struct peer *peer,
				 struct io_plan *(*cb)(struct io_conn *,
						       struct peer *))
{
	struct io_plan_arg *arg = io_plan_arg(conn, IO_IN);

	peer->io_data->len_in = 0;
	arg->u1.vp = peer;
	return io_set_plan(conn, IO_IN, do_read_packet,
			   (struct io_plan *(*)(struct io_conn *, void *))cb,
			   peer);
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
	iod->out.cpkt = encrypt_pkt(peer, pkt, &totlen);
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

	/* All complete, return to caller. */
	cb = neg->cb;
	peer->io_data->neg = tal_free(neg);
	return cb(conn, peer);
}

static struct io_plan *receive_proof(struct io_conn *conn, struct peer *peer)
{
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
	if (!setup_crypto(&peer->io_data->in, shared_secret,
			  neg->their_sessionpubkey)
	    || !setup_crypto(&peer->io_data->out, shared_secret,
			     neg->our_sessionpubkey)) {
		log_unusual(peer->log, "Failed setup_crypto()");
		return io_close(conn);
	}

	/* Now sign their session key to prove who we are. */
	privkey_sign(peer, neg->their_sessionpubkey,
		     sizeof(neg->their_sessionpubkey), &sig);

	/* FIXME: Free auth afterwards. */
	auth = authenticate_pkt(peer, &peer->dstate->id, &sig);
	return peer_write_packet(conn, peer, auth, receive_proof);
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
		if (RAND_bytes(seckey, 32) != 1)
			fatal("Could not get random bytes for sessionkey");
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

	peer->io_data = tal(peer, struct io_data);

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
