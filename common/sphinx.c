#include <assert.h>

#include <ccan/array_size/array_size.h>
#include <ccan/crypto/ripemd160/ripemd160.h>
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/mem/mem.h>
#include <common/node_id.h>
#include <common/onion.h>
#include <common/onionreply.h>
#include <common/sphinx.h>
#include <common/utils.h>

#include <err.h>

#include <secp256k1_ecdh.h>

#include <sodium/crypto_auth_hmacsha256.h>
#include <sodium/crypto_stream_chacha20.h>

#include <wire/wire.h>

#define BLINDING_FACTOR_SIZE 32
#define KEY_LEN 32

#define NUM_STREAM_BYTES (2*ROUTING_INFO_SIZE)
#define ONION_REPLY_SIZE 256

#define RHO_KEYTYPE "rho"

struct hop_params {
	struct secret secret;
	u8 blind[BLINDING_FACTOR_SIZE];
	struct pubkey ephemeralkey;
};

struct keyset {
	u8 pi[KEY_LEN];
	u8 mu[KEY_LEN];
	u8 rho[KEY_LEN];
	u8 gamma[KEY_LEN];
};

/* Encapsulates the information about a given payment path for the the onion
 * routing algorithm.
 */
struct sphinx_path {
	/* The session_key used to generate the shared secrets along the
	 * path. This MUST be generated in a cryptographically secure manner,
	 * and is exposed solely for testing, i.e., it can be set to known
	 * values in unit tests. If unset it'll be generated during the packet
	 * generation. */
	struct secret *session_key;

	/* The associated data is appended to the packet when generating the
	 * HMAC, but is not passed along as part of the packet. It is used to
	 * ensure some external data (HTLC payment_hash) is not modified along
	 * the way. */
	u8 *associated_data;

	/* The individual hops on this route. */
	struct sphinx_hop *hops;

	/* If this is a rendez-vous onion, then the following node_id tells us
	 * which node will be processing this onion and decompressing the
	 * onion. It is used to generate the prefill obfuscation stream to
	 * hide the fact that the onion was compressed from the next
	 * node. NULL if this is not a rendez-vous onion, and shouldn't be
	 * compressible. */
	struct pubkey *rendezvous_id;
};

struct sphinx_path *sphinx_path_new(const tal_t *ctx, const u8 *associated_data)
{
	struct sphinx_path *sp = tal(ctx, struct sphinx_path);
	sp->associated_data = tal_dup_talarr(sp, u8, associated_data);
	sp->session_key = NULL;
	sp->rendezvous_id = NULL;
	sp->hops = tal_arr(sp, struct sphinx_hop, 0);
	return sp;
}

struct sphinx_path *sphinx_path_new_with_key(const tal_t *ctx,
					     const u8 *associated_data,
					     const struct secret *session_key)
{
	struct sphinx_path *sp = sphinx_path_new(ctx, associated_data);
	sp->session_key = tal_dup(sp, struct secret, session_key);
	return sp;
}

bool sphinx_path_set_rendezvous(struct sphinx_path *sp,
				const struct node_id *rendezvous_id)
{
	if (rendezvous_id == NULL) {
		sp->rendezvous_id = tal_free(sp->rendezvous_id);
		return true;
	} else {
		sp->rendezvous_id = tal_free(sp->rendezvous_id);
		sp->rendezvous_id = tal(sp, struct pubkey);
		return pubkey_from_node_id(sp->rendezvous_id, rendezvous_id);
	}
}

static size_t sphinx_hop_size(const struct sphinx_hop *hop)
{
	return tal_bytelen(hop->raw_payload) + HMAC_SIZE;
}

size_t sphinx_path_payloads_size(const struct sphinx_path *path)
{
	size_t size = 0;
	for (size_t i=0; i<tal_count(path->hops); i++)
		size += sphinx_hop_size(&path->hops[i]);
	return size;
}

void sphinx_add_hop(struct sphinx_path *path, const struct pubkey *pubkey,
		    const u8 *payload TAKES)
{
	struct sphinx_hop sp;
	sp.raw_payload = tal_dup_talarr(path, u8, payload);
	sp.pubkey = *pubkey;
	tal_arr_expand(&path->hops, sp);
}

/* Small helper to append data to a buffer and update the position
 * into the buffer
 */
static void write_buffer(u8 *dst, const void *src, const size_t len, int *pos)
{
	memcpy(dst + *pos, src, len);
	*pos += len;
}

u8 *serialize_onionpacket(
	const tal_t *ctx,
	const struct onionpacket *m)
{
	u8 *dst = tal_arr(ctx, u8, TOTAL_PACKET_SIZE);

	u8 der[PUBKEY_CMPR_LEN];
	int p = 0;

	pubkey_to_der(der, &m->ephemeralkey);
	write_buffer(dst, &m->version, 1, &p);
	write_buffer(dst, der, sizeof(der), &p);
	write_buffer(dst, m->routinginfo, ROUTING_INFO_SIZE, &p);
	write_buffer(dst, m->mac, sizeof(m->mac), &p);
	return dst;
}

enum onion_type parse_onionpacket(const u8 *src,
				  const size_t srclen,
				  struct onionpacket *dest)
{
	const u8 *cursor = src;
	size_t max = srclen;

	assert(srclen == TOTAL_PACKET_SIZE);

	dest->version = fromwire_u8(&cursor, &max);
	if (dest->version != 0x00) {
		// FIXME add logging
		return WIRE_INVALID_ONION_VERSION;
	}

	fromwire_pubkey(&cursor, &max, &dest->ephemeralkey);
	if (cursor == NULL) {
		return WIRE_INVALID_ONION_KEY;
	}

	fromwire_u8_array(&cursor, &max, dest->routinginfo, ROUTING_INFO_SIZE);
	fromwire_u8_array(&cursor, &max, dest->mac, HMAC_SIZE);
	assert(max == 0);
	return 0;
}

static void xorbytes(uint8_t *d, const uint8_t *a, const uint8_t *b, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		d[i] = a[i] ^ b[i];
}

/*
 * Generate a pseudo-random byte stream of length `dstlen` from key `k` and
 * store it in `dst`. `dst must be at least `dstlen` bytes long.
 */
static void generate_cipher_stream(void *dst, const u8 *k, size_t dstlen)
{
	const u8 nonce[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	crypto_stream_chacha20(dst, dstlen, nonce, k);
}

/* xor cipher stream into dst */
static void xor_cipher_stream(void *dst, const u8 *k, size_t dstlen)
{
	const u8 nonce[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	crypto_stream_chacha20_xor(dst, dst, dstlen, nonce, k);
}

static bool compute_hmac(
	void *dst,
	const void *src,
	size_t len,
	const void *key,
	size_t keylen)
{
	crypto_auth_hmacsha256_state state;

	crypto_auth_hmacsha256_init(&state, key, keylen);
	crypto_auth_hmacsha256_update(&state, memcheck(src, len), len);
	crypto_auth_hmacsha256_final(&state, dst);
	return true;
}

static void compute_packet_hmac(const struct onionpacket *packet,
				const u8 *assocdata, const size_t assocdatalen,
				u8 *mukey, u8 *hmac)
{
	u8 mactemp[ROUTING_INFO_SIZE + assocdatalen];
	u8 mac[32];
	int pos = 0;

	write_buffer(mactemp, packet->routinginfo, ROUTING_INFO_SIZE, &pos);
	write_buffer(mactemp, assocdata, assocdatalen, &pos);

	compute_hmac(mac, mactemp, sizeof(mactemp), mukey, KEY_LEN);
	memcpy(hmac, mac, HMAC_SIZE);
}

static bool generate_key(void *k, const char *t, u8 tlen,
			 const struct secret *s)
{
	return compute_hmac(k, s->data, KEY_LEN, t, tlen);
}

static bool generate_header_padding(void *dst, size_t dstlen,
				    const struct sphinx_path *path,
				    struct hop_params *params)
{
	u8 stream[2 * ROUTING_INFO_SIZE];
	u8 key[KEY_LEN];
	size_t fillerStart, fillerEnd, fillerSize;

	memset(dst, 0, dstlen);
	for (int i = 0; i < tal_count(path->hops) - 1; i++) {
		if (!generate_key(&key, RHO_KEYTYPE, strlen(RHO_KEYTYPE),
				  &params[i].secret))
			return false;

		generate_cipher_stream(stream, key, sizeof(stream));

		/* Sum up how many bytes have been used by previous hops,
		 * that gives us the start in the stream */
		fillerSize = 0;
		for (int j = 0; j < i; j++)
			fillerSize += sphinx_hop_size(&path->hops[j]);
		fillerStart = ROUTING_INFO_SIZE - fillerSize;

		/* The filler will dangle off of the end by the current
		 * hop-size, we'll make sure to copy it into the correct
		 * position in the next step. */
		fillerEnd = ROUTING_INFO_SIZE + sphinx_hop_size(&path->hops[i]);

		/* Apply the cipher-stream to the part of the filler that'll
		 * be added by this hop */
		xorbytes(dst, dst, stream + fillerStart,
			 fillerEnd - fillerStart);
	}
	return true;
}

static bool generate_prefill(void *dst, size_t dstlen,
			     const struct sphinx_path *path,
			     struct hop_params *params)
{
	u8 stream[2 * ROUTING_INFO_SIZE];
	u8 key[KEY_LEN];
	size_t fillerStart, fillerSize;

	memset(dst, 0, dstlen);
	for (int i = 0; i < tal_count(path->hops); i++) {
		if (!generate_key(&key, RHO_KEYTYPE, strlen(RHO_KEYTYPE),
				  &params[i].secret))
			return false;

		generate_cipher_stream(stream, key, sizeof(stream));

		/* Sum up how many bytes have been used by previous hops,
		 * that gives us the start in the stream */
		fillerSize = 0;
		for (int j = 0; j < i; j++)
			fillerSize += sphinx_hop_size(&path->hops[j]);
		fillerStart = ROUTING_INFO_SIZE - fillerSize - dstlen;

		/* Apply the cipher-stream to the part of the filler that'll
		 * be added by this hop */
		xorbytes(dst, dst, stream + fillerStart, dstlen);
	}
	return true;
}

static void compute_blinding_factor(const struct pubkey *key,
				    const struct secret *sharedsecret,
				    u8 res[BLINDING_FACTOR_SIZE])
{
	struct sha256_ctx ctx;
	u8 der[PUBKEY_CMPR_LEN];
	struct sha256 temp;

	pubkey_to_der(der, key);
	sha256_init(&ctx);
	sha256_update(&ctx, der, sizeof(der));
	sha256_update(&ctx, sharedsecret->data, sizeof(sharedsecret->data));
	sha256_done(&ctx, &temp);
	memcpy(res, &temp, 32);
}

static bool blind_group_element(struct pubkey *blindedelement,
				const struct pubkey *pubkey,
				const u8 blind[BLINDING_FACTOR_SIZE])
{
	/* tweak_mul is inplace so copy first. */
	if (pubkey != blindedelement)
		*blindedelement = *pubkey;
	if (secp256k1_ec_pubkey_tweak_mul(secp256k1_ctx,
					  &blindedelement->pubkey, blind) != 1)
		return false;
	return true;
}

bool sphinx_create_shared_secret(struct secret *privkey,
				 const struct pubkey *pubkey,
				 const struct secret *secret)
{
	if (secp256k1_ecdh(secp256k1_ctx, privkey->data, &pubkey->pubkey,
			   secret->data, NULL, NULL) != 1)
		return false;
	return true;
}

bool onion_shared_secret(
	struct secret *secret,
	const struct onionpacket *packet,
	const struct privkey *privkey)
{
	return sphinx_create_shared_secret(secret, &packet->ephemeralkey,
					   &privkey->secret);
}

static void generate_key_set(const struct secret *secret,
			     struct keyset *keys)
{
	generate_key(keys->rho, "rho", 3, secret);
	generate_key(keys->pi, "pi", 2, secret);
	generate_key(keys->mu, "mu", 2, secret);
	generate_key(keys->gamma, "gamma", 5, secret);
}

static struct hop_params *generate_hop_params(
	const tal_t *ctx,
	const u8 *sessionkey,
	struct sphinx_path *path)
{
	int i, j, num_hops = tal_count(path->hops);
	struct pubkey temp;
	u8 blind[BLINDING_FACTOR_SIZE];
	struct hop_params *params = tal_arr(ctx, struct hop_params, num_hops);

	/* Initialize the first hop with the raw information */
	if (secp256k1_ec_pubkey_create(secp256k1_ctx,
				       &params[0].ephemeralkey.pubkey,
				       path->session_key->data) != 1)
		return NULL;

	if (!sphinx_create_shared_secret(
		&params[0].secret, &path->hops[0].pubkey, path->session_key))
		return NULL;

	compute_blinding_factor(
		&params[0].ephemeralkey, &params[0].secret,
		params[0].blind);

	/* Recursively compute all following ephemeral public keys,
	 * secrets and blinding factors
	 */
	for (i = 1; i < num_hops; i++) {
		if (!blind_group_element(
			    &params[i].ephemeralkey,
			    &params[i - 1].ephemeralkey,
			    params[i - 1].blind))
			return NULL;

		/* Blind this hop's point with all previous blinding factors
		 * Order is indifferent, multiplication is commutative.
		 */
		memcpy(&blind, sessionkey, 32);
		temp = path->hops[i].pubkey;
		if (!blind_group_element(&temp, &temp, blind))
			return NULL;
		for (j = 0; j < i; j++)
			if (!blind_group_element(
				    &temp,
				    &temp,
				    params[j].blind))
				return NULL;

		/* Now hash temp and store it. This requires us to
		 * DER-serialize first and then skip the sign byte.
		 */
		u8 der[PUBKEY_CMPR_LEN];
		pubkey_to_der(der, &temp);
		struct sha256 h;
		sha256(&h, der, sizeof(der));
		memcpy(&params[i].secret, &h, sizeof(h));

		compute_blinding_factor(
			&params[i].ephemeralkey,
			&params[i].secret, params[i].blind);
	}
	return params;
}

static void sphinx_write_frame(u8 *dest, const struct sphinx_hop *hop)
{
	memcpy(dest, hop->raw_payload, tal_bytelen(hop->raw_payload));
	memcpy(dest + tal_bytelen(hop->raw_payload), hop->hmac, HMAC_SIZE);
}

static void sphinx_prefill_stream_xor(u8 *dst, size_t dstlen,
				      const struct secret *shared_secret)
{
	u8 padkey[KEY_LEN];
	generate_key(padkey, "prefill", 7, shared_secret);
	xor_cipher_stream(dst, padkey, dstlen);
}

static void sphinx_prefill(u8 *routinginfo, const struct sphinx_path *sp,
			   size_t prefill_size, struct hop_params *params)
{
	int num_hops = tal_count(sp->hops);
	size_t fillerSize = sphinx_path_payloads_size(sp) -
			    sphinx_hop_size(&sp->hops[num_hops - 1]);
	size_t last_hop_size = sphinx_hop_size(&sp->hops[num_hops - 1]);
	int prefill_offset =
	    ROUTING_INFO_SIZE - fillerSize - last_hop_size - prefill_size;
	u8 prefill[prefill_size];
	struct secret shared_secret;

	/* Generate the prefill stream, which cancels out the layers of
	 * encryption that will be applied while wrapping the onion. This
	 * leaves the middle, unused, section with all 0x00 bytes after
	 * encrypting. */
	generate_prefill(prefill, prefill_size, sp, params);
	memcpy(routinginfo + prefill_offset, prefill, prefill_size);

	/* Now fill in the obfuscation stream, which can be regenerated by the
	 * node processing this onion. */
	sphinx_create_shared_secret(&shared_secret, sp->rendezvous_id, sp->session_key);
	sphinx_prefill_stream_xor(routinginfo + prefill_offset, prefill_size, &shared_secret);
}

struct onionpacket *create_onionpacket(
	const tal_t *ctx,
	struct sphinx_path *sp,
	struct secret **path_secrets
	)
{
	struct onionpacket *packet = talz(ctx, struct onionpacket);
	int i, num_hops = tal_count(sp->hops);
	size_t fillerSize = sphinx_path_payloads_size(sp) -
			      sphinx_hop_size(&sp->hops[num_hops - 1]);
	u8 filler[fillerSize];
	struct keyset keys;
	u8 padkey[KEY_LEN];
	u8 nexthmac[HMAC_SIZE];
	struct hop_params *params;
	struct secret *secrets = tal_arr(ctx, struct secret, num_hops);
	size_t payloads_size = sphinx_path_payloads_size(sp);
	size_t max_prefill  = ROUTING_INFO_SIZE - payloads_size;

	if (sphinx_path_payloads_size(sp) > ROUTING_INFO_SIZE) {
		tal_free(packet);
		tal_free(secrets);
		return NULL;
	}

	if (sp->session_key == NULL) {
		sp->session_key = tal(sp, struct secret);
		randombytes_buf(sp->session_key, sizeof(struct secret));
	}

	params = generate_hop_params(ctx, sp->session_key->data, sp);
	if (!params) {
		tal_free(packet);
		tal_free(secrets);
		return NULL;
	}
	packet->version = 0;
	memset(nexthmac, 0, HMAC_SIZE);

	/* BOLT-e116441ee836447ac3f24cdca62bac1e0f223d5f #4:
	 *
	 * The packet is initialized with 1366 _random_ bytes derived from a
	 * CSPRNG.
	 */
	/* Note that this is just hop_payloads: the rest of the packet is
	 * overwritten below or above anyway. */
	generate_key(padkey, "pad", 3, sp->session_key);
	generate_cipher_stream(packet->routinginfo, padkey, ROUTING_INFO_SIZE);

	generate_header_padding(filler, sizeof(filler), sp, params);

	if (sp->rendezvous_id != NULL)
		/* FIXME: Fuzz this or expose to the caller to hide encoded
		 * route length. */
		sphinx_prefill(packet->routinginfo, sp, max_prefill, params);

	for (i = num_hops - 1; i >= 0; i--) {
		memcpy(sp->hops[i].hmac, nexthmac, HMAC_SIZE);
		generate_key_set(&params[i].secret, &keys);

		/* Rightshift mix-header by FRAME_SIZE */
		size_t shiftSize = sphinx_hop_size(&sp->hops[i]);
		memmove(packet->routinginfo + shiftSize, packet->routinginfo,
			ROUTING_INFO_SIZE-shiftSize);
		sphinx_write_frame(packet->routinginfo, &sp->hops[i]);
		xor_cipher_stream(packet->routinginfo, keys.rho,
				  ROUTING_INFO_SIZE);

		if (i == num_hops - 1) {
			memcpy(packet->routinginfo + ROUTING_INFO_SIZE - fillerSize, filler, fillerSize);
		}

		compute_packet_hmac(packet, sp->associated_data, tal_bytelen(sp->associated_data), keys.mu,
				    nexthmac);
	}
	memcpy(packet->mac, nexthmac, sizeof(nexthmac));
	memcpy(&packet->ephemeralkey, &params[0].ephemeralkey, sizeof(secp256k1_pubkey));

	for (i=0; i<num_hops; i++) {
		secrets[i] = params[i].secret;
	}

	*path_secrets = secrets;
	return packet;
}

#if DEVELOPER
bool dev_fail_process_onionpacket;
#endif

/*
 * Given an onionpacket msg extract the information for the current
 * node and unwrap the remainder so that the node can forward it.
 */
struct route_step *process_onionpacket(
	const tal_t *ctx,
	const struct onionpacket *msg,
	const struct secret *shared_secret,
	const u8 *assocdata,
	const size_t assocdatalen
	)
{
	struct route_step *step = talz(ctx, struct route_step);
	u8 hmac[HMAC_SIZE];
	struct keyset keys;
	u8 blind[BLINDING_FACTOR_SIZE];
	u8 paddedheader[2*ROUTING_INFO_SIZE];
	size_t payload_size;
	bigsize_t shift_size;
	bool valid;

	step->next = talz(step, struct onionpacket);
	step->next->version = msg->version;
	generate_key_set(shared_secret, &keys);

	compute_packet_hmac(msg, assocdata, assocdatalen, keys.mu, hmac);

	if (memcmp(msg->mac, hmac, sizeof(hmac)) != 0
	    || IFDEV(dev_fail_process_onionpacket, false)) {
		/* Computed MAC does not match expected MAC, the message was modified. */
		return tal_free(step);
	}

	//FIXME:store seen secrets to avoid replay attacks
	memset(paddedheader, 0, sizeof(paddedheader));
	memcpy(paddedheader, msg->routinginfo, ROUTING_INFO_SIZE);
	xor_cipher_stream(paddedheader, keys.rho, sizeof(paddedheader));

	compute_blinding_factor(&msg->ephemeralkey, shared_secret, blind);
	if (!blind_group_element(&step->next->ephemeralkey, &msg->ephemeralkey, blind))
		return tal_free(step);

	payload_size = onion_payload_length(paddedheader, ROUTING_INFO_SIZE,
					    &valid, NULL);

	/* Can't decode?  Treat it as terminal. */
	if (!valid) {
		shift_size = payload_size;
		memset(step->next->mac, 0, sizeof(step->next->mac));
	} else {
		assert(payload_size <= ROUTING_INFO_SIZE - HMAC_SIZE);
		/* Copy hmac */
		shift_size = payload_size + HMAC_SIZE;
		memcpy(step->next->mac, paddedheader + payload_size, HMAC_SIZE);
	}
	step->raw_payload = tal_dup_arr(step, u8, paddedheader, payload_size, 0);

	/* Left shift the current payload out and make the remainder the new onion */
	memcpy(&step->next->routinginfo, paddedheader + shift_size,
	       ROUTING_INFO_SIZE);

	if (memeqzero(step->next->mac, sizeof(step->next->mac))) {
		step->nextcase = ONION_END;
	} else {
		step->nextcase = ONION_FORWARD;
	}

	return step;
}

struct onionreply *create_onionreply(const tal_t *ctx,
				     const struct secret *shared_secret,
				     const u8 *failure_msg)
{
	size_t msglen = tal_count(failure_msg);
	size_t padlen = ONION_REPLY_SIZE - msglen;
	struct onionreply *reply = tal(ctx, struct onionreply);
	u8 *payload = tal_arr(ctx, u8, 0);
	u8 key[KEY_LEN];
	u8 hmac[HMAC_SIZE];

	/* BOLT #4:
	 *
	 * The node generating the error message (_erring node_) builds a return
	 * packet consisting of
	 * the following fields:
	 *
	 * 1. data:
	 *    * [`32*byte`:`hmac`]
	 *    * [`u16`:`failure_len`]
	 *    * [`failure_len*byte`:`failuremsg`]
	 *    * [`u16`:`pad_len`]
	 *    * [`pad_len*byte`:`pad`]
	 */
	towire_u16(&payload, msglen);
	towire(&payload, failure_msg, msglen);
	towire_u16(&payload, padlen);
	towire_pad(&payload, padlen);

	/* BOLT #4:
	 *
	 * The _erring node_:
	 *   - SHOULD set `pad` such that the `failure_len` plus `pad_len` is
	 *     equal to 256.
	 *     - Note: this value is 118 bytes longer than the longest
	 *       currently-defined message.
	 */
	assert(tal_count(payload) == ONION_REPLY_SIZE + 4);

	/* BOLT #4:
	 *
 	 * Where `hmac` is an HMAC authenticating the remainder of the packet,
	 * with a key generated using the above process, with key type `um`
	 */
	generate_key(key, "um", 2, shared_secret);

	compute_hmac(hmac, payload, tal_count(payload), key, KEY_LEN);
	reply->contents = tal_arr(reply, u8, 0),
	towire(&reply->contents, hmac, sizeof(hmac));

	towire(&reply->contents, payload, tal_count(payload));
	tal_free(payload);

	return reply;
}

struct onionreply *wrap_onionreply(const tal_t *ctx,
				   const struct secret *shared_secret,
				   const struct onionreply *reply)
{
	u8 key[KEY_LEN];
	struct onionreply *result = tal(ctx, struct onionreply);

	/* BOLT #4:
	 *
	 * The erring node then generates a new key, using the key type `ammag`.
	 * This key is then used to generate a pseudo-random stream, which is
	 * in turn applied to the packet using `XOR`.
	 *
	 * The obfuscation step is repeated by every hop along the return path.
	 */
	generate_key(key, "ammag", 5, shared_secret);
	result->contents = tal_dup_talarr(result, u8, reply->contents);
	xor_cipher_stream(result->contents, key, tal_bytelen(result->contents));
	return result;
}

u8 *unwrap_onionreply(const tal_t *ctx,
		      const struct secret *shared_secrets,
		      const int numhops,
		      const struct onionreply *reply,
		      int *origin_index)
{
	struct onionreply *r;
	u8 key[KEY_LEN], hmac[HMAC_SIZE];
	const u8 *cursor;
	u8 *final;
	size_t max;
	u16 msglen;

	if (tal_count(reply->contents) != ONION_REPLY_SIZE + sizeof(hmac) + 4) {
		return NULL;
	}

	r = new_onionreply(tmpctx, reply->contents);
	*origin_index = -1;

	for (int i = 0; i < numhops; i++) {
		/* Since the encryption is just XORing with the cipher
		 * stream encryption is identical to decryption */
		r = wrap_onionreply(tmpctx, &shared_secrets[i], r);

		/* Check if the HMAC matches, this means that this is
		 * the origin */
		generate_key(key, "um", 2, &shared_secrets[i]);
		compute_hmac(hmac, r->contents + sizeof(hmac),
			     tal_count(r->contents) - sizeof(hmac),
			     key, KEY_LEN);
		if (memcmp(hmac, r->contents, sizeof(hmac)) == 0) {
			*origin_index = i;
			break;
		}
	}
	if (*origin_index == -1) {
		return NULL;
	}

	cursor = r->contents + sizeof(hmac);
	max = tal_count(r->contents) - sizeof(hmac);
	msglen = fromwire_u16(&cursor, &max);

	if (msglen > ONION_REPLY_SIZE) {
		return NULL;
	}

	final = tal_arr(ctx, u8, msglen);
	if (!fromwire(&cursor, &max, final, msglen))
		return tal_free(final);
	return final;
}

struct onionpacket *sphinx_decompress(const tal_t *ctx,
				      const struct sphinx_compressed_onion *src,
				      const struct secret *shared_secret)
{
	struct onionpacket *res = tal(ctx, struct onionpacket);
	size_t srclen = tal_bytelen(src->routinginfo);
	size_t prefill_size = ROUTING_INFO_SIZE - srclen;

	res->version = src->version;
	res->ephemeralkey = src->ephemeralkey;
	memcpy(res->mac, src->mac, HMAC_SIZE);

	/* Decompress routinginfo by copying the unmodified prefix, setting
	 * the compressed suffix to 0x00 bytes and then xoring the obfuscation
	 * stream in place. */
	memset(res->routinginfo, 0, ROUTING_INFO_SIZE);
	memcpy(res->routinginfo, src->routinginfo, srclen);
	sphinx_prefill_stream_xor(res->routinginfo + srclen, prefill_size,
				  shared_secret);

	return res;
}

struct sphinx_compressed_onion *
sphinx_compress(const tal_t *ctx, const struct onionpacket *packet,
		const struct sphinx_path *path)
{
	struct sphinx_compressed_onion *res;
	size_t payloads_size = sphinx_path_payloads_size(path);

	/* We can't compress an onion that doesn't have a rendez-vous node. */
	if (path->rendezvous_id == NULL)
		return NULL;

	res = tal(ctx, struct sphinx_compressed_onion);
	res->version = packet->version;
	res->ephemeralkey = packet->ephemeralkey;
	memcpy(res->mac, packet->mac, HMAC_SIZE);

	res->routinginfo = tal_arr(res, u8, payloads_size);
	memcpy(res->routinginfo, packet->routinginfo, payloads_size);

	return res;
}

u8 *sphinx_compressed_onion_serialize(const tal_t *ctx, const struct sphinx_compressed_onion *onion)
{
	size_t routelen = tal_bytelen(onion->routinginfo);
	size_t len = VERSION_SIZE + PUBKEY_SIZE + routelen + HMAC_SIZE;
	u8 *dst = tal_arr(ctx, u8, len);
	u8 der[PUBKEY_CMPR_LEN];
	int p = 0;

	pubkey_to_der(der, &onion->ephemeralkey);

	write_buffer(dst, &onion->version, VERSION_SIZE, &p);
	write_buffer(dst, der, PUBKEY_SIZE, &p);
	write_buffer(dst, onion->routinginfo, routelen, &p);
	write_buffer(dst, onion->mac, HMAC_SIZE, &p);

	assert(p == len);
	return dst;
}

struct sphinx_compressed_onion *
sphinx_compressed_onion_deserialize(const tal_t *ctx, const u8 *src)
{
	const u8 *cursor = src;
	size_t max = tal_bytelen(src);
	size_t routelen = max - VERSION_SIZE - PUBKEY_SIZE - HMAC_SIZE;
	struct sphinx_compressed_onion *dst =
	    tal(ctx, struct sphinx_compressed_onion);

	/* This is not a compressed onion, so let's not parse it. */
	if (routelen > ROUTING_INFO_SIZE)
		return tal_free(dst);

	dst->version = fromwire_u8(&cursor, &max);
	if (dst->version != 0x00)
		return tal_free(dst);

	fromwire_pubkey(&cursor, &max, &dst->ephemeralkey);

	dst->routinginfo = tal_arr(dst, u8, routelen);
	fromwire_u8_array(&cursor, &max, dst->routinginfo, routelen);
	fromwire_u8_array(&cursor, &max, dst->mac, HMAC_SIZE);

	assert(max == 0);
	return dst;
}
