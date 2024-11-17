#include "config.h"
#include <assert.h>

#include <ccan/array_size/array_size.h>
#include <ccan/mem/mem.h>
#include <common/onion_decode.h>
#include <common/onionreply.h>
#include <common/overflows.h>
#include <common/sphinx.h>


#include <secp256k1_ecdh.h>

#include <sodium/crypto_stream_chacha20.h>
#include <sodium/randombytes.h>


#define BLINDING_FACTOR_SIZE 32

#define RHO_KEYTYPE "rho"

struct hop_params {
	struct secret secret;
	u8 blind[BLINDING_FACTOR_SIZE];
	struct pubkey ephemeralkey;
};

struct keyset {
	struct secret pi, mu, rho, gamma;
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

	/* The individual hops on this route, and their hmacs */
	struct sphinx_hop *hops;

	/* If this is a rendez-vous onion, then the following node_id tells us
	 * which node will be processing this onion and decompressing the
	 * onion. It is used to generate the prefill obfuscation stream to
	 * hide the fact that the onion was compressed from the next
	 * node. NULL if this is not a rendez-vous onion, and shouldn't be
	 * compressible. */
	struct pubkey *rendezvous_id;
};

struct sphinx_path *sphinx_path_new(const tal_t *ctx,
				    const u8 *associated_data,
				    size_t associated_data_len)
{
	struct sphinx_path *sp = tal(ctx, struct sphinx_path);
	if (associated_data) {
		sp->associated_data
			= tal_dup_arr(sp, u8, associated_data, associated_data_len, 0);
	} else {
		assert(associated_data_len == 0);
		sp->associated_data = NULL;
	}
	sp->session_key = NULL;
	sp->rendezvous_id = NULL;
	sp->hops = tal_arr(sp, struct sphinx_hop, 0);
	return sp;
}

struct sphinx_path *sphinx_path_new_with_key(const tal_t *ctx,
					     const u8 *associated_data,
					     size_t associated_data_len,
					     const struct secret *session_key)
{
	struct sphinx_path *sp = sphinx_path_new(ctx, associated_data, associated_data_len);
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

bool sphinx_add_hop_has_length(struct sphinx_path *path, const struct pubkey *pubkey,
			       const u8 *payload TAKES)
{
	struct sphinx_hop sp;
	bigsize_t lenlen, prepended_len;

	/* In case length is missing, we'll return false. */
	prepended_len = UINT64_MAX;
	lenlen = bigsize_get(payload, tal_bytelen(payload), &prepended_len);
	if (add_overflows_u64(lenlen, prepended_len))
		return false;
	if (lenlen + prepended_len != tal_bytelen(payload))
		return false;

	sp.raw_payload = tal_dup_talarr(path, u8, payload);
	sp.pubkey = *pubkey;
	tal_arr_expand(&path->hops, sp);
	return true;
}

static u8 *make_v0_hop(const tal_t *ctx,
		       const struct short_channel_id *scid,
		       struct amount_msat forward, u32 outgoing_cltv)
{
	const u8 padding[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			      0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	/* Prepend 0 byte for realm */
	u8 *buf = tal_arrz(ctx, u8, 1);
	towire_short_channel_id(&buf, *scid);
	towire_amount_msat(&buf, forward);
	towire_u32(&buf, outgoing_cltv);
	towire(&buf, padding, ARRAY_SIZE(padding));
	assert(tal_bytelen(buf) == 1 + 32);
	return buf;
}

void sphinx_add_v0_hop(struct sphinx_path *path, const struct pubkey *pubkey,
		       const struct short_channel_id *scid,
		       struct amount_msat forward, u32 outgoing_cltv)
{
	struct sphinx_hop sp;

	sp.raw_payload = make_v0_hop(path, scid, forward, outgoing_cltv);
	sp.pubkey = *pubkey;
	tal_arr_expand(&path->hops, sp);
}

void sphinx_add_hop(struct sphinx_path *path, const struct pubkey *pubkey,
		    const u8 *payload TAKES)
{
	u8 *with_len = tal_arr(NULL, u8, 0);
	size_t len = tal_bytelen(payload);
	towire_bigsize(&with_len, len);
	towire_u8_array(&with_len, payload, len);
	if (taken(payload))
		tal_free(payload);

	if (!sphinx_add_hop_has_length(path, pubkey, take(with_len)))
		abort();
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
	u8 *dst = tal_arr(ctx, u8, TOTAL_PACKET_SIZE(tal_bytelen(m->routinginfo)));

	u8 der[PUBKEY_CMPR_LEN];
	int p = 0;

	pubkey_to_der(der, &m->ephemeralkey);
	write_buffer(dst, &m->version, 1, &p);
	write_buffer(dst, der, sizeof(der), &p);
	write_buffer(dst, m->routinginfo, tal_bytelen(m->routinginfo), &p);
	write_buffer(dst, m->hmac.bytes, sizeof(m->hmac.bytes), &p);
	return dst;
}

struct onionpacket *parse_onionpacket(const tal_t *ctx,
				      const u8 *src,
				      const size_t srclen,
				      enum onion_wire *failcode)
{
	struct onionpacket *dest = tal(ctx, struct onionpacket);
	const u8 *cursor = src;
	size_t max = srclen;

	dest->version = fromwire_u8(&cursor, &max);
	if (dest->version != 0x00) {
		// FIXME add logging
		*failcode = WIRE_INVALID_ONION_VERSION;
		return tal_free(dest);
	}

	fromwire_pubkey(&cursor, &max, &dest->ephemeralkey);
	if (cursor == NULL) {
		*failcode = WIRE_INVALID_ONION_KEY;
		return tal_free(dest);
	}

	/* If max underflows, this returns NULL and fromwire fails. */
	dest->routinginfo = fromwire_tal_arrn(dest, &cursor, &max,
					      max - HMAC_SIZE);
	fromwire_hmac(&cursor, &max, &dest->hmac);

	assert(max == 0);
	if (cursor == NULL) {
		*failcode = WIRE_INVALID_ONION_HMAC;
		return tal_free(dest);
	}

	return dest;
}

/*
 * Generate a pseudo-random byte stream of length `dstlen` from key `k` and
 * store it in `dst`. `dst must be at least `dstlen` bytes long.
 */
static void generate_cipher_stream(void *dst, const struct secret *k, size_t dstlen)
{
	const u8 nonce[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	crypto_stream_chacha20(dst, dstlen, nonce, k->data);
}

/* xor cipher stream into dst */
static void xor_cipher_stream(void *dst, const struct secret *k, size_t dstlen)
{
	const u8 nonce[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	crypto_stream_chacha20_xor(dst, dst, dstlen, nonce, k->data);
}

#define CHACHA20_BLOCK_BYTES 64

static void xor_cipher_stream_off(const struct secret *k,
				  size_t off,
				  void *dst, size_t dstlen)
{
	const u8 nonce[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	u8 block[CHACHA20_BLOCK_BYTES];
	size_t block_off;
	size_t ic = off / CHACHA20_BLOCK_BYTES;

	/* From https://libsodium.gitbook.io/doc/advanced/stream_ciphers/chacha20:
	 *
	 * The crypto_stream_chacha20_xor_ic() function is similar to
	 * crypto_stream_chacha20_xor() but adds the ability to set
	 * the initial value of the block counter to a non-zero value,
	 * ic.
	 *
	 * This permits direct access to any block without having to
	 * compute the previous ones.
	 */
	block_off = (off % CHACHA20_BLOCK_BYTES);
	if (block_off != 0) {
		size_t rem = CHACHA20_BLOCK_BYTES - block_off;
		if (rem > dstlen)
			rem = dstlen;
		memcpy(block + block_off, dst, rem);
		crypto_stream_chacha20_xor_ic(block, block, block_off + rem,
					      nonce,
					      ic,
					      k->data);
		ic++;
		memcpy(dst, block + block_off, rem);
		dst = (char *)dst + rem;
		dstlen -= rem;
	}
	crypto_stream_chacha20_xor_ic(dst, dst, dstlen, nonce, ic, k->data);
}

/* Convenience function: s2/s2len can be NULL/0 if unwanted */
static void compute_hmac(const struct secret *key,
			 const u8 *s1, size_t s1len,
			 const u8 *s2, size_t s2len,
			 struct hmac *hmac)
{
	crypto_auth_hmacsha256_state state;

	hmac_start(&state, key->data, sizeof(key->data));
	hmac_update(&state, s1, s1len);
	hmac_update(&state, s2, s2len);
	hmac_done(&state, hmac);
}

static void compute_packet_hmac(const struct onionpacket *packet,
				const u8 *assocdata, const size_t assocdatalen,
				const struct secret *mukey,
				struct hmac *hmac)
{
	compute_hmac(mukey,
		     packet->routinginfo, tal_bytelen(packet->routinginfo),
		     assocdata, assocdatalen,
		     hmac);
}

static void generate_header_padding(void *dst, size_t dstlen,
				    size_t fixed_size,
				    const struct sphinx_path *path,
				    struct hop_params *params)
{
	struct secret key;
	size_t fillerStart, fillerEnd, fillerSize;

	memset(dst, 0, dstlen);
	for (int i = 0; i < tal_count(path->hops) - 1; i++) {
		subkey_from_hmac("rho", &params[i].secret, &key);

		/* Sum up how many bytes have been used by previous hops,
		 * that gives us the start in the stream */
		fillerSize = 0;
		for (int j = 0; j < i; j++)
			fillerSize += sphinx_hop_size(&path->hops[j]);
		fillerStart = fixed_size - fillerSize;

		/* The filler will dangle off of the end by the current
		 * hop-size, we'll make sure to copy it into the correct
		 * position in the next step. */
		fillerEnd = fixed_size + sphinx_hop_size(&path->hops[i]);

		/* Apply the cipher-stream to the part of the filler that'll
		 * be added by this hop */
		xor_cipher_stream_off(&key, fillerStart,
				      dst, fillerEnd - fillerStart);
	}
}

static void generate_prefill(void *dst, size_t dstlen,
			     size_t fixed_size,
			     const struct sphinx_path *path,
			     struct hop_params *params)
{
	struct secret key;
	size_t fillerStart, fillerSize;

	memset(dst, 0, dstlen);
	for (int i = 0; i < tal_count(path->hops); i++) {
		subkey_from_hmac("rho", &params[i].secret, &key);

		/* Sum up how many bytes have been used by previous hops,
		 * that gives us the start in the stream */
		fillerSize = 0;
		for (int j = 0; j < i; j++)
			fillerSize += sphinx_hop_size(&path->hops[j]);
		fillerStart = fixed_size - fillerSize - dstlen;

		/* Apply the cipher-stream to the part of the filler that'll
		 * be added by this hop */
		xor_cipher_stream_off(&key, fillerStart, dst, dstlen);
	}
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
	subkey_from_hmac("rho", secret, &keys->rho);
	subkey_from_hmac("pi", secret, &keys->pi);
	subkey_from_hmac("mu", secret, &keys->mu);
	subkey_from_hmac("gamma", secret, &keys->gamma);
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

static void sphinx_write_frame(u8 *dest,
			       const struct sphinx_hop *hop,
			       const struct hmac *hmac)
{
	BUILD_ASSERT(sizeof(hmac->bytes) == HMAC_SIZE);
	memcpy(dest, hop->raw_payload, tal_bytelen(hop->raw_payload));
	memcpy(dest + tal_bytelen(hop->raw_payload),
	       hmac->bytes, HMAC_SIZE);
}

static void sphinx_prefill_stream_xor(u8 *dst, size_t dstlen,
				      const struct secret *shared_secret)
{
	struct secret padkey;
	subkey_from_hmac("prefill", shared_secret, &padkey);
	xor_cipher_stream(dst, &padkey, dstlen);
}

static void sphinx_prefill(u8 *routinginfo, const struct sphinx_path *sp,
			   size_t prefill_size, struct hop_params *params,
			   size_t fixed_size)
{
	int num_hops = tal_count(sp->hops);
	size_t fillerSize = sphinx_path_payloads_size(sp) -
			    sphinx_hop_size(&sp->hops[num_hops - 1]);
	size_t last_hop_size = sphinx_hop_size(&sp->hops[num_hops - 1]);
	int prefill_offset =
	    fixed_size - fillerSize - last_hop_size - prefill_size;
	struct secret shared_secret;

	/* Generate the prefill stream, which cancels out the layers of
	 * encryption that will be applied while wrapping the onion. This
	 * leaves the middle, unused, section with all 0x00 bytes after
	 * encrypting. */
	generate_prefill(routinginfo + prefill_offset, prefill_size,
			 fixed_size, sp, params);

	/* Now fill in the obfuscation stream, which can be regenerated by the
	 * node processing this onion. */
	sphinx_create_shared_secret(&shared_secret, sp->rendezvous_id, sp->session_key);
	sphinx_prefill_stream_xor(routinginfo + prefill_offset, prefill_size, &shared_secret);
}

struct onionpacket *create_onionpacket(
	const tal_t *ctx,
	struct sphinx_path *sp,
	size_t fixed_size,
	struct secret **path_secrets
	)
{
	struct onionpacket *packet = talz(ctx, struct onionpacket);
	int i, num_hops = tal_count(sp->hops);
	size_t fillerSize = sphinx_path_payloads_size(sp) -
			      sphinx_hop_size(&sp->hops[num_hops - 1]);
	u8 *filler;
	struct keyset keys;
	struct secret padkey;
	struct hmac nexthmac;
	struct hop_params *params;
	struct secret *secrets = tal_arr(ctx, struct secret, num_hops);
	size_t payloads_size = sphinx_path_payloads_size(sp);
	size_t max_prefill = fixed_size - payloads_size;

	if (sphinx_path_payloads_size(sp) > fixed_size) {
		tal_free(packet);
		tal_free(secrets);
		return NULL;
	}
	packet->routinginfo = tal_arr(packet, u8, fixed_size);

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
	memset(nexthmac.bytes, 0, sizeof(nexthmac.bytes));

	/* BOLT #4:
	 *
	 * The packet is initialized with 1300 _random_ bytes derived from a
	 * CSPRNG
	 */
	/* Note that this is just hop_payloads: the rest of the packet is
	 * overwritten below or above anyway. */
	subkey_from_hmac("pad", sp->session_key, &padkey);
	generate_cipher_stream(packet->routinginfo, &padkey, fixed_size);

	filler = tal_arr(tmpctx, u8, fillerSize);
	generate_header_padding(filler, tal_bytelen(filler), fixed_size, sp, params);

	if (sp->rendezvous_id != NULL)
		/* FIXME: Fuzz this or expose to the caller to hide encoded
		 * route length. */
		sphinx_prefill(packet->routinginfo, sp, max_prefill, params,
			       fixed_size);

	for (i = num_hops - 1; i >= 0; i--) {
		generate_key_set(&params[i].secret, &keys);

		/* Rightshift mix-header by FRAME_SIZE */
		size_t shiftSize = sphinx_hop_size(&sp->hops[i]);
		memmove(packet->routinginfo + shiftSize, packet->routinginfo,
			fixed_size - shiftSize);
		sphinx_write_frame(packet->routinginfo, &sp->hops[i], &nexthmac);
		xor_cipher_stream(packet->routinginfo, &keys.rho,
				  fixed_size);

		if (i == num_hops - 1) {
			memcpy(packet->routinginfo + fixed_size - fillerSize, filler, fillerSize);
		}

		compute_packet_hmac(packet, sp->associated_data, tal_bytelen(sp->associated_data), &keys.mu,
				    &nexthmac);
	}
	packet->hmac = nexthmac;
	packet->ephemeralkey = params[0].ephemeralkey;

	for (i=0; i<num_hops; i++) {
		secrets[i] = params[i].secret;
	}

	*path_secrets = secrets;
	return packet;
}

bool dev_fail_process_onionpacket;

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
	struct hmac hmac;
	struct keyset keys;
	u8 blind[BLINDING_FACTOR_SIZE];
	u8 *paddedheader;
	size_t payload_size;
	bigsize_t shift_size;
	const u8 *cursor;
	size_t max;

	step->next = talz(step, struct onionpacket);
	step->next->version = msg->version;
	generate_key_set(shared_secret, &keys);

	compute_packet_hmac(msg, assocdata, assocdatalen, &keys.mu, &hmac);

	if (!hmac_eq(&msg->hmac, &hmac) || dev_fail_process_onionpacket) {
		/* Computed MAC does not match expected MAC, the message was modified. */
		return tal_free(step);
	}

	//FIXME:store seen secrets to avoid replay attacks
	paddedheader = tal_arrz(step, u8, tal_bytelen(msg->routinginfo)*2);
	memcpy(paddedheader, msg->routinginfo, tal_bytelen(msg->routinginfo));
	xor_cipher_stream(paddedheader, &keys.rho, tal_bytelen(paddedheader));

	compute_blinding_factor(&msg->ephemeralkey, shared_secret, blind);
	if (!blind_group_element(&step->next->ephemeralkey, &msg->ephemeralkey, blind))
		return tal_free(step);

	/* Now, try to pull data out. */
	cursor = paddedheader;
	max = tal_bytelen(msg->routinginfo);

	/* Any of these could fail, falling thru with cursor == NULL */
	payload_size = fromwire_bigsize(&cursor, &max);

	/* Legacy!  0 length payload means fixed 32 byte structure */
	if (payload_size == 0 && max >= 32) {
		struct tlv_payload *legacy = tlv_payload_new(tmpctx);
		const u8 *legacy_cursor = cursor;
		size_t legacy_max = 32;
		u8 *onwire_tlv;

		legacy->amt_to_forward = tal(legacy, u64);
		legacy->outgoing_cltv_value = tal(legacy, u32);
		legacy->short_channel_id = tal(legacy, struct short_channel_id);

		/* BOLT-obsolete #4:
		 * ## Legacy `hop_data` payload format
		 *
		 * The `hop_data` format is identified by a single `0x00`-byte
		 * length, for backward compatibility.  Its payload is defined
		 * as:
		 *
		 * 1. type: `hop_data` (for `realm` 0)
		 * 2. data:
		 *    * [`short_channel_id`:`short_channel_id`]
		 *    * [`u64`:`amt_to_forward`]
		 *    * [`u32`:`outgoing_cltv_value`]
		 *    * [`12*byte`:`padding`]
		 */
		*legacy->short_channel_id = fromwire_short_channel_id(&legacy_cursor, &legacy_max);
		*legacy->amt_to_forward = fromwire_u64(&legacy_cursor, &legacy_max);
		*legacy->outgoing_cltv_value = fromwire_u32(&legacy_cursor, &legacy_max);

		/* Re-linearize it as a modern TLV! */
		onwire_tlv = tal_arr(tmpctx, u8, 0);
		towire_tlv_payload(&onwire_tlv, legacy);

		/* Length, then tlv */
		step->raw_payload = tal_arr(step, u8, 0);
		towire_bigsize(&step->raw_payload, tal_bytelen(onwire_tlv));
		towire_u8_array(&step->raw_payload, onwire_tlv, tal_bytelen(onwire_tlv));

		payload_size = 32;
		fromwire_pad(&cursor, &max, payload_size);
	} else {
		/* FIXME: raw_payload *includes* the length, which is redundant and
		 * means we can't just ust fromwire_tal_arrn. */
		fromwire_pad(&cursor, &max, payload_size);
		if (cursor != NULL)
			step->raw_payload = tal_dup_arr(step, u8, paddedheader,
							cursor - paddedheader, 0);
	}
	fromwire_hmac(&cursor, &max, &step->next->hmac);

	/* BOLT #4:
	 * Since no `payload` TLV value can ever be shorter than 2 bytes, `length` values of 0 and 1 are
	 * reserved.  (`0` indicated a legacy format no longer supported, and `1` is reserved for future
	 * use). */
	if (payload_size < 2 || !cursor)
		return tal_free(step);

	/* This includes length field and hmac */
	shift_size = cursor - paddedheader;

	/* Left shift the current payload out and make the remainder the new onion */
	step->next->routinginfo = tal_dup_arr(step->next,
					      u8,
					      paddedheader + shift_size,
					      tal_bytelen(msg->routinginfo), 0);

	if (memeqzero(step->next->hmac.bytes, sizeof(step->next->hmac.bytes))) {
		step->nextcase = ONION_END;
	} else {
		step->nextcase = ONION_FORWARD;
	}

	tal_free(paddedheader);
	return step;
}

unsigned dev_onion_reply_length = 256;

struct onionreply *create_onionreply(const tal_t *ctx,
				     const struct secret *shared_secret,
				     const u8 *failure_msg)
{
	size_t msglen = tal_count(failure_msg);
	size_t padlen;
	struct onionreply *reply = tal(ctx, struct onionreply);
	u8 *payload = tal_arr(ctx, u8, 0);
	struct secret key;
	struct hmac hmac;

	/* BOLT #4:
	 * The _erring node_:
	 * - MUST set `pad` such that the `failure_len` plus `pad_len`
	 *  is at least 256.
	 *   - SHOULD set `pad` such that the `failure_len` plus `pad_len` is equal
	 *     to 256. Deviating from this may cause older nodes to be unable to parse
	 *     the return message.
	 */
	const u16 onion_reply_size = dev_onion_reply_length;

	/* We never do this currently, but could in future! */
	if (msglen > onion_reply_size)
		padlen = 0;
	else
		padlen = onion_reply_size - msglen;

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

	/* Two bytes for each length: failure_len and pad_len */
	assert(tal_count(payload) == onion_reply_size + 4);

	/* BOLT #4:
	 *
 	 * Where `hmac` is an HMAC authenticating the remainder of the packet,
	 * with a key generated using the above process, with key type `um`
	 */
	subkey_from_hmac("um", shared_secret, &key);

	compute_hmac(&key, payload, tal_count(payload), NULL, 0, &hmac);
	reply->contents = tal_arr(reply, u8, 0),
	towire_hmac(&reply->contents, &hmac);

	towire(&reply->contents, payload, tal_count(payload));
	tal_free(payload);

	return reply;
}

struct onionreply *wrap_onionreply(const tal_t *ctx,
				   const struct secret *shared_secret,
				   const struct onionreply *reply)
{
	struct secret key;
	struct onionreply *result = tal(ctx, struct onionreply);

	/* BOLT #4:
	 *
	 * The erring node then generates a new key, using the key type `ammag`.
	 * This key is then used to generate a pseudo-random stream, which is
	 * in turn applied to the packet using `XOR`.
	 *
	 * The obfuscation step is repeated by every hop along the return path.
	 */
	subkey_from_hmac("ammag", shared_secret, &key);
	result->contents = tal_dup_talarr(result, u8, reply->contents);
	xor_cipher_stream(result->contents, &key, tal_bytelen(result->contents));
	return result;
}

u8 *unwrap_onionreply(const tal_t *ctx,
		      const struct secret *shared_secrets,
		      const int numhops,
		      const struct onionreply *reply,
		      int *origin_index)
{
	struct onionreply *r;
	const u8 *cursor;
	size_t max;
	u16 msglen;

	r = new_onionreply(tmpctx, reply->contents);
	*origin_index = -1;

	for (int i = 0; i < numhops; i++) {
		struct secret key;
		struct hmac hmac, expected_hmac;

		/* Since the encryption is just XORing with the cipher
		 * stream encryption is identical to decryption */
		r = wrap_onionreply(tmpctx, &shared_secrets[i], r);

		/* Check if the HMAC matches, this means that this is
		 * the origin */
		subkey_from_hmac("um", &shared_secrets[i], &key);

		cursor = r->contents;
		max = tal_count(r->contents);

		fromwire_hmac(&cursor, &max, &hmac);
		/* Too short. */
		if (!cursor)
			return NULL;

		compute_hmac(&key, cursor, max, NULL, 0, &expected_hmac);
		if (hmac_eq(&hmac, &expected_hmac)) {
			*origin_index = i;
			break;
		}
	}

	/* Didn't find source, it's garbled */
	if (*origin_index == -1) {
		return NULL;
	}

	msglen = fromwire_u16(&cursor, &max);
	return fromwire_tal_arrn(ctx, &cursor, &max, msglen);
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
	res->hmac = src->hmac;

	/* Decompress routinginfo by copying the unmodified prefix, setting
	 * the compressed suffix to 0x00 bytes and then xoring the obfuscation
	 * stream in place. */
	res->routinginfo = tal_arrz(res, u8, ROUTING_INFO_SIZE);
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
	res->hmac = packet->hmac;

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
	write_buffer(dst, onion->hmac.bytes, sizeof(onion->hmac.bytes), &p);

	assert(p == len);
	return dst;
}

struct sphinx_compressed_onion *
sphinx_compressed_onion_deserialize(const tal_t *ctx, const u8 *src)
{
	const u8 *cursor = src;
	size_t max = tal_bytelen(src);
	struct sphinx_compressed_onion *dst =
	    tal(ctx, struct sphinx_compressed_onion);

	/* This is not a compressed onion, so let's not parse it. */
	if (max > TOTAL_PACKET_SIZE(ROUTING_INFO_SIZE))
		return tal_free(dst);

	dst->version = fromwire_u8(&cursor, &max);
	if (dst->version != 0x00)
		return tal_free(dst);

	fromwire_pubkey(&cursor, &max, &dst->ephemeralkey);
	dst->routinginfo = fromwire_tal_arrn(dst, &cursor, &max, max - HMAC_SIZE);
	fromwire_hmac(&cursor, &max, &dst->hmac);

	/* If at any point we failed to pull from the serialized compressed
	 * onion the entire deserialization is considered to have failed. */
	if (cursor == NULL)
		return tal_free(dst);
	return dst;
}
