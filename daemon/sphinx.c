#include "sphinx.h"
#include <assert.h>

#include <ccan/crypto/ripemd160/ripemd160.h>
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/mem/mem.h>

#include <err.h>

#include <sodium/crypto_auth_hmacsha256.h>
#include <sodium/crypto_stream_chacha20.h>

#define BLINDING_FACTOR_SIZE 32
#define SHARED_SECRET_SIZE 32
#define NUM_STREAM_BYTES (2 * NUM_MAX_HOPS + 2) * SECURITY_PARAMETER
#define KEY_LEN 32

struct hop_params {
	u8 secret[SHARED_SECRET_SIZE];
	u8 blind[BLINDING_FACTOR_SIZE];
	secp256k1_pubkey ephemeralkey;
};

struct keyset {
	u8 pi[KEY_LEN];
	u8 mu[KEY_LEN];
	u8 rho[KEY_LEN];
	u8 gamma[KEY_LEN];
};

/* Small helper to append data to a buffer and update the position
 * into the buffer
 */
static void write_buffer(u8 *dst, const void *src, const size_t len, int *pos)
{
	memcpy(dst + *pos, src, len);
	*pos += len;
}

/* Read len bytes from the source at position pos into dst and update
 * the position pos accordingly.
 */
static void read_buffer(void *dst, const u8 *src, const size_t len, int *pos)
{
	memcpy(dst, src + *pos, len);
	*pos += len;
}

u8 *serialize_onionpacket(
	const tal_t *ctx,
	const secp256k1_context *secpctx,
	const struct onionpacket *m)
{
	u8 *dst = tal_arr(ctx, u8, TOTAL_PACKET_SIZE);

	u8 der[33];
	size_t outputlen = 33;
	int p = 0;

	secp256k1_ec_pubkey_serialize(secpctx,
				      der,
				      &outputlen,
				      &m->ephemeralkey,
				      SECP256K1_EC_COMPRESSED);

	write_buffer(dst, &m->version, 1, &p);
	write_buffer(dst, der, outputlen, &p);
	write_buffer(dst, m->mac, sizeof(m->mac), &p);
	write_buffer(dst, m->routinginfo, ROUTING_INFO_SIZE, &p);
	write_buffer(dst, m->hoppayloads, TOTAL_HOP_PAYLOAD_SIZE, &p);
	write_buffer(dst, m->payload, MESSAGE_SIZE, &p);
	return dst;
}

struct onionpacket *parse_onionpacket(
	const tal_t *ctx,
	const secp256k1_context *secpctx,
	const void *src,
	const size_t srclen
	)
{
	struct onionpacket *m;
	int p = 0;
	u8 rawEphemeralkey[33];

	if (srclen != TOTAL_PACKET_SIZE)
		return NULL;

	m = talz(ctx, struct onionpacket);

	read_buffer(&m->version, src, 1, &p);
	if (m->version != 0x01) {
		// FIXME add logging
		return tal_free(m);
	}
	read_buffer(rawEphemeralkey, src, 33, &p);

	if (secp256k1_ec_pubkey_parse(secpctx, &m->ephemeralkey, rawEphemeralkey, 33) != 1)
		return tal_free(m);

	read_buffer(&m->mac, src, 20, &p);
	read_buffer(&m->routinginfo, src, ROUTING_INFO_SIZE, &p);
	read_buffer(&m->hoppayloads, src, TOTAL_HOP_PAYLOAD_SIZE, &p);
	read_buffer(m->payload, src, MESSAGE_SIZE, &p);
	return m;
}

static struct hoppayload *parse_hoppayload(const tal_t *ctx, u8 *src)
{
	int p = 0;
	struct hoppayload *result = talz(ctx, struct hoppayload);

	read_buffer(&result->realm, src, sizeof(&result->realm), &p);
	read_buffer(&result->amount, src, sizeof(&result->amount), &p);
	read_buffer(&result->remainder, src, sizeof(&result->remainder), &p);
	return result;
}

static void serialize_hoppayload(u8 *dst, struct hoppayload *hp)
{
	int p = 0;

	write_buffer(dst, &hp->realm, sizeof(&hp->realm), &p);
	write_buffer(dst, &hp->amount, sizeof(&hp->amount), &p);
	write_buffer(dst, &hp->remainder, sizeof(&hp->remainder), &p);
}


static void xorbytes(uint8_t *d, const uint8_t *a, const uint8_t *b, size_t len)
{
	size_t i = 0;

	for (i = 0; i < len; i++)
		d[i] = a[i] ^ b[i];
}

/*
 * Encrypt a message `m` of length `mlen` with key `key` and store the
 * ciphertext in `c`. `c` must be pre-allocated to at least `mlen` bytes.
 */
static void stream_encrypt(void *c, const void *m, const size_t mlen, const u8 *key)
{
	u8 nonce[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	memcheck(c, mlen);
	crypto_stream_chacha20_xor(c, m, mlen, nonce, key);
}

/*
 * Decrypt a ciphertext `c` of length `clen` with key `key` and store the
 * cleartext in `m`. `m` must be pre-allocated to at least `clen` bytes.
 */
static void stream_decrypt(void *m, const void *c, const size_t clen, const u8 *key)
{
	stream_encrypt(m, c, clen, key);
}

/*
 * Generate a pseudo-random byte stream of length `dstlen` from key `k` and
 * store it in `dst`. `dst must be at least `dstlen` bytes long.
 */
static void generate_cipher_stream(void *dst, const u8 *k, size_t dstlen)
{
	u8 nonce[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	crypto_stream_chacha20(dst, dstlen, nonce, k);
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

static void compute_packet_hmac(struct onionpacket *packet, u8 *mukey, u8 *hmac)
{
	u8 mactemp[ROUTING_INFO_SIZE + TOTAL_HOP_PAYLOAD_SIZE + MESSAGE_SIZE];

	memcpy(mactemp, packet->routinginfo, ROUTING_INFO_SIZE);
	memcpy(mactemp + ROUTING_INFO_SIZE, packet->hoppayloads, TOTAL_HOP_PAYLOAD_SIZE);
	memcpy(mactemp + ROUTING_INFO_SIZE + TOTAL_HOP_PAYLOAD_SIZE, packet->payload, sizeof(packet->payload));
	compute_hmac(hmac, mactemp, sizeof(mactemp), mukey, KEY_LEN);
}

static bool generate_key(void *k, const char *t, u8 tlen, const u8 *s)
{
	return compute_hmac(k, s, KEY_LEN, t, tlen);
}

static bool generate_header_padding(
	void *dst, size_t dstlen,
	const size_t hopsize,
	const char *keytype,
	size_t keytypelen,
	const u8 numhops,
	struct hop_params *params
	)
{
	int i;
	u8 cipher_stream[(NUM_MAX_HOPS + 1) * hopsize];
	u8 key[KEY_LEN];

	memset(dst, 0, dstlen);
	for (i = 1; i < numhops; i++) {
		if (!generate_key(&key, keytype, keytypelen, params[i - 1].secret))
			return false;

		generate_cipher_stream(cipher_stream, key, sizeof(cipher_stream));
		int pos = ((NUM_MAX_HOPS - i) + 1) * hopsize;
		xorbytes(dst, dst, cipher_stream + pos, sizeof(cipher_stream) - pos);
	}
	return true;
}

static void compute_blinding_factor(secp256k1_context *secpctx,
				    secp256k1_pubkey *key,
				    u8 sharedsecret[SHARED_SECRET_SIZE],
				    u8 res[BLINDING_FACTOR_SIZE])
{
	struct sha256_ctx ctx;
	u8 der[33];
	size_t outputlen = 33;
	struct sha256 temp;

	secp256k1_ec_pubkey_serialize(secpctx, der, &outputlen, key,
				      SECP256K1_EC_COMPRESSED);
	sha256_init(&ctx);
	sha256_update(&ctx, der, sizeof(der));
	sha256_update(&ctx, sharedsecret, SHARED_SECRET_SIZE);
	sha256_done(&ctx, &temp);
	memcpy(res, &temp, 32);
}

static bool blind_group_element(
	secp256k1_context *secpctx,
	secp256k1_pubkey *blindedelement,
	secp256k1_pubkey *pubkey,
	u8 blind[BLINDING_FACTOR_SIZE])
{
	/* tweak_mul is inplace so copy first. */
	if (pubkey != blindedelement)
		memcpy(blindedelement, pubkey, sizeof(secp256k1_pubkey));
	if (secp256k1_ec_pubkey_tweak_mul(secpctx, blindedelement, blind) != 1)
		return false;
	return true;
}

static bool create_shared_secret(
	secp256k1_context *secpctx,
	u8 *secret,
	const secp256k1_pubkey *pubkey,
	const u8 *sessionkey)
{
	/* Need to copy since tweak is in-place */
	secp256k1_pubkey pkcopy;
	u8 ecres[33];

	memcpy(&pkcopy, pubkey, sizeof(pkcopy));

	if (secp256k1_ec_pubkey_tweak_mul(secpctx, &pkcopy, sessionkey) != 1)
		return false;

	/* Serialize and strip first byte, this gives us the X coordinate */
	size_t outputlen = 33;
	secp256k1_ec_pubkey_serialize(secpctx, ecres, &outputlen,
				      &pkcopy, SECP256K1_EC_COMPRESSED);
	struct sha256 h;
	sha256(&h, ecres + 1, sizeof(ecres) - 1);
	memcpy(secret, &h, sizeof(h));
	return true;
}

void pubkey_hash160(
	const secp256k1_context *secpctx,
	u8 *dst,
	const struct pubkey *pubkey)
{
	struct ripemd160 r;
	struct sha256 h;
	u8 der[33];
	size_t outputlen = 33;

	secp256k1_ec_pubkey_serialize(secpctx,
				      der,
				      &outputlen,
				      &pubkey->pubkey,
				      SECP256K1_EC_COMPRESSED);
	sha256(&h, der, sizeof(der));
	ripemd160(&r, h.u.u8, sizeof(h));

	memcpy(dst, r.u.u8, sizeof(r));
}

static void generate_key_set(u8 secret[SHARED_SECRET_SIZE], struct keyset *keys)
{
	generate_key(keys->rho, "rho", 3, secret);
	generate_key(keys->pi, "pi", 2, secret);
	generate_key(keys->mu, "mu", 2, secret);
	generate_key(keys->gamma, "gamma", 5, secret);
}

static struct hop_params *generate_hop_params(
	const tal_t *ctx,
	secp256k1_context *secpctx,
	const u8 *sessionkey,
	struct pubkey path[])
{
	int i, j, num_hops = tal_count(path);
	secp256k1_pubkey temp;
	u8 blind[BLINDING_FACTOR_SIZE];
	struct hop_params *params = tal_arr(ctx, struct hop_params, num_hops);

	/* Initialize the first hop with the raw information */
	if (secp256k1_ec_pubkey_create(
		    secpctx, &params[0].ephemeralkey, sessionkey) != 1)
		return NULL;

	if (!create_shared_secret(
		    secpctx, params[0].secret, &path[0].pubkey, sessionkey))
		return NULL;

	compute_blinding_factor(
		secpctx, &params[0].ephemeralkey, params[0].secret,
		params[0].blind);

	/* Recursively compute all following ephemeral public keys,
	 * secrets and blinding factors
	 */
	for (i = 1; i < num_hops; i++) {
		if (!blind_group_element(
			    secpctx, &params[i].ephemeralkey,
			    &params[i - 1].ephemeralkey,
			    params[i - 1].blind))
			return NULL;

		/* Blind this hop's point with all previous blinding factors
		 * Order is indifferent, multiplication is commutative.
		 */
		memcpy(&blind, sessionkey, 32);
		memcpy(&temp, &path[i], sizeof(temp));
		if (!blind_group_element(secpctx, &temp, &temp, blind))
			return NULL;
		for (j = 0; j < i; j++)
			if (!blind_group_element(
				    secpctx,
				    &temp,
				    &temp,
				    params[j].blind))
				return NULL;

		/* Now hash temp and store it. This requires us to
		 * DER-serialize first and then skip the sign byte.
		 */
		u8 der[33];
		size_t outputlen = 33;
		secp256k1_ec_pubkey_serialize(
			secpctx, der, &outputlen, &temp,
			SECP256K1_EC_COMPRESSED);
		struct sha256 h;
		sha256(&h, der + 1, sizeof(der) - 1);
		memcpy(&params[i].secret, &h, sizeof(h));

		compute_blinding_factor(
			secpctx, &params[i].ephemeralkey,
			params[i].secret, params[i].blind);
	}
	return params;
}

struct onionpacket *create_onionpacket(
	const tal_t *ctx,
	secp256k1_context *secpctx,
	struct pubkey *path,
	struct hoppayload hoppayloads[],
	const u8 *sessionkey,
	const u8 *message,
	const size_t messagelen
	)
{
	struct onionpacket *packet = talz(ctx, struct onionpacket);
	int i, num_hops = tal_count(path);
	u8 filler[2 * (num_hops - 1) * SECURITY_PARAMETER];
	u8 hopfiller[(num_hops - 1) * HOP_PAYLOAD_SIZE];
	struct keyset keys;
	u8 nextaddr[20], nexthmac[SECURITY_PARAMETER];
	u8 stream[ROUTING_INFO_SIZE], hopstream[TOTAL_HOP_PAYLOAD_SIZE];
	struct hop_params *params = generate_hop_params(ctx, secpctx, sessionkey, path);
	u8 binhoppayloads[tal_count(path)][HOP_PAYLOAD_SIZE];

	for (i = 0; i < num_hops; i++)
		serialize_hoppayload(binhoppayloads[i], &hoppayloads[i]);

	if (MESSAGE_SIZE > messagelen) {
		memset(&packet->hoppayloads, 0, TOTAL_HOP_PAYLOAD_SIZE);
#if MESSAGE_SIZE != 0  /* Suppress GCC warning about 0-length memset */
		memset(&packet->payload, 0xFF, MESSAGE_SIZE);
#endif
		memcpy(&packet->payload, message, messagelen);
		packet->payload[messagelen] = 0x7f;
	}

	if (!params)
		return NULL;
	packet->version = 1;
	memset(nextaddr, 0, 20);
	memset(nexthmac, 0, 20);
	memset(packet->routinginfo, 0, ROUTING_INFO_SIZE);

	generate_header_padding(filler, sizeof(filler), 2 * SECURITY_PARAMETER,
				"rho", 3, num_hops, params);
	generate_header_padding(hopfiller, sizeof(hopfiller), HOP_PAYLOAD_SIZE,
				"gamma", 5, num_hops, params);

	for (i = num_hops - 1; i >= 0; i--) {
		generate_key_set(params[i].secret, &keys);
		generate_cipher_stream(stream, keys.rho, ROUTING_INFO_SIZE);

		/* Rightshift mix-header by 2*SECURITY_PARAMETER */
		memmove(packet->routinginfo + 2 * SECURITY_PARAMETER, packet->routinginfo,
			ROUTING_INFO_SIZE - 2 * SECURITY_PARAMETER);
		memcpy(packet->routinginfo, nextaddr, SECURITY_PARAMETER);
		memcpy(packet->routinginfo + SECURITY_PARAMETER, nexthmac, SECURITY_PARAMETER);
		xorbytes(packet->routinginfo, packet->routinginfo, stream, ROUTING_INFO_SIZE);

		/* Rightshift hop-payloads and obfuscate */
		memmove(packet->hoppayloads + HOP_PAYLOAD_SIZE, packet->hoppayloads,
			TOTAL_HOP_PAYLOAD_SIZE - HOP_PAYLOAD_SIZE);
		memcpy(packet->hoppayloads, binhoppayloads[i], HOP_PAYLOAD_SIZE);
		generate_cipher_stream(hopstream, keys.gamma, TOTAL_HOP_PAYLOAD_SIZE);
		xorbytes(packet->hoppayloads, packet->hoppayloads, hopstream,
			 TOTAL_HOP_PAYLOAD_SIZE);

		if (i == num_hops - 1) {
			size_t len = (NUM_MAX_HOPS - num_hops + 1) * 2 * SECURITY_PARAMETER;
			memcpy(packet->routinginfo + len, filler, sizeof(filler));
			len = (NUM_MAX_HOPS - num_hops + 1) * HOP_PAYLOAD_SIZE;
			memcpy(packet->hoppayloads + len, hopfiller, sizeof(hopfiller));
		}

		/* Obfuscate end-to-end payload */
		stream_encrypt(packet->payload, packet->payload, sizeof(packet->payload), keys.pi);

		compute_packet_hmac(packet, keys.mu, nexthmac);
		pubkey_hash160(secpctx, nextaddr, &path[i]);
	}
	memcpy(packet->mac, nexthmac, sizeof(nexthmac));
	memcpy(&packet->ephemeralkey, &params[0].ephemeralkey, sizeof(secp256k1_pubkey));
	return packet;
}

/*
 * Given a onionpacket msg extract the information for the current
 * node and unwrap the remainder so that the node can forward it.
 */
struct route_step *process_onionpacket(
	const tal_t *ctx,
	secp256k1_context *secpctx,
	struct onionpacket *msg,
	struct privkey *hop_privkey
	)
{
	struct route_step *step = talz(ctx, struct route_step);
	u8 secret[SHARED_SECRET_SIZE];
	u8 hmac[20];
	struct keyset keys;
	u8 paddedhoppayloads[TOTAL_HOP_PAYLOAD_SIZE + HOP_PAYLOAD_SIZE];
	u8 hopstream[TOTAL_HOP_PAYLOAD_SIZE + HOP_PAYLOAD_SIZE];
	u8 blind[BLINDING_FACTOR_SIZE];
	u8 stream[NUM_STREAM_BYTES];
	u8 paddedheader[ROUTING_INFO_SIZE + 2 * SECURITY_PARAMETER];

	step->next = talz(step, struct onionpacket);
	step->next->version = msg->version;
	create_shared_secret(secpctx, secret, &msg->ephemeralkey, hop_privkey->secret);
	generate_key_set(secret, &keys);

	compute_packet_hmac(msg, keys.mu, hmac);

	if (memcmp(msg->mac, hmac, sizeof(hmac)) != 0) {
		warnx("Computed MAC does not match expected MAC, the message was modified.");
		return tal_free(step);
	}

	//FIXME:store seen secrets to avoid replay attacks
	generate_cipher_stream(stream, keys.rho, sizeof(stream));

	memset(paddedheader, 0, sizeof(paddedheader));
	memcpy(paddedheader, msg->routinginfo, ROUTING_INFO_SIZE);
	xorbytes(paddedheader, paddedheader, stream, sizeof(stream));

	/* Extract the per-hop payload */
	generate_cipher_stream(hopstream, keys.gamma, sizeof(hopstream));

	memset(paddedhoppayloads, 0, sizeof(paddedhoppayloads));
	memcpy(paddedhoppayloads, msg->hoppayloads, TOTAL_HOP_PAYLOAD_SIZE);
	xorbytes(paddedhoppayloads, paddedhoppayloads, hopstream, sizeof(hopstream));
	step->hoppayload = parse_hoppayload(step, paddedhoppayloads);
	memcpy(&step->next->hoppayloads, paddedhoppayloads + HOP_PAYLOAD_SIZE,
	       TOTAL_HOP_PAYLOAD_SIZE);

	compute_blinding_factor(secpctx, &msg->ephemeralkey, secret, blind);
	if (!blind_group_element(secpctx, &step->next->ephemeralkey, &msg->ephemeralkey, blind))
		return tal_free(step);
	memcpy(&step->next->nexthop, paddedheader, SECURITY_PARAMETER);
	memcpy(&step->next->mac,
	       paddedheader + SECURITY_PARAMETER,
	       SECURITY_PARAMETER);

	stream_decrypt(step->next->payload, msg->payload, sizeof(msg->payload), keys.pi);
	memcpy(&step->next->routinginfo, paddedheader + 2 * SECURITY_PARAMETER, ROUTING_INFO_SIZE);

	if (memeqzero(step->next->mac, sizeof(&step->next->mac))) {
		step->nextcase = ONION_END;
	} else {
		step->nextcase = ONION_FORWARD;
	}

	return step;
}
