#include <assert.h>

#include <ccan/crypto/ripemd160/ripemd160.h>
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/mem/mem.h>
#include <common/sphinx.h>
#include <common/utils.h>

#include <err.h>

#include <secp256k1_ecdh.h>

#include <sodium/crypto_auth_hmacsha256.h>
#include <sodium/crypto_stream_chacha20.h>

#define BLINDING_FACTOR_SIZE 32
#define SHARED_SECRET_SIZE 32
#define HMAC_SIZE 32

#define NUM_STREAM_BYTES ((NUM_MAX_HOPS + 1) * HOP_DATA_SIZE)
#define KEY_LEN 32
#define ONION_REPLY_SIZE 256

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
	const struct onionpacket *m)
{
	u8 *dst = tal_arr(ctx, u8, TOTAL_PACKET_SIZE);

	u8 der[33];
	size_t outputlen = 33;
	int p = 0;

	secp256k1_ec_pubkey_serialize(secp256k1_ctx,
				      der,
				      &outputlen,
				      &m->ephemeralkey,
				      SECP256K1_EC_COMPRESSED);

	write_buffer(dst, &m->version, 1, &p);
	write_buffer(dst, der, outputlen, &p);
	write_buffer(dst, m->routinginfo, ROUTING_INFO_SIZE, &p);
	write_buffer(dst, m->mac, sizeof(m->mac), &p);
	return dst;
}

struct onionpacket *parse_onionpacket(
	const tal_t *ctx,
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
	if (m->version != 0x00) {
		// FIXME add logging
		return tal_free(m);
	}
	read_buffer(rawEphemeralkey, src, 33, &p);

	if (secp256k1_ec_pubkey_parse(secp256k1_ctx, &m->ephemeralkey, rawEphemeralkey, 33) != 1)
		return tal_free(m);

	read_buffer(&m->routinginfo, src, ROUTING_INFO_SIZE, &p);
	read_buffer(&m->mac, src, SECURITY_PARAMETER, &p);
	return m;
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
	memcpy(hmac, mac, SECURITY_PARAMETER);
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

static void compute_blinding_factor(const secp256k1_pubkey *key,
				    const u8 sharedsecret[SHARED_SECRET_SIZE],
				    u8 res[BLINDING_FACTOR_SIZE])
{
	struct sha256_ctx ctx;
	u8 der[33];
	size_t outputlen = 33;
	struct sha256 temp;

	secp256k1_ec_pubkey_serialize(secp256k1_ctx, der, &outputlen, key,
				      SECP256K1_EC_COMPRESSED);
	sha256_init(&ctx);
	sha256_update(&ctx, der, sizeof(der));
	sha256_update(&ctx, sharedsecret, SHARED_SECRET_SIZE);
	sha256_done(&ctx, &temp);
	memcpy(res, &temp, 32);
}

static bool blind_group_element(
	secp256k1_pubkey *blindedelement,
	const secp256k1_pubkey *pubkey,
	const u8 blind[BLINDING_FACTOR_SIZE])
{
	/* tweak_mul is inplace so copy first. */
	if (pubkey != blindedelement)
		*blindedelement = *pubkey;
	if (secp256k1_ec_pubkey_tweak_mul(secp256k1_ctx, blindedelement, blind) != 1)
		return false;
	return true;
}

static bool create_shared_secret(
	u8 *secret,
	const secp256k1_pubkey *pubkey,
	const u8 *sessionkey)
{

	if (secp256k1_ecdh(secp256k1_ctx, secret, pubkey, sessionkey) != 1)
		return false;
	return true;
}

bool onion_shared_secret(
	u8 *secret,
	const struct onionpacket *packet,
	const struct privkey *privkey)
{
	return create_shared_secret(secret, &packet->ephemeralkey,
				    privkey->secret.data);
}

static void generate_key_set(const u8 secret[SHARED_SECRET_SIZE],
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
	struct pubkey path[])
{
	int i, j, num_hops = tal_count(path);
	secp256k1_pubkey temp;
	u8 blind[BLINDING_FACTOR_SIZE];
	struct hop_params *params = tal_arr(ctx, struct hop_params, num_hops);

	/* Initialize the first hop with the raw information */
	if (secp256k1_ec_pubkey_create(
		    secp256k1_ctx, &params[0].ephemeralkey, sessionkey) != 1)
		return NULL;

	if (!create_shared_secret(
		    params[0].secret, &path[0].pubkey, sessionkey))
		return NULL;

	compute_blinding_factor(
		&params[0].ephemeralkey, params[0].secret,
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
		temp = path[i].pubkey;
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
		u8 der[33];
		size_t outputlen = 33;
		secp256k1_ec_pubkey_serialize(
			secp256k1_ctx, der, &outputlen, &temp,
			SECP256K1_EC_COMPRESSED);
		struct sha256 h;
		sha256(&h, der, sizeof(der));
		memcpy(&params[i].secret, &h, sizeof(h));

		compute_blinding_factor(
			&params[i].ephemeralkey,
			params[i].secret, params[i].blind);
	}
	return params;
}

static void serialize_hop_data(tal_t *ctx, u8 *dst, const struct hop_data *data)
{
	u8 *buf = tal_arr(ctx, u8, 0);
	towire_u8(&buf, data->realm);
	towire_short_channel_id(&buf, &data->channel_id);
	towire_u64(&buf, data->amt_forward);
	towire_u32(&buf, data->outgoing_cltv);
	towire_pad(&buf, 12);
	towire(&buf, data->hmac, SECURITY_PARAMETER);
	memcpy(dst, buf, tal_count(buf));
	tal_free(buf);
}

static void deserialize_hop_data(struct hop_data *data, const u8 *src)
{
	const u8 *cursor = src;
	size_t max = HOP_DATA_SIZE;
	data->realm = fromwire_u8(&cursor, &max);
	fromwire_short_channel_id(&cursor, &max, &data->channel_id);
	data->amt_forward = fromwire_u64(&cursor, &max);
	data->outgoing_cltv = fromwire_u32(&cursor, &max);
	fromwire_pad(&cursor, &max, 12);
	fromwire(&cursor, &max, &data->hmac, SECURITY_PARAMETER);
}

struct onionpacket *create_onionpacket(
	const tal_t *ctx,
	struct pubkey *path,
	struct hop_data hops_data[],
	const u8 *sessionkey,
	const u8 *assocdata,
	const size_t assocdatalen,
	struct secret **path_secrets
	)
{
	struct onionpacket *packet = talz(ctx, struct onionpacket);
	int i, num_hops = tal_count(path);
	u8 filler[(num_hops - 1) * HOP_DATA_SIZE];
	struct keyset keys;
	u8 nexthmac[SECURITY_PARAMETER];
	u8 stream[ROUTING_INFO_SIZE];
	struct hop_params *params = generate_hop_params(ctx, sessionkey, path);
	struct secret *secrets = tal_arr(ctx, struct secret, num_hops);

	if (!params) {
		tal_free(packet);
		tal_free(secrets);
		return NULL;
	}
	packet->version = 0;
	memset(nexthmac, 0, SECURITY_PARAMETER);
	memset(packet->routinginfo, 0, ROUTING_INFO_SIZE);

	generate_header_padding(filler, sizeof(filler), HOP_DATA_SIZE,
				"rho", 3, num_hops, params);

	for (i = num_hops - 1; i >= 0; i--) {
		memcpy(hops_data[i].hmac, nexthmac, SECURITY_PARAMETER);
		hops_data[i].realm = 0;
		generate_key_set(params[i].secret, &keys);
		generate_cipher_stream(stream, keys.rho, ROUTING_INFO_SIZE);

		/* Rightshift mix-header by 2*SECURITY_PARAMETER */
		memmove(packet->routinginfo + HOP_DATA_SIZE, packet->routinginfo,
			ROUTING_INFO_SIZE - HOP_DATA_SIZE);
		serialize_hop_data(packet, packet->routinginfo, &hops_data[i]);
		xorbytes(packet->routinginfo, packet->routinginfo, stream, ROUTING_INFO_SIZE);

		if (i == num_hops - 1) {
			size_t len = (NUM_MAX_HOPS - num_hops + 1) * HOP_DATA_SIZE;
			memcpy(packet->routinginfo + len, filler, sizeof(filler));
		}

		compute_packet_hmac(packet, assocdata, assocdatalen, keys.mu,
				    nexthmac);
	}
	memcpy(packet->mac, nexthmac, sizeof(nexthmac));
	memcpy(&packet->ephemeralkey, &params[0].ephemeralkey, sizeof(secp256k1_pubkey));

	for (i=0; i<num_hops; i++) {
		memcpy(&secrets[i], params[i].secret, SHARED_SECRET_SIZE);
	}

	*path_secrets = secrets;
	return packet;
}

/*
 * Given an onionpacket msg extract the information for the current
 * node and unwrap the remainder so that the node can forward it.
 */
struct route_step *process_onionpacket(
	const tal_t *ctx,
	const struct onionpacket *msg,
	const u8 *shared_secret,
	const u8 *assocdata,
	const size_t assocdatalen
	)
{
	struct route_step *step = talz(ctx, struct route_step);
	u8 hmac[SECURITY_PARAMETER];
	struct keyset keys;
	u8 blind[BLINDING_FACTOR_SIZE];
	u8 stream[NUM_STREAM_BYTES];
	u8 paddedheader[ROUTING_INFO_SIZE + HOP_DATA_SIZE];

	step->next = talz(step, struct onionpacket);
	step->next->version = msg->version;
	generate_key_set(shared_secret, &keys);

	compute_packet_hmac(msg, assocdata, assocdatalen, keys.mu, hmac);

	if (memcmp(msg->mac, hmac, sizeof(hmac)) != 0) {
		/* Computed MAC does not match expected MAC, the message was modified. */
		return tal_free(step);
	}

	//FIXME:store seen secrets to avoid replay attacks
	generate_cipher_stream(stream, keys.rho, sizeof(stream));

	memset(paddedheader, 0, sizeof(paddedheader));
	memcpy(paddedheader, msg->routinginfo, ROUTING_INFO_SIZE);
	xorbytes(paddedheader, paddedheader, stream, sizeof(stream));

	compute_blinding_factor(&msg->ephemeralkey, shared_secret, blind);
	if (!blind_group_element(&step->next->ephemeralkey, &msg->ephemeralkey, blind))
		return tal_free(step);

	deserialize_hop_data(&step->hop_data, paddedheader);

        memcpy(&step->next->mac, step->hop_data.hmac, SECURITY_PARAMETER);

	memcpy(&step->next->routinginfo, paddedheader + HOP_DATA_SIZE, ROUTING_INFO_SIZE);

	if (memeqzero(step->next->mac, sizeof(step->next->mac))) {
		step->nextcase = ONION_END;
	} else {
		step->nextcase = ONION_FORWARD;
	}

	return step;
}

u8 *create_onionreply(const tal_t *ctx, const struct secret *shared_secret,
		      const u8 *failure_msg)
{
	size_t msglen = tal_count(failure_msg);
	size_t padlen = ONION_REPLY_SIZE - msglen;
	u8 *reply = tal_arr(ctx, u8, 0), *payload = tal_arr(ctx, u8, 0);
	u8 key[KEY_LEN];
	u8 hmac[HMAC_SIZE];

	/* BOLT #4:
	 *
	 * The node generating the error message (_erring node_) builds a return
	 * packet consisting of
	 * the following fields:
	 *
	 * 1. data:
	 *    * [`32`:`hmac`]
	 *    * [`2`:`failure_len`]
	 *    * [`failure_len`:`failuremsg`]
	 *    * [`2`:`pad_len`]
	 *    * [`pad_len`:`pad`]
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
	generate_key(key, "um", 2, shared_secret->data);

	compute_hmac(hmac, payload, tal_count(payload), key, KEY_LEN);
	towire(&reply, hmac, sizeof(hmac));

	towire(&reply, payload, tal_count(payload));
	tal_free(payload);

	return reply;
}

u8 *wrap_onionreply(const tal_t *ctx,
		    const struct secret *shared_secret, const u8 *reply)
{
	u8 key[KEY_LEN];
	size_t streamlen = tal_count(reply);
	u8 stream[streamlen];
	u8 *result = tal_arr(ctx, u8, streamlen);

	/* BOLT #4:
	 *
	 * The erring node then generates a new key, using the key type `ammag`.
	 * This key is then used to generate a pseudo-random stream, which is
	 * in turn applied to the packet using `XOR`.
	 *
	 * The obfuscation step is repeated by every hop along the return path.
	 */
	generate_key(key, "ammag", 5, shared_secret->data);
	generate_cipher_stream(stream, key, streamlen);
	xorbytes(result, stream, reply, streamlen);
	return result;
}

struct onionreply *unwrap_onionreply(const tal_t *ctx,
				     const struct secret *shared_secrets,
				     const int numhops, const u8 *reply)
{
	struct onionreply *oreply = tal(tmpctx, struct onionreply);
	u8 *msg = tal_arr(oreply, u8, tal_count(reply));
	u8 key[KEY_LEN], hmac[HMAC_SIZE];
	const u8 *cursor;
	size_t max;
	u16 msglen;

	if (tal_count(reply) != ONION_REPLY_SIZE + sizeof(hmac) + 4) {
		return NULL;
	}

	memcpy(msg, reply, tal_count(reply));
	oreply->origin_index = -1;

	for (int i = 0; i < numhops; i++) {
		/* Since the encryption is just XORing with the cipher
		 * stream encryption is identical to decryption */
		msg = wrap_onionreply(tmpctx, &shared_secrets[i], msg);

		/* Check if the HMAC matches, this means that this is
		 * the origin */
		generate_key(key, "um", 2, shared_secrets[i].data);
		compute_hmac(hmac, msg + sizeof(hmac),
			     tal_count(msg) - sizeof(hmac), key, KEY_LEN);
		if (memcmp(hmac, msg, sizeof(hmac)) == 0) {
			oreply->origin_index = i;
			break;
		}
	}
	if (oreply->origin_index == -1) {
		return NULL;
	}

	cursor = msg + sizeof(hmac);
	max = tal_count(msg) - sizeof(hmac);
	msglen = fromwire_u16(&cursor, &max);

	if (msglen > ONION_REPLY_SIZE) {
		return NULL;
	}

	oreply->msg = tal_arr(oreply, u8, msglen);
	fromwire(&cursor, &max, oreply->msg, msglen);

	tal_steal(ctx, oreply);
	return oreply;

}
