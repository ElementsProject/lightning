#ifndef LIGHTNING_COMMON_SPHINX_H
#define LIGHTNING_COMMON_SPHINX_H

#include "config.h"
#include "bitcoin/privkey.h"
#include "bitcoin/pubkey.h"

#include <common/hmac.h>
#include <wire/onion_wire.h>

struct node_id;

#define VERSION_SIZE 1
#define REALM_SIZE 1
#define HMAC_SIZE 32
#define PUBKEY_SIZE 33
#define FRAME_SIZE 65
#define ROUTING_INFO_SIZE 1300
#define TOTAL_PACKET_SIZE(payload) (VERSION_SIZE + PUBKEY_SIZE + (payload) + HMAC_SIZE)

struct onionpacket {
	/* Cleartext information */
	u8 version;
	struct hmac hmac;
	struct pubkey ephemeralkey;

	/* Encrypted information (tal arr)*/
	u8 *routinginfo;
};

struct sphinx_compressed_onion {
	u8 version;
	struct pubkey ephemeralkey;
	u8 *routinginfo;
	struct hmac hmac;
};


enum route_next_case {
	ONION_END = 0,
	ONION_FORWARD = 1,
};

/**
 * A sphinx payment path.
 *
 * This struct defines a path a payment is taking through the Lightning
 * Network, including the session_key used to generate secrets, the associated
 * data that'll be included in the HMACs and the payloads at each hop in the
 * path. The struct is opaque since it should not be modified externally. Use
 * `sphinx_path_new` or `sphinx_path_new_with_key` (testing only) to create a
 * new instance.
 */
struct sphinx_path;

/*
 * All the necessary information to generate a valid onion for this hop on a
 * sphinx path. The payload is preserialized in order since the onion
 * generation is payload agnostic. */
struct sphinx_hop {
	struct pubkey pubkey;
	const u8 *raw_payload;
	struct hmac hmac;
};

struct route_step {
	enum route_next_case nextcase;
	struct onionpacket *next;
	u8 *raw_payload;
};

/**
 * create_onionpacket - Create a new onionpacket that can be routed
 * over a path of intermediate nodes.
 *
 * @ctx: tal context to allocate from
 * @sphinx_path: path to encode along.
 * @fixed_size: the size of the onion packet eg ROUTING_INFO_SIZE (fails if input is larger)
 * @secrets: (out) shared secrets generated for the entire path
 */
struct onionpacket *create_onionpacket(
	const tal_t * ctx,
	struct sphinx_path *sp,
	size_t fixed_size,
	struct secret **path_secrets
	);

/**
 * onion_shared_secret - calculate ECDH shared secret between nodes.
 *
 * @secret: the shared secret
 * @pubkey: the public key of the other node
 * @privkey: the private key of this node (32 bytes long)
 */
bool onion_shared_secret(
	struct secret *secret,
	const struct onionpacket *packet,
	const struct privkey *privkey);

/**
 * process_onionpacket - process an incoming packet by stripping one
 * onion layer and return the packet for the next hop.
 *
 * @ctx: tal context to allocate from
 * @packet: incoming packet being processed
 * @shared_secret: the result of onion_shared_secret.
 * @hoppayload: the per-hop payload destined for the processing node.
 * @assocdata: associated data to commit to in HMACs
 * @assocdatalen: length of the assocdata
 */
struct route_step *process_onionpacket(
	const tal_t * ctx,
	const struct onionpacket *packet,
	const struct secret *shared_secret,
	const u8 *assocdata,
	const size_t assocdatalen);

/**
 * serialize_onionpacket - Serialize an onionpacket to a buffer.
 *
 * @ctx: tal context to allocate from
 * @packet: the packet to serialize
 */
u8 *serialize_onionpacket(
	const tal_t *ctx,
	const struct onionpacket *packet);

/**
 * parse_onionpacket - Parse an onionpacket from a buffer.
 *
 * @ctx: the context to allocate return value from.
 * @src: buffer to read the packet from
 * @srclen: length of the @src (must be TOTAL_PACKET_SIZE)
 * @failcode: the failure code (set iff this returns NULL)
 */
struct onionpacket *parse_onionpacket(const tal_t *ctx,
				      const u8 *src,
				      const size_t srclen,
				      enum onion_wire *failcode);

/**
 * create_onionreply - Format a failure message so we can return it
 *
 * @ctx: tal context to allocate from
 * @shared_secret: The shared secret used in the forward direction, used for the
 *     HMAC
 * @failure_msg: message (must support tal_len)
 */
struct onionreply *create_onionreply(const tal_t *ctx,
				     const struct secret *shared_secret,
				     const u8 *failure_msg);

/**
 * wrap_onionreply - Add another encryption layer to the reply.
 *
 * @ctx: tal context to allocate from
 * @shared_secret: the shared secret associated with the HTLC, used for the
 *     encryption.
 * @reply: the reply to wrap
 */
struct onionreply *wrap_onionreply(const tal_t *ctx,
				   const struct secret *shared_secret,
				   const struct onionreply *reply);

/**
 * unwrap_onionreply - Remove layers, check integrity and parse reply
 *
 * @ctx: tal context to allocate from
 * @shared_secrets: shared secrets from the forward path
 * @numhops: path length and number of shared_secrets provided
 * @reply: the incoming reply
 * @origin_index: the index in the path where the reply came from (-1 if unknown)
 *
 * Reverses create_onionreply and wrap_onionreply.
 */
u8 *unwrap_onionreply(const tal_t *ctx,
		      const struct secret *shared_secrets,
		      const int numhops,
		      const struct onionreply *reply,
		      int *origin_index);

/**
 * Create a new empty sphinx_path.
 *
 * The sphinx_path instance can then be decorated with other functions and
 * passed to `create_onionpacket` to generate the packet.
 */
struct sphinx_path *sphinx_path_new(const tal_t *ctx,
				    const u8 *associated_data);

/**
 * Create a new empty sphinx_path with a given `session_key`.
 *
 * This MUST NOT be used outside of tests and tools as it may leak the path
 * details if the `session_key` is not randomly generated.
 */
struct sphinx_path *sphinx_path_new_with_key(const tal_t *ctx,
					     const u8 *associated_data,
					     const struct secret *session_key);

/**
 * Add a payload hop to the path (already has length prepended).
 *
 * Fails if length actually isn't prepended!
 */
bool sphinx_add_hop_has_length(struct sphinx_path *path, const struct pubkey *pubkey,
			       const u8 *payload TAKES);

/**
 * Prepend length to payload and add: for onionmessage, any size is OK,
 * for HTLC onions tal_bytelen(payload) must be > 1.
 */
void sphinx_add_hop(struct sphinx_path *path, const struct pubkey *pubkey,
		    const u8 *payload TAKES);

/**
 * Do not use, function is cursed.
 */
void sphinx_add_v0_hop(struct sphinx_path *path, const struct pubkey *pubkey,
		       const struct short_channel_id *scid,
		       struct amount_msat forward, u32 outgoing_cltv);

/**
 * Compute the size of the serialized payloads.
 */
size_t sphinx_path_payloads_size(const struct sphinx_path *path);

/**
 * Set the rendez-vous node_id and make the onion generated from the
 * sphinx_path compressible. To unset pass in a NULL rendezvous_id.
 *
 * Returns false if there was an error converting from the node_id to a public
 * key.
 */
bool sphinx_path_set_rendezvous(struct sphinx_path *sp,
				const struct node_id *rendezvous_id);

/**
 * Given a compressed onion expand it by re-generating the prefiller and
 * inserting it in the appropriate place.
 */
struct onionpacket *sphinx_decompress(const tal_t *ctx,
				      const struct sphinx_compressed_onion *src,
				      const struct secret *shared_secret);

/**
 * Use ECDH to generate a shared secret from a privkey and a pubkey.
 *
 * Sphinx uses shared secrets derived from a private key and a public key
 * using ECDH in a number of places. This is a simple wrapper around the
 * secp256k1 functions, with our internal types.
 */
bool sphinx_create_shared_secret(struct secret *privkey,
				 const struct pubkey *pubkey,
				 const struct secret *secret);


/**
 * Given a compressible onionpacket, return the compressed version.
 */
struct sphinx_compressed_onion *
sphinx_compress(const tal_t *ctx, const struct onionpacket *packet,
		const struct sphinx_path *path);

u8 *sphinx_compressed_onion_serialize(
    const tal_t *ctx, const struct sphinx_compressed_onion *onion);

struct sphinx_compressed_onion *
sphinx_compressed_onion_deserialize(const tal_t *ctx, const u8 *src);

/* Override to force us to reject valid onion packets */
extern bool dev_fail_process_onionpacket;

/* Override to set custom onion error lengths. */
extern unsigned dev_onion_reply_length;

#endif /* LIGHTNING_COMMON_SPHINX_H */
