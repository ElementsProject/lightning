#ifndef LIGHTNING_DAEMON_SPHINX_H
#define LIGHTNING_DAEMON_SPHINX_H

#include "config.h"
#include "bitcoin/privkey.h"
#include "bitcoin/pubkey.h"

#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <secp256k1.h>
#include <sodium/randombytes.h>
#include <wire/wire.h>

#define SECURITY_PARAMETER 32
#define NUM_MAX_HOPS 20
#define PAYLOAD_SIZE 32
#define HOP_DATA_SIZE (1 + SECURITY_PARAMETER + PAYLOAD_SIZE)
#define ROUTING_INFO_SIZE (HOP_DATA_SIZE * NUM_MAX_HOPS)
#define TOTAL_PACKET_SIZE (1 + 33 + SECURITY_PARAMETER + ROUTING_INFO_SIZE)

struct onionpacket {
	/* Cleartext information */
	u8 version;
	u8 mac[SECURITY_PARAMETER];
	secp256k1_pubkey ephemeralkey;

	/* Encrypted information */
	u8 routinginfo[ROUTING_INFO_SIZE];
};

enum route_next_case {
	ONION_END = 0,
	ONION_FORWARD = 1,
};

/* BOLT #4:
 *
 * The `hops_data` field is a structure that holds obfuscated versions of the
 * next hop's address, transfer information and the associated HMAC. It is
 * 1300 bytes long, and has the following structure:
 *
 * 1. type: `hops_data`
 * 2. data:
 *    * [`1`:`realm`]
 *    * [`32`:`per_hop`]
 *    * [`32`:`HMAC`]
 *    * ...
 *    * `filler`
 *
 * Where the `realm`, `HMAC` and `per_hop` (whose contents depend on `realm`)
 * are repeated for each hop, and `filler` consists of obfuscated
 * deterministically generated padding. For details about how the `filler` is
 * generated please see below. In addition, `hops_data` is incrementally
 * obfuscated at each hop.
 *
 * The `realm` byte determines the format of the `per_hop`; so far only
 * `realm` 0 is defined, and for that, the `per_hop` format is:
 *
 * 1. type: `per_hop` (for `realm` 0)
 * 2. data:
 *    * [`8`:`channel_id`]
 *    * [`8`:`amt_to_forward`]
 *    * [`4`:`outgoing_cltv_value`]
 *    * [`12`:`padding`]
 */
struct hop_data {
	u8 realm;
	struct short_channel_id channel_id;
	u32 amt_forward;
	u32 outgoing_cltv;
	/* Padding omitted, will be zeroed */
	u8 hmac[SECURITY_PARAMETER];
};

struct route_step {
	enum route_next_case nextcase;
	struct onionpacket *next;
	struct hop_data hop_data;
};

/**
 * create_onionpacket - Create a new onionpacket that can be routed
 * over a path of intermediate nodes.
 *
 * @ctx: tal context to allocate from
 * @path: public keys of nodes along the path.
 * @hoppayloads: payloads destined for individual hosts (limited to
 *    HOP_PAYLOAD_SIZE bytes)
 * @num_hops: path length in nodes
 * @sessionkey: 32 byte random session key to derive secrets from
 * @assocdata: associated data to commit to in HMACs
 * @assocdatalen: length of the assocdata
 * @path_secrets: (out) shared secrets generated for the entire path
 */
struct onionpacket *create_onionpacket(
	const tal_t * ctx,
	struct pubkey path[],
	struct hop_data hops_data[],
	const u8 * sessionkey,
	const u8 *assocdata,
	const size_t assocdatalen,
	struct secret **path_secrets
	);

/**
 * onion_shared_secret - calculate ECDH shared secret between nodes.
 *
 * @secret: the shared secret (32 bytes long)
 * @pubkey: the public key of the other node
 * @privkey: the private key of this node (32 bytes long)
 */
bool onion_shared_secret(
	u8 *secret,
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
	const u8 *shared_secret,
	const u8 *assocdata,
	const size_t assocdatalen
	);

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
 * @ctx: tal context to allocate from
 * @src: buffer to read the packet from
 * @srclen: length of the @src
 */
struct onionpacket *parse_onionpacket(
	const tal_t *ctx,
	const void *src,
	const size_t srclen
	);

void pubkey_hash160(
	u8 *dst,
	const struct pubkey *pubkey);

struct onionreply {
	/* Node index in the path that is replying */
	int origin_index;
	u8 *msg;
};

/**
 * create_onionreply - Format a failure message so we can return it
 *
 * @ctx: tal context to allocate from
 * @shared_secret: The shared secret used in the forward direction, used for the
 *     HMAC
 * @failure_msg: message (must support tal_len)
 */
u8 *create_onionreply(const tal_t *ctx, const struct secret *shared_secret,
		      const u8 *failure_msg);

/**
 * wrap_onionreply - Add another encryption layer to the reply.
 *
 * @ctx: tal context to allocate from
 * @shared_secret: the shared secret associated with the HTLC, used for the
 *     encryption.
 * @reply: the reply to wrap
 */
u8 *wrap_onionreply(const tal_t *ctx, const struct secret *shared_secret,
		    const u8 *reply);

/**
 * unwrap_onionreply - Remove layers, check integrity and parse reply
 *
 * @ctx: tal context to allocate from
 * @shared_secrets: shared secrets from the forward path
 * @numhops: path length and number of shared_secrets provided
 * @reply: the incoming reply
 */
struct onionreply *unwrap_onionreply(const tal_t *ctx,
				     const struct secret *shared_secrets,
				     const int numhops, const u8 *reply);

#endif /* LIGHTNING_DAEMON_SPHINX_H */
