#ifndef LIGHTNING_DAEMON_SPHINX_H
#define LIGHTNING_DAEMON_SPHINX_H

#include "config.h"
#include "bitcoin/privkey.h"
#include "bitcoin/pubkey.h"

#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <secp256k1.h>
#include <sodium/randombytes.h>

#define SECURITY_PARAMETER 20
#define NUM_MAX_HOPS 20
#define HOP_PAYLOAD_SIZE 20
#define TOTAL_HOP_PAYLOAD_SIZE (NUM_MAX_HOPS * HOP_PAYLOAD_SIZE)
#define ROUTING_INFO_SIZE (2 * NUM_MAX_HOPS * SECURITY_PARAMETER)
#define TOTAL_PACKET_SIZE (1 + 33 + SECURITY_PARAMETER + ROUTING_INFO_SIZE + \
			   TOTAL_HOP_PAYLOAD_SIZE)

struct onionpacket {
	/* Cleartext information */
	u8 version;
	u8 nexthop[20];
	u8 mac[20];
	secp256k1_pubkey ephemeralkey;

	/* Encrypted information */
	u8 routinginfo[ROUTING_INFO_SIZE];
	u8 hoppayloads[TOTAL_HOP_PAYLOAD_SIZE];
};

enum route_next_case {
	ONION_END = 0,
	ONION_FORWARD = 1,
};

/* FIXME-OLD #4:
 *
 * The format of the per-hop-payload for a version 0 packet is as follows:
```
+----------------+--------------------------+-------------------------------+--------------------------------------------+
| realm (1 byte) | amt_to_forward (8 bytes) | outgoing_cltv_value (4 bytes) | unused_with_v0_version_on_header (7 bytes) |
+----------------+--------------------------+-------------------------------+--------------------------------------------+
```
*/
struct hoppayload {
	u8 realm;
	u64 amt_to_forward;
	u32 outgoing_cltv_value;
	u8 unused_with_v0_version_on_header[7];
};

struct route_step {
	enum route_next_case nextcase;
	struct onionpacket *next;
	struct hoppayload *hoppayload;
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
 * @sessionkey: 20 byte random session key to derive secrets from
 * @assocdata: associated data to commit to in HMACs
 * @assocdatalen: length of the assocdata
 */
struct onionpacket *create_onionpacket(
	const tal_t * ctx,
	struct pubkey path[],
	struct hoppayload hoppayloads[],
	const u8 * sessionkey,
	const u8 *assocdata,
	const size_t assocdatalen
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
 * parese_onionpacket - Parse an onionpacket from a buffer.
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

#endif /* LIGHTNING_DAEMON_SPHINX_H */
