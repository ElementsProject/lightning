#ifndef LIGHTNING_PROTOBUF_CONVERT_H
#define LIGHTNING_PROTOBUF_CONVERT_H
#include "config.h"
#include "lightning.pb-c.h"
#include <ccan/tal/tal.h>
#include <secp256k1.h>
#include <stdbool.h>

/* Convert to-from protobuf to internal representation. */
Signature *signature_to_proto(const tal_t *ctx,
			      const secp256k1_ecdsa_signature *sig);
bool proto_to_signature(const Signature *pb,
			secp256k1_ecdsa_signature *sig);

/* Convert to-from protobuf to internal representation. */
struct pubkey;
BitcoinPubkey *pubkey_to_proto(const tal_t *ctx,
			       const struct pubkey *key);
bool proto_to_pubkey(const BitcoinPubkey *pb, struct pubkey *key);

/* Useful helper for allocating & populating a protobuf Sha256Hash */
struct sha256;
Sha256Hash *sha256_to_proto(const tal_t *ctx, const struct sha256 *hash);
void proto_to_sha256(const Sha256Hash *pb, struct sha256 *hash);

struct preimage;
Preimage *preimage_to_proto(const tal_t *ctx, const struct preimage *r);
void proto_to_preimage(const Preimage *pb, struct preimage *r);

struct rel_locktime;
struct abs_locktime;
bool proto_to_rel_locktime(const Locktime *l, struct rel_locktime *locktime);
bool proto_to_abs_locktime(const Locktime *l, struct abs_locktime *locktime);
Locktime *rel_locktime_to_proto(const tal_t *ctx,
				const struct rel_locktime *locktime);
Locktime *abs_locktime_to_proto(const tal_t *ctx,
				const struct abs_locktime *locktime);

/* Get allocator so decoded protobuf will be tal off it. */
struct ProtobufCAllocator *make_prototal(const tal_t *ctx);
/* Now steal object off of allocator (and free prototal) */
void steal_from_prototal(const tal_t *ctx, struct ProtobufCAllocator *prototal,
			 const void *pb);

#endif /* LIGHTNING_PROTOBUF_CONVERT_H */
