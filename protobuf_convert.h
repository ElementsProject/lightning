#ifndef LIGHTNING_PROTOBUF_CONVERT_H
#define LIGHTNING_PROTOBUF_CONVERT_H
#include <ccan/tal/tal.h>
#include <stdbool.h>
#include "lightning.pb-c.h"

/* Convert to-from protobuf to internal representation. */
struct signature;
Signature *signature_to_proto(const tal_t *ctx, const struct signature *sig);
bool proto_to_signature(const Signature *pb, struct signature *sig);

/* Convert to-from protobuf to internal representation. */
struct pubkey;
BitcoinPubkey *pubkey_to_proto(const tal_t *ctx, const struct pubkey *key);
bool proto_to_pubkey(const BitcoinPubkey *pb, struct pubkey *key);

/* Useful helper for allocating & populating a protobuf Sha256Hash */
struct sha256;
Sha256Hash *sha256_to_proto(const tal_t *ctx, const struct sha256 *hash);
void proto_to_sha256(const Sha256Hash *pb, struct sha256 *hash);

struct rel_locktime;
struct abs_locktime;
bool proto_to_rel_locktime(const Locktime *l, struct rel_locktime *locktime);
bool proto_to_abs_locktime(const Locktime *l, struct abs_locktime *locktime);
#endif /* LIGHTNING_PROTOBUF_CONVERT_H */
