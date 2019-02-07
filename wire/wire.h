#ifndef LIGHTNING_WIRE_WIRE_H
#define LIGHTNING_WIRE_WIRE_H
#include "config.h"
#include <bitcoin/block.h>
#include <bitcoin/privkey.h>
#include <bitcoin/pubkey.h>
#include <bitcoin/shadouble.h>
#include <bitcoin/short_channel_id.h>
#include <bitcoin/signature.h>
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/short_types/short_types.h>
#include <ccan/structeq/structeq.h>
#include <secp256k1_recovery.h>
#include <stdlib.h>

struct channel_id {
	u8 id[32];
};
/* Define channel_id_eq (no padding) */
STRUCTEQ_DEF(channel_id, 0, id);

struct bitcoin_blkid;
struct bitcoin_signature;
struct bitcoin_txid;
struct preimage;
struct ripemd160;
struct siphash_seed;

/* Makes generate-wire.py work */
typedef char wirestring;

void derive_channel_id(struct channel_id *channel_id,
		       const struct bitcoin_txid *txid, u16 txout);

/* Read the type; returns -1 if not long enough.  cursor is a tal ptr. */
int fromwire_peektype(const u8 *cursor);
const void *fromwire_fail(const u8 **cursor, size_t *max);

void towire(u8 **pptr, const void *data, size_t len);
void towire_pubkey(u8 **pptr, const struct pubkey *pubkey);
void towire_privkey(u8 **pptr, const struct privkey *privkey);
void towire_secret(u8 **pptr, const struct secret *secret);
void towire_secp256k1_ecdsa_signature(u8 **pptr,
			      const secp256k1_ecdsa_signature *signature);
void towire_secp256k1_ecdsa_recoverable_signature(u8 **pptr,
			      const secp256k1_ecdsa_recoverable_signature *rsig);
void towire_channel_id(u8 **pptr, const struct channel_id *channel_id);
void towire_short_channel_id(u8 **pptr,
			     const struct short_channel_id *short_channel_id);
void towire_short_channel_id_dir(u8 **pptr,
				 const struct short_channel_id_dir *scidd);
void towire_sha256(u8 **pptr, const struct sha256 *sha256);
void towire_sha256_double(u8 **pptr, const struct sha256_double *sha256d);
void towire_bitcoin_txid(u8 **pptr, const struct bitcoin_txid *txid);
void towire_bitcoin_signature(u8 **pptr, const struct bitcoin_signature *sig);
void towire_bitcoin_blkid(u8 **pptr, const struct bitcoin_blkid *blkid);
void towire_preimage(u8 **pptr, const struct preimage *preimage);
void towire_ripemd160(u8 **pptr, const struct ripemd160 *ripemd);
void towire_u8(u8 **pptr, u8 v);
void towire_u16(u8 **pptr, u16 v);
void towire_u32(u8 **pptr, u32 v);
void towire_u64(u8 **pptr, u64 v);
void towire_double(u8 **pptr, const double *v);
void towire_pad(u8 **pptr, size_t num);
void towire_bool(u8 **pptr, bool v);

void towire_u8_array(u8 **pptr, const u8 *arr, size_t num);

void towire_bitcoin_tx(u8 **pptr, const struct bitcoin_tx *tx);
void towire_wirestring(u8 **pptr, const char *str);
void towire_siphash_seed(u8 **cursor, const struct siphash_seed *seed);

const u8 *fromwire(const u8 **cursor, size_t *max, void *copy, size_t n);
u8 fromwire_u8(const u8 **cursor, size_t *max);
u16 fromwire_u16(const u8 **cursor, size_t *max);
u32 fromwire_u32(const u8 **cursor, size_t *max);
u64 fromwire_u64(const u8 **cursor, size_t *max);
void fromwire_double(const u8 **cursor, size_t *max, double *v);
bool fromwire_bool(const u8 **cursor, size_t *max);
void fromwire_secret(const u8 **cursor, size_t *max, struct secret *secret);
void fromwire_privkey(const u8 **cursor, size_t *max, struct privkey *privkey);
void fromwire_pubkey(const u8 **cursor, size_t *max, struct pubkey *pubkey);
void fromwire_secp256k1_ecdsa_signature(const u8 **cursor, size_t *max,
					secp256k1_ecdsa_signature *signature);
void fromwire_secp256k1_ecdsa_recoverable_signature(const u8 **cursor,
				    size_t *max,
				    secp256k1_ecdsa_recoverable_signature *rsig);
void fromwire_channel_id(const u8 **cursor, size_t *max,
			 struct channel_id *channel_id);
void fromwire_short_channel_id(const u8 **cursor, size_t *max,
			       struct short_channel_id *short_channel_id);
void fromwire_short_channel_id_dir(const u8 **cursor, size_t *max,
				   struct short_channel_id_dir *scidd);
void fromwire_sha256(const u8 **cursor, size_t *max, struct sha256 *sha256);
void fromwire_sha256_double(const u8 **cursor, size_t *max,
			    struct sha256_double *sha256d);
void fromwire_bitcoin_signature(const u8 **cursor, size_t *max,
				struct bitcoin_signature *sig);
void fromwire_bitcoin_txid(const u8 **cursor, size_t *max,
			   struct bitcoin_txid *txid);
void fromwire_bitcoin_blkid(const u8 **cursor, size_t *max,
			   struct bitcoin_blkid *blkid);
void fromwire_preimage(const u8 **cursor, size_t *max, struct preimage *preimage);
void fromwire_ripemd160(const u8 **cursor, size_t *max, struct ripemd160 *ripemd);
void fromwire_pad(const u8 **cursor, size_t *max, size_t num);

void fromwire_u8_array(const u8 **cursor, size_t *max, u8 *arr, size_t num);
char *fromwire_wirestring(const tal_t *ctx, const u8 **cursor, size_t *max);
struct bitcoin_tx *fromwire_bitcoin_tx(const tal_t *ctx,
				       const u8 **cursor, size_t *max);
void fromwire_siphash_seed(const u8 **cursor, size_t *max,
			   struct siphash_seed *seed);
#endif /* LIGHTNING_WIRE_WIRE_H */
