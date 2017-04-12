#ifndef LIGHTNING_WIRE_WIRE_H
#define LIGHTNING_WIRE_WIRE_H
#include "config.h"
#include <bitcoin/privkey.h>
#include <bitcoin/pubkey.h>
#include <bitcoin/shadouble.h>
#include <bitcoin/signature.h>
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/short_types/short_types.h>
#include <stdlib.h>

struct short_channel_id {
	u32 blocknum;
	u32 txnum : 24;
	u8 outnum : 8;
};
struct channel_id {
	u8 id[32];
};
struct ipv6 {
	u8 addr[16];
};
struct preimage;

void derive_channel_id(struct channel_id *channel_id,
		       struct sha256_double *txid, u16 txout);

/* Read the type; returns -1 if not long enough.  cursor is a tal ptr. */
int fromwire_peektype(const u8 *cursor);

void towire(u8 **pptr, const void *data, size_t len);
void towire_pubkey(u8 **pptr, const struct pubkey *pubkey);
void towire_privkey(u8 **pptr, const struct privkey *privkey);
void towire_secp256k1_ecdsa_signature(u8 **pptr,
			      const secp256k1_ecdsa_signature *signature);
void towire_channel_id(u8 **pptr, const struct channel_id *channel_id);
void towire_short_channel_id(u8 **pptr,
			     const struct short_channel_id *short_channel_id);
void towire_sha256(u8 **pptr, const struct sha256 *sha256);
void towire_sha256_double(u8 **pptr, const struct sha256_double *sha256d);
void towire_preimage(u8 **pptr, const struct preimage *preimage);
void towire_ipv6(u8 **pptr, const struct ipv6 *ipv6);
void towire_u8(u8 **pptr, u8 v);
void towire_u16(u8 **pptr, u16 v);
void towire_u32(u8 **pptr, u32 v);
void towire_u64(u8 **pptr, u64 v);
void towire_pad(u8 **pptr, size_t num);
void towire_bool(u8 **pptr, bool v);

void towire_u8_array(u8 **pptr, const u8 *arr, size_t num);

const u8 *fromwire(const u8 **cursor, size_t *max, void *copy, size_t n);
u8 fromwire_u8(const u8 **cursor, size_t *max);
u16 fromwire_u16(const u8 **cursor, size_t *max);
u32 fromwire_u32(const u8 **cursor, size_t *max);
u64 fromwire_u64(const u8 **cursor, size_t *max);
bool fromwire_bool(const u8 **cursor, size_t *max);
void fromwire_privkey(const u8 **cursor, size_t *max, struct privkey *privkey);
void fromwire_pubkey(const u8 **cursor, size_t *max, struct pubkey *pubkey);
void fromwire_secp256k1_ecdsa_signature(const u8 **cursor, size_t *max,
					secp256k1_ecdsa_signature *signature);
void fromwire_channel_id(const u8 **cursor, size_t *max,
			 struct channel_id *channel_id);
void fromwire_short_channel_id(const u8 **cursor, size_t *max,
			       struct short_channel_id *short_channel_id);
void fromwire_sha256(const u8 **cursor, size_t *max, struct sha256 *sha256);
void fromwire_sha256_double(const u8 **cursor, size_t *max,
			    struct sha256_double *sha256d);
void fromwire_preimage(const u8 **cursor, size_t *max, struct preimage *preimage);
void fromwire_ipv6(const u8 **cursor, size_t *max, struct ipv6 *ipv6);
void fromwire_pad(const u8 **cursor, size_t *max, size_t num);

void fromwire_u8_array(const u8 **cursor, size_t *max, u8 *arr, size_t num);
#endif /* LIGHTNING_WIRE_WIRE_H */
