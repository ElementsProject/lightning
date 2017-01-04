#ifndef LIGHTNING_WIRE_WIRE_H
#define LIGHTNING_WIRE_WIRE_H
#include "config.h"
#include <bitcoin/pubkey.h>
#include <bitcoin/signature.h>
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/short_types/short_types.h>
#include <stdlib.h>

struct pubkey;
struct sha256;
struct channel_id {
	u32 blocknum;
	u32 txnum : 24;
	u8 outnum : 8;
};
struct ipv6 {
	u8 addr[16];
};

/* Read the type; returns -1 if not long enough.  cursor is a tal ptr. */
int fromwire_peektype(const u8 *cursor);

void towire(u8 **pptr, const void *data, size_t len);
void towire_pubkey(u8 **pptr, const struct pubkey *pubkey);
void towire_signature(u8 **pptr, const struct signature *signature);
void towire_channel_id(u8 **pptr, const struct channel_id *channel_id);
void towire_sha256(u8 **pptr, const struct sha256 *sha256);
void towire_ipv6(u8 **pptr, const struct ipv6 *ipv6);
void towire_u8(u8 **pptr, u8 v);
void towire_u16(u8 **pptr, u16 v);
void towire_u32(u8 **pptr, u32 v);
void towire_u64(u8 **pptr, u64 v);
void towire_pad(u8 **pptr, size_t num);

void towire_u8_array(u8 **pptr, const u8 *arr, size_t num);
void towire_signature_array(u8 **pptr, const struct signature *arr, size_t num);


const u8 *fromwire(const u8 **cursor, size_t *max, void *copy, size_t n);
u8 fromwire_u8(const u8 **cursor, size_t *max);
u16 fromwire_u16(const u8 **cursor, size_t *max);
u32 fromwire_u32(const u8 **cursor, size_t *max);
u64 fromwire_u64(const u8 **cursor, size_t *max);
void fromwire_pubkey(const u8 **cursor, size_t *max, struct pubkey *pubkey);
void fromwire_signature(const u8 **cursor, size_t *max,
			struct signature *signature);
void fromwire_channel_id(const u8 **cursor, size_t *max,
			 struct channel_id *channel_id);
void fromwire_sha256(const u8 **cursor, size_t *max, struct sha256 *sha256);
void fromwire_ipv6(const u8 **cursor, size_t *max, struct ipv6 *ipv6);
void fromwire_pad(const u8 **cursor, size_t *max, size_t num);

void fromwire_u8_array(const u8 **cursor, size_t *max,
		       u8 *arr, size_t num);
void fromwire_signature_array(const u8 **cursor, size_t *max,
			      struct signature *arr, size_t num);

#endif /* LIGHTNING_WIRE_WIRE_H */
