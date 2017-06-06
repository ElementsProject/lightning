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

/* Short Channel ID is composed of 3 bytes for the block height, 3
 * bytes of tx index in block and 2 bytes of output index. The
 * bitfield is mainly for unit tests where it is nice to be able to
 * just memset them and not have to take care about the extra byte for
 * u32 */
struct short_channel_id {
	u32 blocknum : 24;
	u32 txnum : 24;
	u16 outnum;
};
struct channel_id {
	u8 id[32];
};

/* Address types as defined in the lightning specification. Does not
 * match AF_INET and AF_INET6 so we just define our
 * own. ADDR_TYPE_PADDING is also used to signal in the config whether
 * an address is defined at all. */
enum wire_addr_type {
	ADDR_TYPE_PADDING = 0,
	ADDR_TYPE_IPV4 = 1,
	ADDR_TYPE_IPV6 = 2,
};

/* FIXME(cdecker) Extend this once we have defined how TOR addresses
 * should look like */
struct ipaddr {
	enum wire_addr_type type;
	u8 addrlen;
	u8 addr[16];
	u16 port;
};

struct preimage;

void derive_channel_id(struct channel_id *channel_id,
		       struct sha256_double *txid, u16 txout);

/* Read the type; returns -1 if not long enough.  cursor is a tal ptr. */
int fromwire_peektype(const u8 *cursor);
const void *fromwire_fail(const u8 **cursor, size_t *max);

void towire(u8 **pptr, const void *data, size_t len);
void towire_pubkey(u8 **pptr, const struct pubkey *pubkey);
void towire_privkey(u8 **pptr, const struct privkey *privkey);
void towire_secret(u8 **pptr, const struct secret *secret);
void towire_secp256k1_ecdsa_signature(u8 **pptr,
			      const secp256k1_ecdsa_signature *signature);
void towire_channel_id(u8 **pptr, const struct channel_id *channel_id);
void towire_short_channel_id(u8 **pptr,
			     const struct short_channel_id *short_channel_id);
void towire_sha256(u8 **pptr, const struct sha256 *sha256);
void towire_sha256_double(u8 **pptr, const struct sha256_double *sha256d);
void towire_preimage(u8 **pptr, const struct preimage *preimage);
void towire_ipaddr(u8 **pptr, const struct ipaddr *addr);
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
void fromwire_secret(const u8 **cursor, size_t *max, struct secret *secret);
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
void fromwire_ipaddr(const u8 **cursor, size_t *max, struct ipaddr *addr);
void fromwire_pad(const u8 **cursor, size_t *max, size_t num);

void fromwire_u8_array(const u8 **cursor, size_t *max, u8 *arr, size_t num);
#endif /* LIGHTNING_WIRE_WIRE_H */
