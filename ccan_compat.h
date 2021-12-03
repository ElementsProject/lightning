#ifndef LIGHTNING_CCAN_COMPAT_H
#define LIGHTNING_CCAN_COMPAT_H

/* Magical file included from config.h (ie. everywhere) which renames
 * sha256 routines so they don't clash with libwally-core's internal ones */

/* So, for obvious reasons, this is an exception to the usual rule that we
#include "config.h"
 * in all files. */
#define sha256(sha, p, size) ccan_sha256(sha, p, size)
#define sha256_init(ctx) ccan_sha256_init(ctx)
#define sha256_update(ctx, p, size) ccan_sha256_update(ctx, p, size)
#define sha256_done(sha256, res) ccan_sha256_done(sha256, res)
#define sha256_u8(ctx, v) ccan_sha256_u8(ctx, v)
#define sha256_u16(ctx, v) ccan_sha256_u16(ctx, v)
#define sha256_u32(ctx, v) ccan_sha256_u32(ctx, v)
#define sha256_u64(ctx, v) ccan_sha256_u64(ctx, v)
#define sha256_le16(ctx, v) ccan_sha256_le16(ctx, v)
#define sha256_le32(ctx, v) ccan_sha256_le32(ctx, v)
#define sha256_le64(ctx, v) ccan_sha256_le64(ctx, v)
#define sha256_be16(ctx, v) ccan_sha256_be16(ctx, v)
#define sha256_be32(ctx, v) ccan_sha256_be32(ctx, v)
#define sha256_be64(ctx, v) ccan_sha256_be64(ctx, v)
#endif /* LIGHTNING_CCAN_COMPAT_H */
