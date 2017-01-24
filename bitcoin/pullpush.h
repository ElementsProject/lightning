#ifndef LIGHTNING_BITCOIN_PULLPUSH_H
#define LIGHTNING_BITCOIN_PULLPUSH_H
#include "config.h"
#include "bitcoin/varint.h"
#include <ccan/tal/tal.h>

void push_varint(varint_t v,
		 void (*push)(const void *, size_t, void *), void *pushp);
void push_le32(u32 v, void (*push)(const void *, size_t, void *), void *pushp);
void push_le64(u64 v, void (*push)(const void *, size_t, void *), void *pushp);
void push_varint_blob(const tal_t *blob,
		      void (*push)(const void *, size_t, void *),
		      void *pushp);

u64 pull_varint(const u8 **cursor, size_t *max);
u32 pull_le32(const u8 **cursor, size_t *max);
u64 pull_le64(const u8 **cursor, size_t *max);

/* This extends **pptr by tal_resize */
void push(const void *data, size_t len, void *pptr_);
const u8 *pull(const u8 **cursor, size_t *max, void *copy, size_t n);

#endif /* LIGHTNING_BITCOIN_PULLPUSH_H */
