#ifndef LIGHTNING_WIRE_TLVSTREAM_H
#define LIGHTNING_WIRE_TLVSTREAM_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <stdbool.h>
#include <stdlib.h>

struct tlv_record_type {
	u64 type;
	/* If this type is present return marshalled value.  Otherwise
	 * returns NULL. */
	u8 *(*towire)(const tal_t *ctx, const void *record);
	/* Must call fromwire_fail() if it can't parse. */
	void (*fromwire)(const u8 **cursor, size_t *max, void *record);
};

/* Pull all tlvs from a stream.  Return false and calls fromwire_fail() on
 * error. */
bool fromwire_tlvs(const u8 **cursor, size_t *max,
		   const struct tlv_record_type types[],
		   size_t num_types,
		   void *record);

/* Append a stream of tlvs: types[] must be in increasing type order! */
void towire_tlvs(u8 **pptr,
		 const struct tlv_record_type types[],
		 size_t num_types,
		 const void *record);

#endif /* LIGHTNING_WIRE_TLVSTREAM_H */
