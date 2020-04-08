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

/* A single TLV field, consisting of the data and its associated metadata. */
struct tlv_field {
	/* If this is a type that is known to c-lightning we have a pointer to
	 * the metadata. */
	const struct tlv_record_type *meta;

	/* In any case we'll have the numeric type, even if we don't have a
	 * name that we can call it. */
	u64 numtype;
	size_t length;
	u8 *value;
};

/* Append a stream of tlvs: types[] must be in increasing type order! */
void towire_tlvs(u8 **pptr,
		 const struct tlv_record_type types[],
		 size_t num_types,
		 const void *record);

/* Given any tlvstream serialize the raw fields (untyped ones). */
void towire_tlvstream_raw(u8 **pptr, const struct tlv_field *fields);

#endif /* LIGHTNING_WIRE_TLVSTREAM_H */
