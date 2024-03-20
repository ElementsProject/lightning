#ifndef LIGHTNING_WIRE_TLVSTREAM_H
#define LIGHTNING_WIRE_TLVSTREAM_H
#include "config.h"
#include <bitcoin/short_channel_id.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

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
	/* If this is a type that is known to Core Lightning we have a pointer to
	 * the metadata. */
	const struct tlv_record_type *meta;

	/* In any case we'll have the numeric type, even if we don't have a
	 * name that we can call it. */
	u64 numtype;
	size_t length;
	u8 *value;
};

/* Given any tlvstream serialize the raw fields (untyped ones). */
void towire_tlvstream_raw(u8 **pptr, struct tlv_field *fields);

/* Given a tlv record with manually-set fields, populate ->fields */
#define tlv_make_fields(tlv, type)					\
	tlv_make_fields_(tlvs_##type, TLVS_ARRAY_SIZE_##type, (tlv))

struct tlv_field *tlv_make_fields_(const struct tlv_record_type *types,
				   size_t num_types,
				   const void *record);

/**
 * fromwire_tlv: generic TLV decode engine
 * @cursor: cursor to update (set to NULL if we fail).
 * @max: max len to update (always set to 0 if we succeed).
 * @types / @num_types: table of known tlv types
 * @record: the tlv to hand to @type-specific decode
 * @fields: the fields array to populate
 * @extra_types: tal_arr of unknown types to allow, or NULL, or FROMWIRE_TLV_ANY_TYPE.
 * @err_off: NULL, or set to offset in tlv stream which failed.
 * @err_type: NULL, or set to tlv type which failed (or 0 if malformed)
 */
bool fromwire_tlv(const u8 **cursor, size_t *max,
		  const struct tlv_record_type *types, size_t num_types,
		  void *record, struct tlv_field **fields,
		  const u64 *extra_types, size_t *err_off, u64 *err_type);
void towire_tlv(u8 **pptr,
		const struct tlv_record_type *types, size_t num_types,
		const void *record);

/* Get the offset of this field: returns size of msg if not found (or
 * tlv malformed) */
size_t tlv_field_offset(const u8 *tlvstream, size_t tlvlen, u64 fieldtype);

/* Constant for fromwire_tlv to allow absolutely any unknown type. */
extern const u64 *FROMWIRE_TLV_ANY_TYPE;

/* Generic primitive setters for tlvstreams. */
void tlvstream_set_raw(struct tlv_field **stream, u64 type, const void *value TAKES, size_t valuelen);
void tlvstream_set_short_channel_id(struct tlv_field **stream, u64 type,
				    struct short_channel_id value);
void tlvstream_set_tu64(struct tlv_field **stream, u64 type, u64 value);
void tlvstream_set_tu32(struct tlv_field **stream, u64 type, u32 value);

#endif /* LIGHTNING_WIRE_TLVSTREAM_H */
