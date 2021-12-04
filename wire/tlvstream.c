#include "config.h"
#include <ccan/asort/asort.h>
#include <common/bigsize.h>
#include <wire/tlvstream.h>
#include <wire/wire.h>

#ifndef SUPERVERBOSE
#define SUPERVERBOSE(...)
#endif

static int tlv_field_cmp(const struct tlv_field *a, const struct tlv_field *b,
			 void *x)
{
	return a->numtype > b->numtype ? 1 : -1;
}

void towire_tlvstream_raw(u8 **pptr, struct tlv_field *fields)
{
	if (!fields)
		return;

	asort(fields, tal_count(fields), tlv_field_cmp, NULL);

	for (size_t i = 0; i < tal_count(fields); i++) {
		const struct tlv_field *field = &fields[i];
		/* BOLT #1:
		 *
		 * The sending node:
		 ...
		 *  - MUST minimally encode `type` and `length`.
		 */
		towire_bigsize(pptr, field->numtype);
		towire_bigsize(pptr, field->length);
		towire(pptr, field->value, field->length);
	}
}

static struct tlv_field *tlvstream_get_raw(struct tlv_field *stream, u64 type)
{
	for (size_t i=0; i<tal_count(stream); i++)
		if (stream[i].numtype == type)
			return &stream[i];
	return NULL;
}

void tlvstream_set_raw(struct tlv_field **stream, u64 type, void *value TAKES, size_t valuelen)
{
	struct tlv_field f, *e = tlvstream_get_raw(*stream, type);

	if (e != NULL) {
		tal_free(e->value);
		e->length = valuelen;
		e->value = tal_dup_arr(*stream, u8, value, e->length, 0);
	} else {
		/* If we haven't found it insert it insead. */
		f.length = valuelen;
		f.numtype = type;
		f.value = tal_dup_arr(*stream, u8, value, f.length, 0);
		tal_arr_expand(stream, f);
	}
}

void tlvstream_set_short_channel_id(struct tlv_field **stream, u64 type,
				    struct short_channel_id *value)
{
	u8 *ser = tal_arr(NULL, u8, 0);
	towire_short_channel_id(&ser, value);
	tlvstream_set_raw(stream, type, take(ser), tal_bytelen(ser));
}

void tlvstream_set_tu64(struct tlv_field **stream, u64 type, u64 value)
{
	u8 *ser = tal_arr(NULL, u8, 0);
	towire_tu64(&ser, value);
	tlvstream_set_raw(stream, type, take(ser), tal_bytelen(ser));
}

void tlvstream_set_tu32(struct tlv_field **stream, u64 type, u32 value)
{
	u8 *ser = tal_arr(NULL, u8, 0);
	towire_tu64(&ser, value);
	tlvstream_set_raw(stream, type, take(ser), tal_bytelen(ser));
}

bool fromwire_tlv(const u8 **cursor, size_t *max,
		  const struct tlv_record_type *types, size_t num_types,
		  void *record, struct tlv_field **fields)
{
	while (*max > 0) {
		struct tlv_field field;

		/* BOLT #1:
		 *
		 * The `type` is encoded using the BigSize format.
		 */
		field.numtype = fromwire_bigsize(cursor, max);

		/* BOLT #1:
		 *  - if a `type` or `length` is not minimally encoded:
		 *    - MUST fail to parse the `tlv_stream`.
		 */
		if (!*cursor) {
			SUPERVERBOSE("type");
			goto fail;
		}
		field.length = fromwire_bigsize(cursor, max);

		/* BOLT #1:
		 *  - if a `type` or `length` is not minimally encoded:
		 *    - MUST fail to parse the `tlv_stream`.
		 */
		if (!*cursor) {
			SUPERVERBOSE("length");
			goto fail;
		}

		/* BOLT #1:
		 *  - if `length` exceeds the number of bytes remaining in the
		 *    message:
		 *    - MUST fail to parse the `tlv_stream`.
		 */
		if (field.length > *max) {
			SUPERVERBOSE("value");
			goto fail;
		}
		field.value = tal_dup_arr(record, u8, *cursor, field.length, 0);

		/* BOLT #1:
		 * - if `type` is known:
		 *   - MUST decode the next `length` bytes using the known
		 *     encoding for `type`.
		 */
		field.meta = NULL;
		for (size_t i = 0; i < num_types; i++) {
			if (types[i].type == field.numtype)
				field.meta = &types[i];
		}

		if (field.meta) {
			/* Length of message can't exceed 16 bits anyway. */
			size_t tlvlen = field.length;
			field.meta->fromwire(cursor, &tlvlen, record);

			if (!*cursor)
				goto fail;

			/* BOLT #1:
			 *  - if `length` is not exactly equal to that required
			 *    for the known encoding for `type`:
			 *    - MUST fail to parse the `tlv_stream`.
			 */
			if (tlvlen != 0) {
				SUPERVERBOSE("greater than encoding length");
				goto fail;
			}
		} else {
			/* We didn't read from *cursor through a fromwire, so
			 * update manually. */
			*cursor += field.length;
		}
		/* We've read bytes in ->fromwire, so update max */
		*max -= field.length;
		tal_arr_expand(fields, field);
	}
	return true;
fail:
	fromwire_fail(cursor, max);
	return false;
}

static bool tlv_type_is_allowed(const struct tlv_field *f, u64 *extra_types) {
	/* Simple case: we have internal meta fields or it's an odd field. */
	if (f->numtype % 2 != 0 || f->meta != NULL)
		return true;

	if (extra_types == NULL)
		return false;

	/* Now iterate through the extras and see if we should make an
	 * exception. */
	for (size_t i = 0; i < tal_count(extra_types); i++)
		if (extra_types[i] == f->numtype)
			return true;
	return false;
}

bool tlv_fields_valid(const struct tlv_field *fields, u64 *allow_extra,
		      size_t *err_index)
{
	size_t numfields = tal_count(fields);
	bool first = true;
	u64 prev_type = 0;
	for (int i=0; i<numfields; i++) {
		const struct tlv_field *f = &fields[i];
		if (!tlv_type_is_allowed(f, allow_extra)) {
			/* BOLT #1:
			 * - otherwise, if `type` is unknown:
			 *   - if `type` is even:
			 *     - MUST fail to parse the `tlv_stream`.
			 *   - otherwise, if `type` is odd:
			 *     - MUST discard the next `length` bytes.
			 */
			SUPERVERBOSE("unknown even");
			if (err_index != NULL)
				*err_index = i;
			return false;
		} else if (!first && f->numtype <= prev_type) {
			/* BOLT #1:
			 *  - if decoded `type`s are not strictly-increasing
			 *    (including situations when two or more occurrences
			 *    of the same `type` are met):
			 *    - MUST fail to parse the `tlv_stream`.
			 */
			if (f->numtype == prev_type)
				SUPERVERBOSE("duplicate tlv type");
			else
				SUPERVERBOSE("invalid ordering");
			if (err_index != NULL)
				*err_index = i;
			return false;
		}
		first = false;
		prev_type = f->numtype;
	}
	return true;
}

void towire_tlv(u8 **pptr,
		const struct tlv_record_type *types, size_t num_types,
		const void *record)
{
	if (!record)
		return;

	for (size_t i = 0; i < num_types; i++) {
		u8 *val;
		if (i != 0)
			assert(types[i].type > types[i-1].type);
		val = types[i].towire(NULL, record);
		if (!val)
			continue;

		/* BOLT #1:
		 *
		 * The sending node:
		 ...
		 *  - MUST minimally encode `type` and `length`.
		 */
		towire_bigsize(pptr, types[i].type);
		towire_bigsize(pptr, tal_bytelen(val));
		towire(pptr, val, tal_bytelen(val));
		tal_free(val);
	}
}

struct tlv_field *tlv_make_fields_(const struct tlv_record_type *types,
				   size_t num_types,
				   const void *record)
{
	struct tlv_field *fields = tal_arr(record, struct tlv_field, 0);

	for (size_t i = 0; i < num_types; i++) {
		struct tlv_field f;
		u8 *val;
		if (i != 0)
			assert(types[i].type > types[i-1].type);
		val = types[i].towire(NULL, record);
		if (!val)
			continue;

		f.meta = &types[i];
		f.numtype = types[i].type;
		f.length = tal_bytelen(val);
		f.value = tal_steal(fields, val);
		tal_arr_expand(&fields, f);
	}
	return fields;
}
