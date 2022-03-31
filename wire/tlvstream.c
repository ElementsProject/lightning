#include "config.h"
#include <ccan/asort/asort.h>
#include <common/bigsize.h>
#include <wire/tlvstream.h>
#include <wire/wire.h>

#ifndef SUPERVERBOSE
#define SUPERVERBOSE(...)
#endif

/* This simply needs to be an address which is neither NULL nor a
 * tal_arr return */
static const u64 dummy;
const u64 *FROMWIRE_TLV_ANY_TYPE = &dummy;

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

void tlvstream_set_raw(struct tlv_field **stream, u64 type, const void *value TAKES, size_t valuelen)
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

/* Get the offset of this field: returns size of msg if not found (or
 * tlv malformed) */
size_t tlv_field_offset(const u8 *tlvstream, size_t tlvlen, u64 fieldtype)
{
	size_t max = tlvlen;
	while (max > 0) {
		u64 type, length;
		size_t field_off = tlvlen - max;

		type = fromwire_bigsize(&tlvstream, &max);
		length = fromwire_bigsize(&tlvstream, &max);

		if (!tlvstream)
			break;

		/* Found it! */
		if (type == fieldtype)
			return field_off;

		if (length > max)
			break;

		max -= length;
		tlvstream += length;
	}
	return tlvlen;
}

static bool tlv_type_is_allowed(const struct tlv_field *f,
				const u64 *extra_types)
{
	/* Simple case: it's an odd field. */
	if (f->numtype % 2 != 0)
		return true;

	if (extra_types == FROMWIRE_TLV_ANY_TYPE)
		return true;

	/* Now iterate through the extras and see if we should make an
	 * exception. */
	for (size_t i = 0; i < tal_count(extra_types); i++)
		if (extra_types[i] == f->numtype)
			return true;
	return false;
}

/* Update err_off to point to current offset. */
static void update_err_off(size_t *err_off, size_t initial_len, size_t max)
{
	if (err_off)
		*err_off = initial_len - max;
}

bool fromwire_tlv(const u8 **cursor, size_t *max,
		  const struct tlv_record_type *types, size_t num_types,
		  void *record, struct tlv_field **fields,
		  const u64 *extra_types,
		  size_t *err_off, u64 *err_type)
{
	bool first = true;
	u64 prev_type = 0;
	size_t initial_len = *max;

	update_err_off(err_off, initial_len, *max);
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
			if (err_type)
				*err_type = 0;
			goto fail;
		}

		/* BOLT #1:
		 *  - if decoded `type`s are not strictly-increasing
		 *    (including situations when two or more occurrences
		 *    of the same `type` are met):
		 *    - MUST fail to parse the `tlv_stream`.
		 */
		if (!first && field.numtype <= prev_type) {
			if (field.numtype == prev_type)
				SUPERVERBOSE("duplicate tlv type");
			else
				SUPERVERBOSE("invalid ordering");
			if (err_type)
				*err_type = field.numtype;
			goto fail;
		}
		first = false;
		prev_type = field.numtype;

		/* BOLT #1:
		 * - if `type` is known:
		 *   - MUST decode the next `length` bytes using the known
		 *     encoding for `type`.
		 */
		field.meta = NULL;
		for (size_t i = 0; i < num_types; i++) {
			if (types[i].type == field.numtype) {
				field.meta = &types[i];
				break;
			}
		}

		if (!field.meta && !tlv_type_is_allowed(&field, extra_types)) {
			SUPERVERBOSE("unknown even");
			if (err_type != NULL)
				*err_type = field.numtype;
			goto fail;
		}

		/* We're happy with type field.  Move on. */
		update_err_off(err_off, initial_len, *max);

		field.length = fromwire_bigsize(cursor, max);

		/* BOLT #1:
		 *  - if a `type` or `length` is not minimally encoded:
		 *    - MUST fail to parse the `tlv_stream`.
		 */
		if (!*cursor) {
			SUPERVERBOSE("length");
			if (err_type)
				*err_type = field.numtype;
			goto fail;
		}

		/* BOLT #1:
		 *  - if `length` exceeds the number of bytes remaining in the
		 *    message:
		 *    - MUST fail to parse the `tlv_stream`.
		 */
		if (field.length > *max) {
			SUPERVERBOSE("value");
			if (err_type)
				*err_type = field.numtype;
			goto fail;
		}

		/* We're happy with length field.  Move on. */
		update_err_off(err_off, initial_len, *max);

		field.value = tal_dup_arr(record, u8, *cursor, field.length, 0);

		if (field.meta) {
			/* Length of message can't exceed 16 bits anyway. */
			size_t tlvlen = field.length;

			/* We're happy with type field.  Move on. */
			update_err_off(err_off, initial_len, *max);

			/* FIXME: We could add an err_off in here for more accuracy. */
			field.meta->fromwire(cursor, &tlvlen, record);

			if (!*cursor) {
				if (err_type != NULL)
					*err_type = field.numtype;
				goto fail;
			}

			/* BOLT #1:
			 *  - if `length` is not exactly equal to that required
			 *    for the known encoding for `type`:
			 *    - MUST fail to parse the `tlv_stream`.
			 */
			if (tlvlen != 0) {
				if (err_type != NULL)
					*err_type = field.numtype;
				SUPERVERBOSE("greater than encoding length");
				goto fail;
			}
		} else {
			/* We're happy with type field.  Move on. */
			update_err_off(err_off, initial_len, *max);

			/* We didn't read from *cursor through a fromwire, so
			 * update manually. */
			*cursor += field.length;
		}
		/* We've read bytes in ->fromwire, so update max */
		*max -= field.length;

		/* We're happy with contents.  Move on. */
		update_err_off(err_off, initial_len, *max);

		tal_arr_expand(fields, field);
	}
	return true;
fail:
	fromwire_fail(cursor, max);
	return false;
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
