#include <common/bigsize.h>
#include <wire/tlvstream.h>
#include <wire/wire.h>

void towire_tlvstream_raw(u8 **pptr, const struct tlv_field *fields)
{
	if (!fields)
		return;

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

void tlvstream_set_raw(struct tlv_field **stream, u64 type, void *value, size_t valuelen)
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
	tlvstream_set_raw(stream, type, ser, tal_bytelen(ser));
}

void tlvstream_set_tu64(struct tlv_field **stream, u64 type, u64 value)
{
	u8 *ser = tal_arr(NULL, u8, 0);
	towire_tu64(&ser, value);
	tlvstream_set_raw(stream, type, ser, tal_bytelen(ser));
}

void tlvstream_set_tu32(struct tlv_field **stream, u64 type, u32 value)
{
	u8 *ser = tal_arr(NULL, u8, 0);
	towire_tu64(&ser, value);
	tlvstream_set_raw(stream, type, ser, tal_bytelen(ser));
}

bool tlvstream_get_short_channel_id(struct tlv_field *stream, u64 type,
				    struct short_channel_id *value)
{
	struct tlv_field *raw = tlvstream_get_raw(stream, type);
	const u8 *v;
	size_t max;
	if (raw == NULL || raw->length != 8)
		return false;

	max = raw->length;
	v = raw->value;
	fromwire_short_channel_id(&v, &max, value);

	return true;
}

bool tlvstream_get_tu64(struct tlv_field *stream, u64 type, u64 *value)
{
	struct tlv_field *raw = tlvstream_get_raw(stream, type);
	const u8 *v;
	size_t max;
	if (raw == NULL || raw->length != 8)
		return false;

	max = raw->length;
	v = raw->value;
	*value = fromwire_tu64(&v, &max);

	return true;
}

bool tlvstream_get_tu32(struct tlv_field *stream, u64 type, u32 *value)
{
	struct tlv_field *raw = tlvstream_get_raw(stream, type);
	const u8 *v;
	size_t max;
	if (raw == NULL || raw->length != 8)
		return false;

	max = raw->length;
	v = raw->value;
	*value = fromwire_tu64(&v, &max);
	return true;
}
