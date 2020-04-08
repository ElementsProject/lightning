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
