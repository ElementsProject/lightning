#include "wire/tlvstream.h"
#include <assert.h>
#include <wire/wire.h>

#ifndef SUPERVERBOSE
#define SUPERVERBOSE(...)
#endif

static const struct tlv_record_type *
find_record_type(u64 type,
		 const struct tlv_record_type types[],
		 size_t num_types)
{
	for (size_t i = 0; i < num_types; i++)
		if (types[i].type == type)
			return types + i;
	return NULL;
}

/* Pull all tlvs from a stream.  Return false and calls fromwire_fail() on
 * error. */
bool fromwire_tlvs(const u8 **cursor, size_t *max,
		   const struct tlv_record_type types[],
		   size_t num_types,
		   void *record)
{
	/* prev_type points to prev_type_store after first iter. */
	u64 prev_type_store, *prev_type = NULL;

	/* BOLT #1:
	 *
	 * The receiving node:
	 *  - if zero bytes remain before parsing a `type`:
	 *    - MUST stop parsing the `tlv_stream`.
	 */
	while (*max > 0) {
		u64 type, length;
		const struct tlv_record_type *rtype;

		/* BOLT #1:
		 *
		 * A `varint` is a variable-length, unsigned integer encoding
		 * using the [BigSize](#appendix-a-bigsize-test-vectors)
		 * format
		 */
		type = fromwire_bigsize(cursor, max);

		/* BOLT #1:
		 *  - if a `type` or `length` is not minimally encoded:
		 *    - MUST fail to parse the `tlv_stream`.
		 */
		if (!*cursor) {
			SUPERVERBOSE("type");
			goto fail;
		}
		length = fromwire_bigsize(cursor, max);

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
		if (length > *max) {
			SUPERVERBOSE("value");
			goto fail;
		}

		/* BOLT #1:
		 *  - if decoded `type`s are not monotonically-increasing:
		 *    - MUST fail to parse the `tlv_stream`.
		 */
		if (prev_type && type <= *prev_type) {
			if (type == *prev_type)
				SUPERVERBOSE("duplicate tlv type");
			else
				SUPERVERBOSE("invalid ordering");
			goto fail;
		}

		/* BOLT #1:
		 * - if `type` is known:
		 *   - MUST decode the next `length` bytes using the known
		 *     encoding for `type`.
		 */
		rtype = find_record_type(type, types, num_types);
		if (rtype) {
			/* Length of message can't exceed 16 bits anyway. */
			size_t tlvlen = length;
			rtype->fromwire(cursor, &tlvlen, record);

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

			/* We've read bytes in ->fromwire, so update max */
			*max -= length;
		} else {
			/* BOLT #1:
			 * - otherwise, if `type` is unknown:
			 *   - if `type` is even:
			 *     - MUST fail to parse the `tlv_stream`.
			 *   - otherwise, if `type` is odd:
			 *     - MUST discard the next `length` bytes.
			 */
			if (type & 1)
				fromwire(cursor, max, NULL, length);
			else {
				SUPERVERBOSE("unknown even");
				goto fail;
			}
		}
		prev_type = &prev_type_store;
		*prev_type = type;
	}
	return true;

fail:
	fromwire_fail(cursor, max);
	return false;
}

/* Append a stream of tlvs. */
void towire_tlvs(u8 **pptr,
		 const struct tlv_record_type types[],
		 size_t num_types,
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
