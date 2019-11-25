#include "wire/tlvstream.h"
#include <assert.h>
#include <wire/wire.h>

#ifndef SUPERVERBOSE
#define SUPERVERBOSE(...)
#endif

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
