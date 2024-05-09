#include "config.h"
#include <ccan/mem/mem.h>
#include <ccan/utf8/utf8.h>
#include <common/decode_array.h>
#include <common/sciddir_or_pubkey.h>
#include <devtools/print_wire.h>
#include <errno.h>
#include <stdio.h>

bool printwire_u8(const char *fieldname, const u8 **cursor, size_t *plen)
{
	u8 v = fromwire_u8(cursor, plen);
	if (!*cursor) {
		printf("**TRUNCATED u8 %s**\n", fieldname);
		return false;
	}
	printf("%u\n", v);
	return true;
}

bool printwire_u16(const char *fieldname, const u8 **cursor, size_t *plen)
{
	u16 v = fromwire_u16(cursor, plen);
	if (!*cursor) {
		printf("**TRUNCATED u16 %s**\n", fieldname);
		return false;
	}
	printf("%u\n", v);
	return true;
}

bool printwire_u32(const char *fieldname, const u8 **cursor, size_t *plen)
{
	u32 v = fromwire_u32(cursor, plen);
	if (!*cursor) {
		printf("**TRUNCATED u32 %s**\n", fieldname);
		return false;
	}
	printf("%u\n", v);
	return true;
}

bool printwire_u64(const char *fieldname, const u8 **cursor, size_t *plen)
{
	u64 v = fromwire_u64(cursor, plen);
	if (!*cursor) {
		printf("**TRUNCATED u64 %s**\n", fieldname);
		return false;
	}
	printf("%"PRIu64"\n", v);
	return true;
}

bool printwire_s8(const char *fieldname, const u8 **cursor, size_t *plen)
{
	s8 v = fromwire_s8(cursor, plen);
	if (!*cursor) {
		printf("**TRUNCATED s64 %s**\n", fieldname);
		return false;
	}
	printf("%d\n", v);
	return true;
}

bool printwire_s16(const char *fieldname, const u8 **cursor, size_t *plen)
{
	s16 v = fromwire_s16(cursor, plen);
	if (!*cursor) {
		printf("**TRUNCATED s64 %s**\n", fieldname);
		return false;
	}
	printf("%d\n", v);
	return true;
}

bool printwire_s32(const char *fieldname, const u8 **cursor, size_t *plen)
{
	s32 v = fromwire_s32(cursor, plen);
	if (!*cursor) {
		printf("**TRUNCATED s64 %s**\n", fieldname);
		return false;
	}
	printf("%d\n", v);
	return true;
}

bool printwire_s64(const char *fieldname, const u8 **cursor, size_t *plen)
{
	s64 v = fromwire_s64(cursor, plen);
	if (!*cursor) {
		printf("**TRUNCATED s64 %s**\n", fieldname);
		return false;
	}
	printf("%"PRId64"\n", v);
	return true;
}

bool printwire_tu16(const char *fieldname, const u8 **cursor, size_t *plen)
{
	u16 v = fromwire_tu16(cursor, plen);
	if (!*cursor) {
		printf("**TRUNCATED tu16 %s**\n", fieldname);
		return false;
	}
	printf("%u\n", v);
	return true;
}

bool printwire_tu32(const char *fieldname, const u8 **cursor, size_t *plen)
{
	u32 v = fromwire_tu32(cursor, plen);
	if (!*cursor) {
		printf("**TRUNCATED tu32 %s**\n", fieldname);
		return false;
	}
	printf("%u\n", v);
	return true;
}

bool printwire_tu64(const char *fieldname, const u8 **cursor, size_t *plen)
{
	u64 v = fromwire_tu64(cursor, plen);
	if (!*cursor) {
		printf("**TRUNCATED tu64 %s**\n", fieldname);
		return false;
	}
	printf("%"PRIu64"\n", v);
	return true;
}

bool printwire_wireaddr(const char *fieldname, const u8 **cursor, size_t *plen)
{
	struct wireaddr w;
	if (!fromwire_wireaddr(cursor, plen, &w))
		return false;
	printf("%s\n", fmt_wireaddr(tmpctx, &w));
	return true;
}

/* Returns false if we ran out of data. */
static bool print_hexstring(const u8 **cursor, size_t *plen, size_t len)
{
	while (len) {
		u8 v = fromwire_u8(cursor, plen);
		if (!*cursor) {
			printf("**TRUNCATED**\n");
			return false;
		}
		printf("%02x", v);
		len--;
	}
	return true;
}

bool printwire_utf8_array(const char *fieldname, const u8 **cursor, size_t *plen, size_t len)
{
	struct utf8_state utf8 = UTF8_STATE_INIT;
	const char *p = (const char *)*cursor;
	bool char_done = true;

	printf("[");
	for (size_t i = 0; i < len; i++) {
		if (!p[i]) {
			if (!memeqzero(p+i, len-i)) {
				printf(" **INVALID PADDING** ");
				goto hexdump;
			}
			break;
		}
		if (utf8_decode(&utf8, p[i])) {
			if (errno != 0) {
				printf(" **INVALID UTF-8** ");
				goto hexdump;
			}
			char_done = true;
		} else {
			/* Don't allow unprintable characters */
			if (utf8.total_len == 1 && !cisprint(utf8.c)) {
				printf(" **UNPRINTABLE CHARACTER** ");
				goto hexdump;
			}
			char_done = false;
		}
	}
	if (!char_done) {
		printf(" **INCOMPLETE UTF-8** ");
		goto hexdump;
	}
	printf("%.*s ", (int)len, p);

hexdump:
	if (!print_hexstring(cursor, plen, len))
		return false;
	printf(" ]\n");
	return true;
}

static bool printwire_addresses(const u8 **cursor, size_t *plen, size_t len)
{
	struct wireaddr addr;
	size_t to_go = len;
	const size_t len_ref = *plen;

	printf("[");
	while (to_go && fromwire_wireaddr(cursor, plen, &addr)) {
		to_go = len - (len_ref - *plen);
		printf(" %s", fmt_wireaddr(NULL, &addr));
	}
	if (!*cursor)
		return false;

	if (to_go) {
		printf(" UNKNOWN:");
		if (!print_hexstring(cursor, plen, len))
			return false;
	}
	printf(" ]\n");
	return true;
}

static bool printwire_encoded_short_ids(const u8 **cursor, size_t *plen, size_t len)
{
	struct short_channel_id *scids;
	u8 *arr = fromwire_tal_arrn(tmpctx, cursor, plen, len);

	if (!arr)
		return false;

	printf("[");
	scids = decode_short_ids(tmpctx, arr);
	if (scids) {
		switch (arr[0]) {
		case ARR_UNCOMPRESSED:
			printf(" (UNCOMPRESSED)");
			break;
		case ARR_ZLIB_DEPRECATED:
			printf(" (ZLIB)");
			break;
		default:
			abort();
		}
		for (size_t i = 0; i < tal_count(scids); i++)
			printf(" %s",
			       fmt_short_channel_id(tmpctx, scids[i]));
	} else {
		/* If it was unknown, that's different from corrupt */
		if (len == 0
		    || arr[0] == ARR_UNCOMPRESSED
		    || arr[0] == ARR_ZLIB_DEPRECATED) {
			printf(" **CORRUPT**");
			return true;
		} else {
			printf(" UNKNOWN:");
			print_hexstring(cursor, plen, len);
		}
	}
	printf(" ]\n");
	return true;
}

bool printwire_u8_array(const char *fieldname, const u8 **cursor, size_t *plen, size_t len)
{
	if (streq(fieldname, "node_announcement.alias"))
		return printwire_utf8_array(fieldname, cursor, plen, len);

	if (streq(fieldname, "node_announcement.addresses"))
		return printwire_addresses(cursor, plen, len);

	if (strends(fieldname, ".encoded_short_ids"))
		return printwire_encoded_short_ids(cursor, plen, len);

	printf("[");
	if (!print_hexstring(cursor, plen, len))
		return false;
	printf("]\n");
	return true;
}

static const struct tlv_print_record_type *
find_print_record_type(u64 type,
		 const struct tlv_print_record_type types[],
		 size_t num_types)
{
	for (size_t i = 0; i < num_types; i++)
		if (types[i].type == type)
			return types + i;
	return NULL;
}

bool printwire_tlvs(const char *fieldname, const u8 **cursor, size_t *plen,
		    const struct tlv_print_record_type types[],
		    size_t num_types)
{
	while (*plen > 0) {
		u64 type, length;
		const struct tlv_print_record_type *ptype;

		type = fromwire_bigsize(cursor, plen);
		if (!*cursor)
			goto fail;
		length = fromwire_bigsize(cursor, plen);
		if (!*cursor)
			goto fail;

		if (length > *plen) {
			*plen = 0;
			goto fail;
		}

		ptype = find_print_record_type(type, types, num_types);
		if (ptype) {
			size_t tlvlen = length;
			printf("{\ntype=%"PRIu64"\nlen=%"PRIu64"\n", type, length);
			ptype->print(fieldname, cursor, &tlvlen);
			if (!*cursor)
				goto fail;
			printf("}\n");
		} else
			printf("**TYPE #%"PRIu64" UNKNOWN for TLV %s**\n", type, fieldname);
		*plen -= length;
	}
	return true;

fail:
	printf("**TRUNCATED TLV %s**\n", fieldname);
	return false;
}

#define PRINTWIRE_TYPE_TO_STRING(T, N)				\
	bool printwire_##N(const char *fieldname, const u8 **cursor,	\
			   size_t *plen)				\
	{								\
		T v;							\
		fromwire_##N(cursor, plen, &v);				\
		if (!*cursor) {						\
			printf("**TRUNCATED " stringify(N) "\n");	\
			return false;					\
		}							\
		const char *s = fmt_##N(NULL, &v);			\
		printf("%s\n", s);					\
		tal_free(s);						\
		return true;						\
	}

#define PRINTWIRE_ASSIGNABLE_STRUCT_TO_STRING(N)			\
	bool printwire_##N(const char *fieldname, const u8 **cursor,	\
			   size_t *plen)				\
	{								\
		struct N v = fromwire_##N(cursor, plen);			\
		if (!*cursor) {						\
			printf("**TRUNCATED " stringify(N) "\n");	\
			return false;					\
		}							\
		const char *s = fmt_##N(NULL, v);			\
		printf("%s\n", s);					\
		tal_free(s);						\
		return true;						\
	}

#define PRINTWIRE_STRUCT_TYPE_TO_STRING(T) \
	PRINTWIRE_TYPE_TO_STRING(struct T, T)

PRINTWIRE_STRUCT_TYPE_TO_STRING(bip340sig)
PRINTWIRE_STRUCT_TYPE_TO_STRING(bitcoin_blkid)
PRINTWIRE_STRUCT_TYPE_TO_STRING(bitcoin_txid)
PRINTWIRE_STRUCT_TYPE_TO_STRING(channel_id)
PRINTWIRE_STRUCT_TYPE_TO_STRING(node_id)
PRINTWIRE_STRUCT_TYPE_TO_STRING(preimage)
PRINTWIRE_STRUCT_TYPE_TO_STRING(pubkey)
PRINTWIRE_STRUCT_TYPE_TO_STRING(sciddir_or_pubkey)
PRINTWIRE_STRUCT_TYPE_TO_STRING(sha256)
PRINTWIRE_STRUCT_TYPE_TO_STRING(secret)
PRINTWIRE_ASSIGNABLE_STRUCT_TO_STRING(short_channel_id)
PRINTWIRE_ASSIGNABLE_STRUCT_TO_STRING(amount_sat)
PRINTWIRE_ASSIGNABLE_STRUCT_TO_STRING(amount_msat)
PRINTWIRE_TYPE_TO_STRING(secp256k1_ecdsa_signature, secp256k1_ecdsa_signature)
