#include <ccan/mem/mem.h>
#include <ccan/utf8/utf8.h>
#include <common/type_to_string.h>
#include <devtools/print_wire.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>

void printwire_u8(const char *fieldname, const u8 *v)
{
	printf("%u\n", *v);
}

void printwire_u16(const char *fieldname, const u16 *v)
{
	printf("%u\n", *v);
}

void printwire_u32(const char *fieldname, const u32 *v)
{
	printf("%u\n", *v);
}

void printwire_u64(const char *fieldname, const u64 *v)
{
	printf("%"PRIu64"\n", *v);
}

/* Returns false if we ran out of data. */
static bool print_hexstring(const u8 **cursor, size_t *plen, size_t len)
{
	while (len) {
		u8 v = fromwire_u8(cursor, plen);
		if (!*cursor)
			return false;
		printf("%02x", v);
		len--;
	}
	return true;
}

static void printwire_alias(const u8 **cursor, size_t *plen, size_t len)
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
		return;
	printf(" ]\n");
	return;
}

static void printwire_addresses(const u8 **cursor, size_t *plen, size_t len)
{
	struct wireaddr addr;

	printf("[");
	while (*plen && fromwire_wireaddr(cursor, plen, &addr))
		printf(" %s", fmt_wireaddr(NULL, &addr));
	if (!*cursor)
		return;

	if (*plen != 0) {
		printf(" UNKNOWN:");
		if (!print_hexstring(cursor, plen, len))
			return;
	}
	printf(" ]\n");
}

void printwire_u8_array(const char *fieldname, const u8 **cursor, size_t *plen, size_t len)
{
	if (streq(fieldname, "node_announcement.alias")) {
		printwire_alias(cursor, plen, len);
		return;
	}
	if (streq(fieldname, "node_announcement.addresses")) {
		printwire_addresses(cursor, plen, len);
		return;
	}

	printf("[");
	if (!print_hexstring(cursor, plen, len))
		return;
	printf("]\n");
}

#define PRINTWIRE_TYPE_TO_STRING(T, N)					\
	void printwire_##N(const char *fieldname, const T *v)		\
	{								\
		const char *s = type_to_string(NULL, T, v);		\
		printf("%s\n", s);					\
		tal_free(s);						\
	}

#define PRINTWIRE_STRUCT_TYPE_TO_STRING(T) \
	PRINTWIRE_TYPE_TO_STRING(struct T, T)

PRINTWIRE_STRUCT_TYPE_TO_STRING(bitcoin_blkid);
PRINTWIRE_STRUCT_TYPE_TO_STRING(bitcoin_txid);
PRINTWIRE_STRUCT_TYPE_TO_STRING(channel_id);
PRINTWIRE_STRUCT_TYPE_TO_STRING(preimage);
PRINTWIRE_STRUCT_TYPE_TO_STRING(pubkey);
PRINTWIRE_STRUCT_TYPE_TO_STRING(sha256);
PRINTWIRE_STRUCT_TYPE_TO_STRING(short_channel_id);
PRINTWIRE_TYPE_TO_STRING(secp256k1_ecdsa_signature, secp256k1_ecdsa_signature);
