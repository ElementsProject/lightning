#include <common/type_to_string.h>
#include <devtools/print_wire.h>
#include <inttypes.h>
#include <stdio.h>

void printwire_u8(const u8 *v)
{
	printf("%u", *v);
}

void printwire_u16(const u16 *v)
{
	printf("%u", *v);
}

void printwire_u32(const u32 *v)
{
	printf("%u", *v);
}

void printwire_u64(const u64 *v)
{
	printf("%"PRIu64, *v);
}

void printwire_u8_array(const u8 **cursor, size_t *plen, size_t len)
{
	printf("[");
	while (len) {
		u8 v = fromwire_u8(cursor, plen);
		if (!*cursor)
			return;
		if (isprint(v))
			printf("%c", v);
		else
			printf("\\x%02x", v);
		len--;
	}
	printf("]\n");
}

#define PRINTWIRE_TYPE_TO_STRING(T, N)					\
	void printwire_##N(const T *v)					\
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
