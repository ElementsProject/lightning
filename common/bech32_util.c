#include "config.h"
#include <ccan/tal/str/str.h>
#include <common/bech32.h>
#include <common/bech32_util.h>

static u8 get_bit(const u8 *src, size_t bitoff)
{
        return ((src[bitoff / 8] >> (7 - (bitoff % 8))) & 1);
}

void bech32_push_bits(u5 **data, const void *src, size_t nbits)
{
        size_t i, b;
        size_t data_len = tal_count(*data);

        for (i = 0; i < nbits; i += b) {
                tal_resize(data, data_len+1);
                (*data)[data_len] = 0;
                for (b = 0; b < 5; b++) {
                        (*data)[data_len] <<= 1;
                        /* If we need bits we don't have, zero */
                        if (i+b < nbits)
                                (*data)[data_len] |= get_bit(src, i+b);
                }
                data_len++;
        }
}

static u8 get_u5_bit(const u5 *src, size_t bitoff)
{
        return ((src[bitoff / 5] >> (4 - (bitoff % 5))) & 1);
}

void bech32_pull_bits(u8 **data, const u5 *src, size_t nbits)
{
        size_t i;
        size_t data_len = tal_count(*data);

	/* We discard trailing bits. */
        for (i = 0; i + 8 <= nbits; i += 8) {
                tal_resize(data, data_len+1);
                (*data)[data_len] = 0;
                for (size_t b = 0; b < 8; b++) {
                        (*data)[data_len] <<= 1;
			(*data)[data_len] |= get_u5_bit(src, i+b);
                }
                data_len++;
        }
}

/* Returns a char, tracks case. */
static int fixup_char(int c, bool *upper, bool *lower)
{
	if (c >= 'A' && c <= 'Z') {
		*upper = true;
		return c + ('a' - 'A');
	} else if (c >= 'a' && c <= 'z') {
		*lower = true;
	}
	return c;
}

bool from_bech32_charset(const tal_t *ctx,
			 const char *bech32,
			 size_t bech32_len,
			 char **hrp, u8 **data)
{
	u5 *u5data;
	const char *sep;
	bool upper = false, lower = false;
	size_t datalen;

	sep = memchr(bech32, '1', bech32_len);
	if (!sep)
		return false;

	*hrp = tal_strndup(ctx, bech32, sep - bech32);
	for (size_t i = 0; i < strlen(*hrp); i++)
		(*hrp)[i] = fixup_char((*hrp)[i], &upper, &lower);

	datalen = bech32_len - (sep + 1 - bech32);
	u5data = tal_arr(NULL, u5, datalen);
	for (size_t i = 0; i < datalen; i++) {
		int c = sep[1+i];
		if (c < 0 || c > 128)
			goto fail;
		c = fixup_char(c, &upper, &lower);
		if (bech32_charset_rev[c] == -1)
			goto fail;
		u5data[i] = bech32_charset_rev[c];
	}

	/* Check case consistency */
	if (upper && lower)
		goto fail;

	*data = tal_arr(ctx, u8, 0);
	bech32_pull_bits(data, u5data, tal_bytelen(u5data) * 5);
	tal_free(u5data);
	return true;

fail:
	*hrp = tal_free(*hrp);
	tal_free(u5data);
	return false;
}

char *to_bech32_charset(const tal_t *ctx,
			const char *hrp, const u8 *data)
{
	u5 *u5data = tal_arr(NULL, u5, 0);
	char *ret;

	bech32_push_bits(&u5data, data, tal_bytelen(data) * 8);
	ret = tal_dup_arr(ctx, char, hrp, strlen(hrp),
			  1 + tal_bytelen(u5data) + 1);
	ret[strlen(hrp)] = '1';
	for (size_t i = 0; i < tal_bytelen(u5data); i++)
		ret[strlen(hrp) + 1 + i] = bech32_charset[u5data[i]];
	ret[strlen(hrp) + 1 + tal_bytelen(u5data)] = '\0';
	tal_free(u5data);
	return ret;
}
