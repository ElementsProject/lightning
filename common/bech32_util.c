#include "bech32_util.h"
#include <ccan/tal/tal.h>

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
