#ifndef LIGHTNING_COMMON_BASE32_H
#define LIGHTNING_COMMON_BASE32_H
#include "config.h"
#include <ccan/short_types/short_types.h>


char *b32_encode(char *dst, u8 * src, u8 ver);
void b32_decode(u8 * dst, u8 * src, u8 ver);

#endif /* LIGHTNING_COMMON_BASE32_H */
