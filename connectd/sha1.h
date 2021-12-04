#ifndef LIGHTNING_CONNECTD_SHA1_H
#define LIGHTNING_CONNECTD_SHA1_H
#include "config.h"
#include <stdint.h>
#include <stdlib.h>

extern int sha1digest(uint8_t *digest, const uint8_t *data, size_t databytes);

#endif /* LIGHTNING_CONNECTD_SHA1_H */
