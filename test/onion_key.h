#ifndef ONION_KEY_H
#define ONION_KEY_H
#include <ccan/endian/endian.h>
#include "bitcoin/privkey.h"

struct seckey {
	union {
		struct privkey k;
		unsigned char u8[32];
		beint64_t be64[4];
	} u;
};

/* Prepend 0x02 to get pubkey for libsecp256k1 */
struct onion_pubkey {
	unsigned char u8[32];
};

#endif /* ONION_KEY_H */
