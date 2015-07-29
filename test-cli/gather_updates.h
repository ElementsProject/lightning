#ifndef GATHER_UPDATES_H
#define GATHER_UPDATES_H
#include "lightning.pb-c.h"

struct signature;
struct sha256;

uint64_t gather_updates(const OpenChannel *o1, const OpenChannel *o2,
			const OpenAnchor *oa,
			char **argv,
			uint64_t *our_amount, uint64_t *their_amount,
			struct sha256 *our_rhash,
			struct sha256 *their_rhash,
			struct signature *their_commit_sig);

#endif /* GATHER_UPDATES_H */
