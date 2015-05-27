#include <ccan/crypto/sha256/sha256.h>
#include "pkt.h"

static struct pkt *to_pkt(const tal_t *ctx, Pkt__PktCase type, void *msg)
{
	struct pkt *ret;
	size_t len;
	Pkt p = PKT__INIT;
	
	p.pkt_case = type;
	/* This is a union, so doesn't matter which we assign. */
	p.error = msg;

	len = pkt__get_packed_size(&p);
	ret = (struct pkt *)tal_arr(ctx, u8, sizeof(ret->len) + len);
	ret->len = cpu_to_le32(len);
	pkt__pack(&p, ret->data);
	return ret;
}

Sha256Hash *proto_sha256_hash(const tal_t *ctx, const struct sha256 *hash)
{
	Sha256Hash *h = tal(ctx, Sha256Hash);
	sha256_hash__init(h);

	/* Kill me now... */
	memcpy(&h->a, hash->u.u8, 8);
	memcpy(&h->b, hash->u.u8 + 8, 8);
	memcpy(&h->c, hash->u.u8 + 16, 8);
	memcpy(&h->d, hash->u.u8 + 24, 8);
	return h;
}

struct pkt *openchannel_pkt(const tal_t *ctx,
			    u64 seed,
			    const struct sha256 *revocation_hash,
			    size_t script_len,
			    const void *script,
			    u64 commitment_fee,
			    u32 rel_locktime_seconds,
			    Anchor *anchor)
{
	OpenChannel o = OPEN_CHANNEL__INIT;

	o.seed = seed;
	o.revocation_hash = proto_sha256_hash(ctx, revocation_hash);
	o.script_to_me.len = script_len;
	o.script_to_me.data = (void *)script;
	o.commitment_fee = commitment_fee;
	o.anchor = anchor;
	o.locktime_case = OPEN_CHANNEL__LOCKTIME_LOCKTIME_SECONDS;
	o.locktime_seconds = rel_locktime_seconds;
	o.tx_version = 1;
	
	return to_pkt(ctx, PKT__PKT_OPEN, &o);
}
