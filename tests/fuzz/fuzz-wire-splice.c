#include "config.h"
#include <tests/fuzz/libfuzz.h>
#include <tests/fuzz/wire.h>
#include <wire/peer_wire.h>

struct splice {
	struct channel_id channel_id;
	struct bitcoin_blkid chain_hash;
	s64 relative_satoshis;
	u32 funding_feerate_perkw;
	u32 locktime;
	struct pubkey funding_pubkey;
	struct tlv_splice_tlvs *tlvs;
};

static void *encode(const tal_t *ctx, const struct splice *s)
{
	return towire_splice(ctx, &s->channel_id, &s->chain_hash,
			     s->relative_satoshis, s->funding_feerate_perkw,
			     s->locktime, &s->funding_pubkey, s->tlvs);
}

static struct splice *decode(const tal_t *ctx, const void *p)
{
	struct splice *s = tal(ctx, struct splice);

	if (fromwire_splice(s, p, &s->channel_id, &s->chain_hash,
			    &s->relative_satoshis, &s->funding_feerate_perkw,
			    &s->locktime, &s->funding_pubkey, &s->tlvs))
		return s;
	return tal_free(s);
}

static bool request_funds_equal(const struct tlv_splice_tlvs_request_funds *x,
				const struct tlv_splice_tlvs_request_funds *y)
{
	if (!x && !y)
		return true;
	if (!x || !y)
		return false;
	if (x->requested_sats != y->requested_sats)
		return false;

	return x->blockheight == y->blockheight;
}

static bool equal(const struct splice *x, const struct splice *y)
{
	if (!request_funds_equal(x->tlvs->request_funds,
				 y->tlvs->request_funds))
		return false;

	return memcmp(x, y, sizeof(*x) - sizeof(struct tlv_splice_tlvs*)) == 0;
}

void run(const u8 *data, size_t size)
{
	test_decode_encode(data, size, WIRE_SPLICE, struct splice);
}
