#include "config.h"
#include <tests/fuzz/libfuzz.h>
#include <tests/fuzz/wire.h>
#include <wire/peer_wire.h>

struct splice_ack {
	struct channel_id channel_id;
	struct bitcoin_blkid chain_hash;
	s64 relative_satoshis;
	struct pubkey funding_pubkey;
	struct tlv_splice_ack_tlvs *tlvs;
};

static void *encode(const tal_t *ctx, const struct splice_ack *s)
{
	return towire_splice_ack(ctx, &s->channel_id, &s->chain_hash,
				 s->relative_satoshis, &s->funding_pubkey,
				 s->tlvs);
}

static struct splice_ack *decode(const tal_t *ctx, const void *p)
{
	struct splice_ack *s = tal(ctx, struct splice_ack);

	if (fromwire_splice_ack(s, p, &s->channel_id, &s->chain_hash,
				&s->relative_satoshis, &s->funding_pubkey,
				&s->tlvs))
		return s;
	return tal_free(s);
}

static bool will_fund_equal(const struct tlv_splice_ack_tlvs_will_fund *x,
			    const struct tlv_splice_ack_tlvs_will_fund *y)
{
	if (!x && !y)
		return true;
	if (!x || !y)
		return false;
	if (memcmp(&x->signature, &y->signature, sizeof(x->signature)) != 0)
		return false;

	return memcmp(&x->lease_rates, &y->lease_rates, sizeof(x->lease_rates)) == 0;
}

static bool equal(const struct splice_ack *x, const struct splice_ack *y)
{
	if (!will_fund_equal(x->tlvs->will_fund, y->tlvs->will_fund))
		return false;

	return memcmp(x, y, sizeof(*x) - sizeof(struct tlv_splice_ack_tlvs*)) == 0;
}

void run(const u8 *data, size_t size)
{
	test_decode_encode(data, size, WIRE_SPLICE_ACK, struct splice_ack);
}
