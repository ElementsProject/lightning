#include "config.h"
#include "../onion_budget.c"
#include <common/pseudorand.h>
#include <common/randbytes.h>
#include <common/setup.h>
#include <stdio.h>

/* A valid, distinct pubkey for each index. */
static struct pubkey test_pubkey(size_t i)
{
	struct privkey priv;
	struct pubkey pub;

	memset(&priv, 0, sizeof(priv));
	priv.secret.data[30] = (i + 1) >> 8;
	priv.secret.data[31] = (i + 1) & 0xFF;
	if (!pubkey_from_privkey(&priv, &pub))
		abort();
	return pub;
}

static struct blinded_path *test_blinded_path(const tal_t *ctx,
					      size_t num_hops,
					      size_t enc_len)
{
	struct blinded_path *path = tal(ctx, struct blinded_path);

	path->first_node_id.is_pubkey = true;
	path->first_node_id.pubkey = test_pubkey(1000);
	path->first_path_key = test_pubkey(1001);
	path->path = tal_arr(path, struct blinded_path_hop *, num_hops);
	for (size_t i = 0; i < num_hops; i++) {
		path->path[i] = tal(path->path, struct blinded_path_hop);
		path->path[i]->blinded_node_id = test_pubkey(1100 + i);
		path->path[i]->encrypted_recipient_data
			= tal_arrz(path->path[i], u8, enc_len);
	}
	return path;
}

/* Random value no greater than max, biased towards all encoding widths. */
static u64 random_upto(u64 max)
{
	u64 v = pseudorand_u64();
	int bits = pseudorand(65);

	if (bits < 64)
		v &= (1ULL << bits) - 1;
	return v > max ? max : v;
}

/* Everything onion_budget() needs to know about a payment. */
struct payment_params {
	struct amount_msat amount;
	struct amount_msat maxfee;
	u32 blockheight;
	u32 maxdelay;
	const struct blinded_path *path;
	const struct secret *payment_secret;
	const u8 *payment_metadata;
	const u8 *extra_tlvs;
};

static u32 params_budget(const struct payment_params *p, size_t *tail_size)
{
	return onion_budget(p->amount, p->maxfee, p->blockheight, p->maxdelay,
			    p->path, p->payment_secret, p->payment_metadata,
			    p->extra_tlvs, tail_size);
}

/* The upper bounds onion_budget() promises to cover (saturating, like it). */
static struct amount_msat max_out(const struct payment_params *p)
{
	struct amount_msat out;
	if (!amount_msat_add(&out, p->amount, p->maxfee))
		return AMOUNT_MSAT(UINT64_MAX);
	return out;
}

static u32 max_cltv(const struct payment_params *p)
{
	u64 cltv = (u64)p->blockheight + p->maxdelay;
	return cltv > UINT32_MAX ? UINT32_MAX : cltv;
}

/* Build an onion like create_onion() does: n forwarding payloads (amounts
 * and cltvs at or below the bounds, or exactly at them if worst), then the
 * tail. */
static struct sphinx_path *build_path(const tal_t *ctx,
				      const struct payment_params *p,
				      size_t n, bool worst)
{
	struct sphinx_path *sp = sphinx_path_new(ctx, NULL, 0);
	struct pubkey node = test_pubkey(0);
	struct amount_msat deliver;
	u32 tail_cltv;

	for (size_t i = 0; i < n; i++) {
		const struct short_channel_id scid = {.u64 = pseudorand_u64()};
		struct amount_msat amt;
		u32 cltv;

		if (worst) {
			amt = max_out(p);
			cltv = max_cltv(p);
		} else {
			amt = amount_msat(random_upto(max_out(p).millisatoshis)); /* Raw: test */
			cltv = random_upto(max_cltv(p));
		}
		sphinx_add_hop_has_length(sp, &node,
					  take(onion_forward_payload(NULL, &scid,
								     amt, cltv)));
		node = test_pubkey(i + 1);
	}

	if (worst) {
		deliver = p->amount;
		tail_cltv = max_cltv(p);
	} else {
		deliver = amount_msat(random_upto(p->amount.millisatoshis)); /* Raw: test */
		tail_cltv = random_upto(max_cltv(p));
	}

	if (p->path) {
		for (size_t i = 0; i < tal_count(p->path->path); i++)
			sphinx_add_hop_has_length(sp,
						  i == 0 ? &p->path->first_node_id.pubkey
						  : &p->path->path[i]->blinded_node_id,
						  take(onion_blinded_payload(NULL, p->path, i,
									     &deliver,
									     &p->amount,
									     &tail_cltv)));
	} else {
		/* Without payment_secret, total_msat must equal deliver. */
		sphinx_add_hop_has_length(sp, &node,
					  take(onion_final_payload(NULL, deliver,
								   tail_cltv,
								   p->payment_secret
								   ? p->amount : deliver,
								   p->payment_secret,
								   p->payment_metadata,
								   p->extra_tlvs)));
	}
	return sp;
}

static bool onion_fits(struct sphinx_path *sp)
{
	struct secret *secrets;
	struct onionpacket *packet;
	bool ok = (sphinx_path_payloads_size(sp) <= ROUTING_INFO_SIZE);

	if (ok) {
		/* we should be able to build the build the onion packet */
		packet =
		    create_onionpacket(tmpctx, sp, ROUTING_INFO_SIZE, &secrets);
		assert(packet);
		tal_free(packet);
	}
	return ok;
}

/* The size helpers agree exactly with what sphinx counts. */
static void check_sizes_exact(void)
{
	struct pubkey node = test_pubkey(0);
	struct secret secret;
	struct blinded_path *path = test_blinded_path(tmpctx, 3, 77);
	const u8 *metadata = tal_arrz(tmpctx, u8, 300);
	const u8 *extra = tal_arrz(tmpctx, u8, 40);

	memset(&secret, 7, sizeof(secret));

	for (size_t iter = 0; iter < 200; iter++) {
		struct sphinx_path *sp = sphinx_path_new(tmpctx, NULL, 0);
		const struct short_channel_id scid = {.u64 = pseudorand_u64()};
		struct amount_msat amt = amount_msat(random_upto(UINT64_MAX));
		struct amount_msat total = amount_msat(random_upto(UINT64_MAX));
		u32 cltv = random_upto(UINT32_MAX);
		size_t expect;

		sphinx_add_hop_has_length(sp, &node,
					  take(onion_forward_payload(NULL, &scid,
								     amt, cltv)));
		expect = onion_forward_hop_size(amt, cltv);
		assert(sphinx_path_payloads_size(sp) == expect);

		/* bolt11, keysend, with and without metadata */
		sphinx_add_hop_has_length(sp, &node,
					  take(onion_final_payload(NULL, amt, cltv,
								   total, &secret,
								   iter % 2 ? metadata : NULL,
								   NULL)));
		expect += onion_final_hop_size(amt, cltv, total, &secret,
					       iter % 2 ? metadata : NULL, NULL);
		assert(sphinx_path_payloads_size(sp) == expect);

		sphinx_add_hop_has_length(sp, &node,
					  take(onion_final_payload(NULL, amt, cltv,
								   amt, NULL, NULL,
								   extra)));
		expect += onion_final_hop_size(amt, cltv, amt, NULL, NULL, extra);
		assert(sphinx_path_payloads_size(sp) == expect);

		for (size_t i = 0; i < tal_count(path->path); i++)
			sphinx_add_hop_has_length(sp, &node,
						  take(onion_blinded_payload(NULL, path,
									     i, &amt,
									     &total,
									     &cltv)));
		expect += onion_blinded_tail_size(path, amt, total, cltv);
		assert(sphinx_path_payloads_size(sp) == expect);
	}
}

/* The builders can't notice themselves dropping a field: compare against
 * the raw encoder. */
static void check_against_raw_encoder(void)
{
	struct secret secret;
	const u8 *extra = tal_arrz(tmpctx, u8, 40);
	const u8 *raw;

	memset(&secret, 7, sizeof(secret));

	/* keysend: extra tlvs are appended (payload stays < 253 bytes, so
	 * the length prefix stays 1 byte). */
	raw = onion_final_hop(tmpctx, AMOUNT_MSAT(1000), 100, AMOUNT_MSAT(1000),
			      NULL, NULL);
	assert(onion_final_hop_size(AMOUNT_MSAT(1000), 100, AMOUNT_MSAT(1000),
				    NULL, NULL, extra)
	       == tal_bytelen(raw) + tal_bytelen(extra) + HMAC_SIZE);

	/* No payment_secret means no payment_data: 32 + 2 + total bytes less. */
	assert(onion_final_hop_size(AMOUNT_MSAT(1000), 100, AMOUNT_MSAT(1000),
				    &secret, NULL, NULL)
	       > onion_final_hop_size(AMOUNT_MSAT(1000), 100, AMOUNT_MSAT(1000),
				      NULL, NULL, NULL) + 32);

	/* Forwarding payload: 1 len + amt (2+3) + cltv (2+3) + scid 10 + hmac */
	assert(onion_forward_hop_size(AMOUNT_MSAT(0xff1234), 0xffabcd) == 53);
	/* Worst case is 27 bytes plus HMAC. */
	assert(onion_forward_hop_size(AMOUNT_MSAT(UINT64_MAX), UINT32_MAX) == 59);
}

/* max_hops always fits at the bounds; one more never does. */
static void check_budget(const struct payment_params *p)
{
	size_t tail;
	u32 n = params_budget(p, &tail);

	if (n == UINT32_MAX) {
		assert(tail > ROUTING_INFO_SIZE);
		assert(!onion_fits(build_path(tmpctx, p, 0, true)));
		return;
	}
	assert(tail <= ROUTING_INFO_SIZE);

	/* At the bounds, and below them. */
	assert(onion_fits(build_path(tmpctx, p, n, true)));
	for (size_t i = 0; i < 5; i++)
		assert(onion_fits(build_path(tmpctx, p, n, false)));

	/* The bound is tight. */
	assert(!onion_fits(build_path(tmpctx, p, n + 1, true)));
}

int main(int argc, char *argv[])
{
	struct payment_params p;
	struct secret secret;
	size_t tail;
	u32 n;

	common_setup(argv[0]);

	/* seed the pRNG */
	dev_override_randbytes("run-onion_budget.c", 42);

	memset(&secret, 7, sizeof(secret));

	check_sizes_exact();
	check_against_raw_encoder();

	/* Plain bolt11, 100k sat. */
	p.amount = AMOUNT_MSAT(100000000);
	p.maxfee = AMOUNT_MSAT(5000000);
	p.blockheight = 900000;
	p.maxdelay = 2016;
	p.path = NULL;
	p.payment_secret = &secret;
	p.payment_metadata = NULL;
	p.extra_tlvs = NULL;
	check_budget(&p);
	n = params_budget(&p, &tail);
	assert(n >= 20);

	/* Huge amounts. */
	p.amount = AMOUNT_MSAT(0xFFFFFFFFFFFF0000ULL);
	p.maxfee = AMOUNT_MSAT(0xFFFF);
	check_budget(&p);
	/* maxfee overflow: treated as UINT64_MAX */
	p.maxfee = AMOUNT_MSAT(0x10000000);
	check_budget(&p);
	p.amount = AMOUNT_MSAT(100000000);
	p.maxfee = AMOUNT_MSAT(5000000);

	/* cltv overflow: treated as UINT32_MAX */
	p.blockheight = UINT32_MAX - 10;
	check_budget(&p);
	p.blockheight = 900000;

	/* Large payment_metadata eats into the budget... */
	p.payment_metadata = tal_arrz(tmpctx, u8, 600);
	check_budget(&p);
	assert(params_budget(&p, NULL) < 20);
	/* ...and too large doesn't fit at all. */
	p.payment_metadata = tal_arrz(tmpctx, u8, 1300);
	check_budget(&p);
	assert(params_budget(&p, &tail) == UINT32_MAX);
	assert(tail > ROUTING_INFO_SIZE);
	p.payment_metadata = NULL;

	/* keysend: no secret, extra tlvs. */
	p.payment_secret = NULL;
	p.extra_tlvs = tal_arrz(tmpctx, u8, 42);
	check_budget(&p);
	p.extra_tlvs = NULL;
	p.payment_secret = &secret;

	/* Blinded paths: small, large, and too large to ever use. */
	p.path = test_blinded_path(tmpctx, 1, 50);
	check_budget(&p);

	p.path = test_blinded_path(tmpctx, 3, 300);
	check_budget(&p);
	assert(params_budget(&p, NULL) < 6);

	/* Exactly zero hops left. */
	p.path = test_blinded_path(tmpctx, 4, 260);
	check_budget(&p);
	assert(params_budget(&p, &tail) == 0);
	assert(tail <= ROUTING_INFO_SIZE);

	p.path = test_blinded_path(tmpctx, 4, 320);
	check_budget(&p);
	assert(params_budget(&p, NULL) == UINT32_MAX);

	/* A tail of exactly ROUTING_INFO_SIZE fits (0 hops), one more byte
	 * doesn't. */
	{
		bool found = false;
		p.path = NULL;
		for (size_t len = 1100; len < 1300 && !found; len++) {
			p.payment_metadata = tal_arrz(tmpctx, u8, len);
			n = params_budget(&p, &tail);
			if (tail != ROUTING_INFO_SIZE)
				continue;
			found = true;
			assert(n == 0);
			check_budget(&p);
			p.payment_metadata = tal_arrz(tmpctx, u8, len + 1);
			assert(params_budget(&p, &tail) == UINT32_MAX);
			assert(tail == ROUTING_INFO_SIZE + 1);
		}
		assert(found);
		p.payment_metadata = NULL;
	}

	/* Sweep enc_len: budget must be tight everywhere. */
	for (size_t len = 0; len < 1300; len += 61) {
		p.path = test_blinded_path(tmpctx, 2, len);
		check_budget(&p);
		clean_tmpctx();
	}

	common_shutdown();
	return 0;
}
