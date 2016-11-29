#include "../gen_wire.c"

void towire_pad_array_orig(u8 **pptr, const u8 *arr, size_t num);
#define towire_pad_array towire_pad_array_orig
#include "../towire.c"
#undef towire_pad_array

#include "../fromwire.c"
#include <ccan/structeq/structeq.h>
#include <assert.h>
#include <stdio.h>

secp256k1_context *secp256k1_ctx;

/* We allow non-zero padding for testing. */
void towire_pad_array(u8 **pptr, const u8 *arr, size_t num)
{
	towire_u8_array(pptr, arr, num);
}

/* memsetting pubkeys doesn't work */
static void set_pubkey(struct pubkey *key)
{
	u8 der[PUBKEY_DER_LEN];
	memset(der, 2, sizeof(der));
	assert(pubkey_from_der(secp256k1_ctx, der, sizeof(der), key));
}

/* Size up to field. */
#define upto_field(p, field)				\
	((char *)&(p)->field - (char *)(p))

/* Size including field. */
#define with_field(p, field)				\
	(upto_field((p), field) + sizeof((p)->field))

/* Equal upto this field */
#define eq_upto(p1, p2, field)			\
	(memcmp((p1), (p2), upto_field(p1, field)) == 0)

/* Equal upto and including this field */
#define eq_with(p1, p2, field)			\
	(memcmp((p1), (p2), with_field(p1, field)) == 0)

/* Equal from fields first to last inclusive. */
#define eq_between(p1, p2, first, last)					\
	(memcmp((char *)(p1) + upto_field((p1), first),			\
		(char *)(p2) + upto_field((p1), first),			\
		with_field(p1, last) - upto_field(p1, first)) == 0)

/* Equal in one field. */
#define eq_field(p1, p2, field)						\
	(memcmp((char *)(p1) + upto_field((p1), field),			\
		(char *)(p2) + upto_field((p1), field),			\
		sizeof((p1)->field)) == 0)

#define eq_var(p1, p2, lenfield, field)			\
	(memcmp((p1)->field, (p2)->field, (p1)->lenfield * sizeof(*(p1)->field)) == 0)

static inline bool eq_skip_(const void *p1, const void *p2,
			    size_t off, size_t skip, size_t total)
{
	if (memcmp(p1, p2, off) != 0)
		return false;
	p1 = (char *)p1 + off + skip;
	p2 = (char *)p2 + off + skip;
	return memcmp(p1, p2, total - (off + skip)) == 0;
}

static bool channel_announcement_eq(const struct msg_channel_announcement *a,
				    const struct msg_channel_announcement *b)
{
	return structeq(a, b);
}

static bool funding_locked_eq(const struct msg_funding_locked *a,
			      const struct msg_funding_locked *b)
{
	return structeq(a, b);
}

static bool update_fail_htlc_eq(const struct msg_update_fail_htlc *a,
				const struct msg_update_fail_htlc *b)
{
	return eq_with(a, b, reason);
}

static bool commit_sig_eq(const struct msg_commit_sig *a,
			  const struct msg_commit_sig *b)
{
	return eq_with(a, b, num_htlcs)
		&& eq_var(a, b, num_htlcs, htlc_signature);
}

static bool funding_signed_eq(const struct msg_funding_signed *a,
			      const struct msg_funding_signed *b)
{
	return structeq(a, b);
}

static bool closing_signed_eq(const struct msg_closing_signed *a,
			      const struct msg_closing_signed *b)
{
	return structeq(a, b);
}

static bool update_fulfill_htlc_eq(const struct msg_update_fulfill_htlc *a,
				   const struct msg_update_fulfill_htlc *b)
{
	return structeq(a, b);
}

static bool error_eq(const struct msg_error *a,
		     const struct msg_error *b)
{
	return eq_with(a, b, len)
		&& eq_var(a, b, len, data);
}

static bool init_eq(const struct msg_init *a,
		    const struct msg_init *b)
{
	return eq_field(a, b, gflen)
		&& eq_var(a, b, gflen, globalfeatures)
		&& eq_field(a, b, lflen)
		&& eq_var(a, b, lflen, localfeatures);
}

static bool update_fee_eq(const struct msg_update_fee *a,
			  const struct msg_update_fee *b)
{
	return structeq(a, b);
}

static bool shutdown_eq(const struct msg_shutdown *a,
			const struct msg_shutdown *b)
{
	return eq_with(a, b, len)
		&& eq_var(a, b, len, scriptpubkey);
}

static bool funding_created_eq(const struct msg_funding_created *a,
			       const struct msg_funding_created *b)
{
	return eq_with(a, b, output_index)
		&& eq_field(a, b, signature);
}

static bool revoke_and_ack_eq(const struct msg_revoke_and_ack *a,
			      const struct msg_revoke_and_ack *b)
{
	return eq_with(a, b, padding)
		&& eq_field(a, b, num_htlc_timeouts)
		&& eq_var(a, b, num_htlc_timeouts, htlc_timeout_signature);
}

static bool open_channel_eq(const struct msg_open_channel *a,
			    const struct msg_open_channel *b)
{
	return eq_with(a, b, max_accepted_htlcs)
		&& eq_between(a, b, funding_pubkey, first_per_commitment_point);
}

static bool channel_update_eq(const struct msg_channel_update *a,
			      const struct msg_channel_update *b)
{
	return structeq(a, b);
}

static bool accept_channel_eq(const struct msg_accept_channel *a,
			      const struct msg_accept_channel *b)
{
	return eq_with(a, b, max_accepted_htlcs)
		&& eq_between(a, b, funding_pubkey, first_per_commitment_point);
}

static bool update_add_htlc_eq(const struct msg_update_add_htlc *a,
			       const struct msg_update_add_htlc *b)
{
	return eq_with(a, b, onion_routing_packet);
}

static bool node_announcement_eq(const struct msg_node_announcement *a,
				 const struct msg_node_announcement *b)
{
	return eq_with(a, b, port)
		&& eq_between(a, b, node_id, pad)
		&& eq_field(a, b, alias);
}

/* Try flipping each bit, try running short. */
#define test_corruption(a, b, type)				\
	for (i = 0; i < tal_count(msg) * 8; i++) {		\
		len = tal_count(msg);				\
		msg[i / 8] ^= (1 << (i%8));			\
		b = fromwire_##type(ctx, msg, &len);		\
		assert(!b || !type##_eq(a, b));			\
		msg[i / 8] ^= (1 << (i%8));			\
	}							\
	for (i = 0; i < tal_count(msg); i++) {			\
		len = i;					\
		b = fromwire_##type(ctx, msg, &len);		\
		assert(!b);					\
	}

int main(void)
{
	struct msg_channel_announcement ca, *ca2;
	struct msg_funding_locked fl, *fl2;
	struct msg_update_fail_htlc ufh, *ufh2;
	struct msg_commit_sig cs, *cs2;
	struct msg_funding_signed fs, *fs2;
	struct msg_closing_signed cls, *cls2;
	struct msg_update_fulfill_htlc uflh, *uflh2;
	struct msg_error e, *e2;
	struct msg_init init, *init2;
	struct msg_update_fee uf, *uf2;
	struct msg_shutdown shutdown, *shutdown2;
	struct msg_funding_created fc, *fc2;
	struct msg_revoke_and_ack raa, *raa2;
	struct msg_open_channel oc, *oc2;
	struct msg_channel_update cu, *cu2;
	struct msg_accept_channel ac, *ac2;
	struct msg_update_add_htlc uah, *uah2;
	struct msg_node_announcement na, *na2;
	void *ctx = tal(NULL, char);
	size_t i, len;
	u8 *msg;

	secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY
						 | SECP256K1_CONTEXT_SIGN);

	memset(&ca, 2, sizeof(ca));
	set_pubkey(&ca.node_id_1);
	set_pubkey(&ca.node_id_2);
	set_pubkey(&ca.bitcoin_key_1);
	set_pubkey(&ca.bitcoin_key_2);
	
	msg = towire_channel_announcement(ctx, &ca);
	len = tal_count(msg);
	ca2 = fromwire_channel_announcement(ctx, msg, &len);
	assert(len == 0);
	assert(channel_announcement_eq(&ca, ca2));
	test_corruption(&ca, ca2, channel_announcement);

	memset(&fl, 2, sizeof(fl));
	set_pubkey(&fl.next_per_commitment_point);
	
	msg = towire_funding_locked(ctx, &fl);
	len = tal_count(msg);
	fl2 = fromwire_funding_locked(ctx, msg, &len);
	assert(len == 0);
	assert(funding_locked_eq(&fl, fl2));
	test_corruption(&fl, fl2, funding_locked);
	
	memset(&ufh, 2, sizeof(ufh));
	
	msg = towire_update_fail_htlc(ctx, &ufh);
	len = tal_count(msg);
	ufh2 = fromwire_update_fail_htlc(ctx, msg, &len);
	assert(len == 0);
	assert(update_fail_htlc_eq(&ufh, ufh2));
	test_corruption(&ufh, ufh2, update_fail_htlc);

	memset(&cs, 2, sizeof(cs));
	cs.num_htlcs = 2;
	cs.htlc_signature = tal_arr(ctx, struct signature, 2);
	memset(cs.htlc_signature, 2, sizeof(struct signature)*2);
	
	msg = towire_commit_sig(ctx, &cs);
	len = tal_count(msg);
	cs2 = fromwire_commit_sig(ctx, msg, &len);
	assert(len == 0);
	assert(commit_sig_eq(&cs, cs2));
	test_corruption(&cs, cs2, commit_sig);

	memset(&fs, 2, sizeof(fs));
	
	msg = towire_funding_signed(ctx, &fs);
	len = tal_count(msg);
	fs2 = fromwire_funding_signed(ctx, msg, &len);
	assert(len == 0);
	assert(funding_signed_eq(&fs, fs2));
	test_corruption(&fs, fs2, funding_signed);

	memset(&cls, 2, sizeof(cls));
	
	msg = towire_closing_signed(ctx, &cls);
	len = tal_count(msg);
	cls2 = fromwire_closing_signed(ctx, msg, &len);
	assert(len == 0);
	assert(closing_signed_eq(&cls, cls2));
	test_corruption(&cls, cls2, closing_signed);
	
	memset(&uflh, 2, sizeof(uflh));
	
	msg = towire_update_fulfill_htlc(ctx, &uflh);
	len = tal_count(msg);
	uflh2 = fromwire_update_fulfill_htlc(ctx, msg, &len);
	assert(len == 0);
	assert(update_fulfill_htlc_eq(&uflh, uflh2));
	test_corruption(&uflh, uflh2, update_fulfill_htlc);

	memset(&e, 2, sizeof(e));
	e.len = 2;
	e.data = tal_arr(ctx, u8, 2);
	memset(e.data, 2, 2);
	
	msg = towire_error(ctx, &e);
	len = tal_count(msg);
	e2 = fromwire_error(ctx, msg, &len);
	assert(len == 0);
	assert(error_eq(&e, e2));
	test_corruption(&e, e2, error);

	memset(&init, 2, sizeof(init));
	init.gflen = 2;
	init.globalfeatures = tal_arr(ctx, u8, 2);
	memset(init.globalfeatures, 2, 2);
	init.lflen = 2;
	init.localfeatures = tal_arr(ctx, u8, 2);
	memset(init.localfeatures, 2, 2);

	msg = towire_init(ctx, &init);
	len = tal_count(msg);
	init2 = fromwire_init(ctx, msg, &len);
	assert(len == 0);
	assert(init_eq(&init, init2));
	test_corruption(&init, init2, init);

	memset(&uf, 2, sizeof(uf));
	
	msg = towire_update_fee(ctx, &uf);
	len = tal_count(msg);
	uf2 = fromwire_update_fee(ctx, msg, &len);
	assert(len == 0);
	assert(update_fee_eq(&uf, uf2));
	test_corruption(&uf, uf2, update_fee);

	memset(&shutdown, 2, sizeof(shutdown));
	shutdown.len = 2;
	shutdown.scriptpubkey = tal_arr(ctx, u8, 2);
	memset(shutdown.scriptpubkey, 2, 2);
	
	msg = towire_shutdown(ctx, &shutdown);
	len = tal_count(msg);
	shutdown2 = fromwire_shutdown(ctx, msg, &len);
	assert(len == 0);
	assert(shutdown_eq(&shutdown, shutdown2));
	test_corruption(&shutdown, shutdown2, shutdown);
	
	memset(&fc, 2, sizeof(fc));
	
	msg = towire_funding_created(ctx, &fc);
	len = tal_count(msg);
	fc2 = fromwire_funding_created(ctx, msg, &len);
	assert(len == 0);
	assert(funding_created_eq(&fc, fc2));
	test_corruption(&fc, fc2, funding_created);

	memset(&raa, 2, sizeof(raa));
	set_pubkey(&raa.next_per_commitment_point);
	raa.num_htlc_timeouts = 2;
	raa.htlc_timeout_signature = tal_arr(ctx, struct signature, 2);
	memset(raa.htlc_timeout_signature, 2, sizeof(struct signature) * 2);
	
	msg = towire_revoke_and_ack(ctx, &raa);
	len = tal_count(msg);
	raa2 = fromwire_revoke_and_ack(ctx, msg, &len);
	assert(len == 0);
	assert(revoke_and_ack_eq(&raa, raa2));
	test_corruption(&raa, raa2, revoke_and_ack);

	memset(&oc, 2, sizeof(oc));
	set_pubkey(&oc.funding_pubkey);
	set_pubkey(&oc.revocation_basepoint);
	set_pubkey(&oc.payment_basepoint);
	set_pubkey(&oc.delayed_payment_basepoint);
	set_pubkey(&oc.first_per_commitment_point);
	
	msg = towire_open_channel(ctx, &oc);
	len = tal_count(msg);
	oc2 = fromwire_open_channel(ctx, msg, &len);
	assert(len == 0);
	assert(open_channel_eq(&oc, oc2));
	test_corruption(&oc, oc2, open_channel);

	memset(&cu, 2, sizeof(cu));
	
	msg = towire_channel_update(ctx, &cu);
	len = tal_count(msg);
	cu2 = fromwire_channel_update(ctx, msg, &len);
	assert(len == 0);
	assert(channel_update_eq(&cu, cu2));
	test_corruption(&cu, cu2, channel_update);

	memset(&ac, 2, sizeof(ac));
	set_pubkey(&ac.funding_pubkey);
	set_pubkey(&ac.revocation_basepoint);
	set_pubkey(&ac.payment_basepoint);
	set_pubkey(&ac.delayed_payment_basepoint);
	set_pubkey(&ac.first_per_commitment_point);
	
	msg = towire_accept_channel(ctx, &ac);
	len = tal_count(msg);
	ac2 = fromwire_accept_channel(ctx, msg, &len);
	assert(len == 0);
	assert(accept_channel_eq(&ac, ac2));
	test_corruption(&ac, ac2, accept_channel);

	memset(&uah, 2, sizeof(uah));
	
	msg = towire_update_add_htlc(ctx, &uah);
	len = tal_count(msg);
	uah2 = fromwire_update_add_htlc(ctx, msg, &len);
	assert(len == 0);
	assert(update_add_htlc_eq(&uah, uah2));
	test_corruption(&uah, uah2, update_add_htlc);

	memset(&na, 2, sizeof(na));
	set_pubkey(&na.node_id);

	msg = towire_node_announcement(ctx, &na);
	len = tal_count(msg);
	na2 = fromwire_node_announcement(ctx, msg, &len);
	assert(len == 0);
	assert(node_announcement_eq(&na, na2));
	test_corruption(&na, na2, node_announcement);

	/* No memory leaks please */
	secp256k1_context_destroy(secp256k1_ctx);
	tal_free(ctx);
	return 0;
}
