#include <ccan/crypto/sha256/sha256.h>
#include <ccan/err/err.h>
#include <ccan/tal/grab_file/grab_file.h>
#include "bitcoin/address.h"
#include "bitcoin/pubkey.h"
#include "bitcoin/signature.h"
#include "bitcoin/tx.h"
#include "pkt.h"
#include "protobuf_convert.h"

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

struct pkt *openchannel_pkt(const tal_t *ctx,
			    u64 seed,
			    const struct sha256 *revocation_hash,
			    const struct pubkey *to_me,
			    u64 commitment_fee,
			    u32 rel_locktime_seconds,
			    Anchor *anchor)
{
	OpenChannel o = OPEN_CHANNEL__INIT;

	/* Required fields must be set: pack functions don't check! */
	assert(anchor->inputs);
	assert(anchor->pubkey);

	o.seed = seed;
	o.revocation_hash = sha256_to_proto(ctx, revocation_hash);
	o.final = pubkey_to_proto(ctx, to_me);
	o.commitment_fee = commitment_fee;
	o.anchor = anchor;
	o.locktime_seconds = rel_locktime_seconds;
	o.tx_version = BITCOIN_TX_VERSION;

	{
		size_t len = open_channel__get_packed_size(&o);
		unsigned char *pb = malloc(len);
		open_channel__pack(&o, pb);
		assert(open_channel__unpack(NULL, len, pb));
	}
		
	return to_pkt(ctx, PKT__PKT_OPEN, &o);
}

Pkt *any_pkt_from_file(const char *filename)
{
	struct pkt *pkt;
	Pkt *ret;
	size_t len;

	pkt = grab_file(NULL, filename);
	if (!pkt)
		err(1, "Opening %s", filename);

	len = tal_count(pkt) - 1;
	if (len < sizeof(pkt->len)
	    || len != sizeof(pkt->len) + le32_to_cpu(pkt->len))
		errx(1, "%s length is wrong", filename);
	len -= sizeof(pkt->len);

	ret = pkt__unpack(NULL, len, pkt->data);
	if (!ret)
		errx(1, "Unpack failed for %s", filename);
	return ret;
}
	
Pkt *pkt_from_file(const char *filename, Pkt__PktCase expect)
{
	Pkt *ret = any_pkt_from_file(filename);

	if (ret->pkt_case != expect)
		errx(1, "Unexpected type %i in %s", ret->pkt_case, filename);
	return ret;
}

struct pkt *open_anchor_sig_pkt(const tal_t *ctx, u8 **sigs, size_t num_sigs)
{
	OpenAnchorScriptsigs o = OPEN_ANCHOR_SCRIPTSIGS__INIT;
	size_t i;

	o.n_script = num_sigs;
	o.script = tal_arr(ctx, ProtobufCBinaryData, num_sigs);
	for (i = 0; i < num_sigs; i++) {
		o.script[i].data = sigs[i];
		o.script[i].len = tal_count(sigs[i]);
	}
	
	return to_pkt(ctx, PKT__PKT_OPEN_ANCHOR_SCRIPTSIGS, &o);
}

struct pkt *leak_anchor_sigs_and_pretend_we_didnt_pkt(const tal_t *ctx,
						      OpenAnchorScriptsigs *s)
{
	LeakAnchorSigsAndPretendWeDidnt omg_fail
		= LEAK_ANCHOR_SIGS_AND_PRETEND_WE_DIDNT__INIT;

	omg_fail.sigs = s;
	return to_pkt(ctx, PKT__PKT_OMG_FAIL, &omg_fail);
}

struct pkt *open_commit_sig_pkt(const tal_t *ctx, const struct signature *sig)
{
	OpenCommitSig o = OPEN_COMMIT_SIG__INIT;

	o.sig = signature_to_proto(ctx, sig);
	return to_pkt(ctx, PKT__PKT_OPEN_COMMIT_SIG, &o);
}

struct pkt *close_channel_pkt(const tal_t *ctx, const struct signature *sig)
{
	CloseChannel c = CLOSE_CHANNEL__INIT;
	c.sig = signature_to_proto(ctx, sig);
	return to_pkt(ctx, PKT__PKT_CLOSE, &c);
}

struct pkt *close_channel_complete_pkt(const tal_t *ctx,
				       const struct signature *sig)
{
	CloseChannelComplete c = CLOSE_CHANNEL_COMPLETE__INIT;
	c.sig = signature_to_proto(ctx, sig);
	return to_pkt(ctx, PKT__PKT_CLOSE_COMPLETE, &c);
}

struct pkt *update_pkt(const tal_t *ctx,
		       const struct sha256 *revocation_hash,
		       s64 delta)
{
	Update u = UPDATE__INIT;
	u.revocation_hash = sha256_to_proto(ctx, revocation_hash);
	u.delta = delta;
	return to_pkt(ctx, PKT__PKT_UPDATE, &u);
}

struct pkt *update_accept_pkt(const tal_t *ctx,
			      struct signature *sig,
			      const struct sha256 *revocation_hash)
{
	UpdateAccept ua = UPDATE_ACCEPT__INIT;
	ua.sig = signature_to_proto(ctx, sig);
	ua.revocation_hash = sha256_to_proto(ctx, revocation_hash);
	return to_pkt(ctx, PKT__PKT_UPDATE_ACCEPT, &ua);
}

struct pkt *update_signature_pkt(const tal_t *ctx,
				 const struct signature *sig,
				 const struct sha256 *revocation_preimage)
{
	UpdateSignature us = UPDATE_SIGNATURE__INIT;
	us.sig = signature_to_proto(ctx, sig);
	us.revocation_preimage = sha256_to_proto(ctx, revocation_preimage);
	return to_pkt(ctx, PKT__PKT_UPDATE_SIGNATURE, &us);
}

struct pkt *update_complete_pkt(const tal_t *ctx,
				const struct sha256 *revocation_preimage)
{
	UpdateComplete uc = UPDATE_COMPLETE__INIT;
	uc.revocation_preimage = sha256_to_proto(ctx, revocation_preimage);
	return to_pkt(ctx, PKT__PKT_UPDATE_COMPLETE, &uc);
}
