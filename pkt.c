#include <ccan/crypto/sha256/sha256.h>
#include <ccan/err/err.h>
#include <ccan/tal/grab_file/grab_file.h>
#include "bitcoin/address.h"
#include "bitcoin/pubkey.h"
#include "bitcoin/signature.h"
#include "bitcoin/tx.h"
#include "pkt.h"
#include "protobuf_convert.h"

size_t pkt_totlen(const struct pkt *pkt)
{
	return sizeof(pkt->len) + le32_to_cpu(pkt->len);
}

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
			    const struct sha256 *revocation_hash,
			    const struct pubkey *commit,
			    const struct pubkey *final,
			    u64 commitment_fee,
			    u32 rel_locktime_seconds,
			    u64 anchor_amount,
			    const struct sha256 *escape_hash,
			    u32 min_confirms)
{
	OpenChannel o = OPEN_CHANNEL__INIT;

	o.revocation_hash = sha256_to_proto(ctx, revocation_hash);
	o.commitkey = pubkey_to_proto(ctx, commit);
	o.final = pubkey_to_proto(ctx, final);
	o.commitment_fee = commitment_fee;
	o.locktime_case = OPEN_CHANNEL__LOCKTIME_LOCKTIME_SECONDS;
	o.locktime_seconds = rel_locktime_seconds;
	o.total_input = anchor_amount;
	o.escape_hash = sha256_to_proto(ctx, escape_hash);
	o.min_confirms = min_confirms;

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

struct pkt *open_anchor_pkt(const tal_t *ctx, const struct sha256_double *txid,
			    u32 index)
{
	OpenAnchor oa = OPEN_ANCHOR__INIT;

	oa.anchor_txid = sha256_to_proto(ctx, &txid->sha);
	oa.index = index;
	return to_pkt(ctx, PKT__PKT_OPEN_ANCHOR, &oa);
}

struct pkt *open_commit_sig_pkt(const tal_t *ctx, const struct signature *sigs)
{
	OpenCommitSig o = OPEN_COMMIT_SIG__INIT;
	o.sigs = tal(ctx, AnchorSpend);
	anchor_spend__init(o.sigs);
	o.sigs->sig0 = signature_to_proto(ctx, &sigs[0]);
	o.sigs->sig1 = signature_to_proto(ctx, &sigs[1]);
	return to_pkt(ctx, PKT__PKT_OPEN_COMMIT_SIG, &o);
}

struct pkt *close_channel_pkt(const tal_t *ctx, const struct signature *sigs)
{
	CloseChannel c = CLOSE_CHANNEL__INIT;
	c.sigs = tal(ctx, AnchorSpend);
	anchor_spend__init(c.sigs);
	c.sigs->sig0 = signature_to_proto(ctx, &sigs[0]);
	c.sigs->sig1 = signature_to_proto(ctx, &sigs[1]);
	return to_pkt(ctx, PKT__PKT_CLOSE, &c);
}

struct pkt *close_channel_complete_pkt(const tal_t *ctx,
				       const struct signature *sigs)
{
	CloseChannelComplete c = CLOSE_CHANNEL_COMPLETE__INIT;
	c.sigs = tal(ctx, AnchorSpend);
	anchor_spend__init(c.sigs);
	c.sigs->sig0 = signature_to_proto(ctx, &sigs[0]);
	c.sigs->sig1 = signature_to_proto(ctx, &sigs[1]);
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
			      const struct signature *sigs,
			      const struct sha256 *revocation_hash)
{
	UpdateAccept ua = UPDATE_ACCEPT__INIT;
	ua.sigs = tal(ctx, AnchorSpend);
	anchor_spend__init(ua.sigs);
	ua.sigs->sig0 = signature_to_proto(ctx, &sigs[0]);
	ua.sigs->sig1 = signature_to_proto(ctx, &sigs[1]);
	ua.revocation_hash = sha256_to_proto(ctx, revocation_hash);
	return to_pkt(ctx, PKT__PKT_UPDATE_ACCEPT, &ua);
}

struct pkt *update_signature_pkt(const tal_t *ctx,
				 const struct signature *sigs,
				 const struct sha256 *revocation_preimage)
{
	UpdateSignature us = UPDATE_SIGNATURE__INIT;
	us.sigs = tal(ctx, AnchorSpend);
	anchor_spend__init(us.sigs);
	us.sigs->sig0 = signature_to_proto(ctx, &sigs[0]);
	us.sigs->sig1 = signature_to_proto(ctx, &sigs[1]);
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
