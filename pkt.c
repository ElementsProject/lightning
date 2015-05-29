#include <ccan/crypto/sha256/sha256.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/err/err.h>
#include "pkt.h"
#include "bitcoin_tx.h"
#include "bitcoin_address.h"

#include <stdio.h>
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

Sha256Hash *sha256_to_proto(const tal_t *ctx, const struct sha256 *hash)
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

void proto_to_sha256(const Sha256Hash *pb, struct sha256 *hash)
{
	/* Kill me again. */
	memcpy(hash->u.u8, &pb->a, 8);
	memcpy(hash->u.u8 + 8, &pb->b, 8);
	memcpy(hash->u.u8 + 16, &pb->c, 8);
	memcpy(hash->u.u8 + 24, &pb->d, 8);
}

BitcoinPubkey *pubkey_to_proto(const tal_t *ctx,
			       const struct bitcoin_compressed_pubkey *key)
{
	BitcoinPubkey *p = tal(ctx, BitcoinPubkey);

	bitcoin_pubkey__init(p);
	p->key.data = tal_dup_arr(ctx, u8, key->key, sizeof(key->key), 0);
	p->key.len = sizeof(key->key);
	return p;
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

	/* Required fields must be set: pack functions don't check! */
	assert(anchor->inputs);
	assert(anchor->pubkey);

	o.seed = seed;
	o.revocation_hash = sha256_to_proto(ctx, revocation_hash);
	o.script_to_me.len = script_len;
	o.script_to_me.data = (void *)script;
	o.commitment_fee = commitment_fee;
	o.anchor = anchor;
	o.locktime_case = OPEN_CHANNEL__LOCKTIME_LOCKTIME_SECONDS;
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

Pkt *pkt_from_file(const char *filename, Pkt__PktCase expect)
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

	if (ret->pkt_case != expect)
		errx(1, "Unexpected type %i in %s", ret->pkt_case, filename);
	return ret;
}

struct pkt *open_anchor_sig_pkt(const tal_t *ctx, u8 **sigs, size_t num_sigs)
{
	OpenAnchorSig o = OPEN_ANCHOR_SIG__INIT;
	size_t i;

	o.n_script = num_sigs;
	o.script = tal_arr(ctx, ProtobufCBinaryData, num_sigs);
	for (i = 0; i < num_sigs; i++) {
		o.script[i].data = sigs[i];
		o.script[i].len = tal_count(sigs[i]);
	}
	
	return to_pkt(ctx, PKT__PKT_OPEN_ANCHOR_SIG, &o);
}

struct pkt *leak_anchor_sigs_and_pretend_we_didnt_pkt(const tal_t *ctx,
						      OpenAnchorSig *s)
{
	LeakAnchorSigsAndPretendWeDidnt omg_fail
		= LEAK_ANCHOR_SIGS_AND_PRETEND_WE_DIDNT__INIT;

	omg_fail.anchor_scriptsigs = s;
	return to_pkt(ctx, PKT__PKT_OMG_FAIL, &omg_fail);
}
