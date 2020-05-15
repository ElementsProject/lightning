#include "bitcoin/block.h"
#include "bitcoin/pullpush.h"
#include "bitcoin/tx.h"
#include <ccan/str/hex/hex.h>
#include <common/type_to_string.h>
#include <wire/wire.h>

static void sha256_varint(struct sha256_ctx *ctx, u64 val)
{
	u8 vt[VARINT_MAX_LEN];
	size_t vtlen;
	vtlen = varint_put(vt, val);
	sha256_update(ctx, vt, vtlen);
}

static void bitcoin_block_pull_dynafed_params(const u8 **cursor, size_t *len, struct sha256_ctx *shactx)
{
	u8 type;
	u64 l1, l2;
	pull(cursor, len, &type, 1);
	sha256_update(shactx, &type, 1);
	switch ((enum dynafed_params_type)type) {
	case DYNAFED_PARAMS_NULL:
		break;
	case DYNAFED_PARAMS_COMPACT:
		/* "scriptPubKey" used for block signing */
		l1 = pull_varint(cursor, len);
		sha256_varint(shactx, l1);
		sha256_update(shactx, *cursor, l1);
		pull(cursor, len, NULL, l1);

		/* signblock_witness_limit */
		sha256_update(shactx, *cursor, 4);
		pull(cursor, len, NULL, 4);

		/* Skip elided_root */
		sha256_update(shactx, *cursor, 32);
		pull(cursor, len, NULL, 32);
		break;

	case DYNAFED_PARAMS_FULL:
		/* "scriptPubKey" used for block signing */
		l1 = pull_varint(cursor, len);
		sha256_varint(shactx, l1);
		sha256_update(shactx, *cursor, l1);
		pull(cursor, len, NULL, l1);

		/* signblock_witness_limit */
		sha256_update(shactx, *cursor, 4);
		pull(cursor, len, NULL, 4);

		/* fedpeg_program */
		l1 = pull_varint(cursor, len);
		sha256_varint(shactx, l1);
		sha256_update(shactx, *cursor, l1);
		pull(cursor, len, NULL, l1);

		/* fedpegscript */
		l1 = pull_varint(cursor, len);
		sha256_varint(shactx, l1);
		sha256_update(shactx, *cursor, l1);
		pull(cursor, len, NULL, l1);

		/* extension space */
		l2 = pull_varint(cursor, len);
		sha256_varint(shactx, l2);
		for (size_t i = 0; i < l2; i++) {
			l1 = pull_varint(cursor, len);
			sha256_varint(shactx, l1);
			sha256_update(shactx, *cursor, l1);
			pull(cursor, len, NULL, l1);
		}
		break;
	}
}

static void bitcoin_block_pull_dynafed_details(const u8 **cursor, size_t *len, struct sha256_ctx *shactx)
{
	bitcoin_block_pull_dynafed_params(cursor, len, shactx);
	bitcoin_block_pull_dynafed_params(cursor, len, shactx);

	/* Consume the signblock_witness */
	u64 numwitnesses = pull_varint(cursor, len);
	for (size_t i=0; i<numwitnesses; i++) {
		u64 witsize = pull_varint(cursor, len);
		pull(cursor, len, NULL, witsize);
	}
}

/* Encoding is <blockhdr> <varint-num-txs> <tx>... */
struct bitcoin_block *
bitcoin_block_from_hex(const tal_t *ctx, const struct chainparams *chainparams,
		       const char *hex, size_t hexlen)
{
	struct bitcoin_block *b;
	u8 *linear_tx;
	const u8 *p;
	size_t len, i, num, templen;
	struct sha256_ctx shactx;
	bool is_dynafed;
	u32 height;

	if (hexlen && hex[hexlen-1] == '\n')
		hexlen--;

	/* Set up the block for success. */
	b = tal(ctx, struct bitcoin_block);

	/* De-hex the array. */
	len = hex_data_size(hexlen);
	p = linear_tx = tal_arr(ctx, u8, len);
	if (!hex_decode(hex, hexlen, linear_tx, len))
		return tal_free(b);

	sha256_init(&shactx);

	b->hdr.version = pull_le32(&p, &len);
	sha256_le32(&shactx, b->hdr.version);

	pull(&p, &len, &b->hdr.prev_hash, sizeof(b->hdr.prev_hash));
	sha256_update(&shactx, &b->hdr.prev_hash, sizeof(b->hdr.prev_hash));

	pull(&p, &len, &b->hdr.merkle_hash, sizeof(b->hdr.merkle_hash));
	sha256_update(&shactx, &b->hdr.merkle_hash, sizeof(b->hdr.merkle_hash));

	b->hdr.timestamp = pull_le32(&p, &len);
	sha256_le32(&shactx, b->hdr.timestamp);

	if (is_elements(chainparams)) {
		/* A dynafed block is signalled by setting the MSB of the version. */
		is_dynafed = (b->hdr.version >> 31 == 1);

		/* elements_header.height */
		height = pull_le32(&p, &len);
		sha256_le32(&shactx, height);

		if (is_dynafed) {
			bitcoin_block_pull_dynafed_details(&p, &len, &shactx);
		} else {
			/* elemens_header.challenge */
			templen = pull_varint(&p, &len);
			sha256_varint(&shactx, templen);
			sha256_update(&shactx, p, templen);
			pull(&p, &len, NULL, templen);

			/* elements_header.solution. Not hashed since it'd be
			 * a circular dependency. */
			templen = pull_varint(&p, &len);
			pull(&p, &len, NULL, templen);
		}

	} else {
		b->hdr.target = pull_le32(&p, &len);
		sha256_le32(&shactx, b->hdr.target);

		b->hdr.nonce = pull_le32(&p, &len);
		sha256_le32(&shactx, b->hdr.nonce);
	}
	sha256_double_done(&shactx, &b->hdr.hash.shad);

	num = pull_varint(&p, &len);
	b->tx = tal_arr(b, struct bitcoin_tx *, num);
	for (i = 0; i < num; i++) {
		b->tx[i] = pull_bitcoin_tx(b->tx, &p, &len);
		b->tx[i]->chainparams = chainparams;
	}

	/* We should end up not overrunning, nor have extra */
	if (!p || len)
		return tal_free(b);

	tal_free(linear_tx);
	return b;
}

void bitcoin_block_blkid(const struct bitcoin_block *b,
			 struct bitcoin_blkid *out)
{
	*out = b->hdr.hash;
}

/* We do the same hex-reversing crud as txids. */
bool bitcoin_blkid_from_hex(const char *hexstr, size_t hexstr_len,
			    struct bitcoin_blkid *blockid)
{
	struct bitcoin_txid fake_txid;
	if (!bitcoin_txid_from_hex(hexstr, hexstr_len, &fake_txid))
		return false;
	blockid->shad = fake_txid.shad;
	return true;
}

bool bitcoin_blkid_to_hex(const struct bitcoin_blkid *blockid,
			  char *hexstr, size_t hexstr_len)
{
	struct bitcoin_txid fake_txid;
	fake_txid.shad = blockid->shad;
	return bitcoin_txid_to_hex(&fake_txid, hexstr, hexstr_len);
}

static char *fmt_bitcoin_blkid(const tal_t *ctx,
			       const struct bitcoin_blkid *blkid)
{
	char *hexstr = tal_arr(ctx, char, hex_str_size(sizeof(*blkid)));

	bitcoin_blkid_to_hex(blkid, hexstr, hex_str_size(sizeof(*blkid)));
	return hexstr;
}
REGISTER_TYPE_TO_STRING(bitcoin_blkid, fmt_bitcoin_blkid);

void fromwire_bitcoin_blkid(const u8 **cursor, size_t *max,
			    struct bitcoin_blkid *blkid)
{
	fromwire_sha256_double(cursor, max, &blkid->shad);
}

void towire_bitcoin_blkid(u8 **pptr, const struct bitcoin_blkid *blkid)
{
	towire_sha256_double(pptr, &blkid->shad);
}


void towire_chainparams(u8 **cursor, const struct chainparams *chainparams)
{
	towire_bitcoin_blkid(cursor, &chainparams->genesis_blockhash);
}

void fromwire_chainparams(const u8 **cursor, size_t *max,
			  const struct chainparams **chainparams)
{
	struct bitcoin_blkid genesis;
	fromwire_bitcoin_blkid(cursor, max, &genesis);
	*chainparams = chainparams_by_chainhash(&genesis);
}
