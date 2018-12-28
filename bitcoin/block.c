#include "bitcoin/block.h"
#include "bitcoin/pullpush.h"
#include "bitcoin/tx.h"
#include <ccan/str/hex/hex.h>
#include <common/type_to_string.h>

/* Encoding is <blockhdr> <varint-num-txs> <tx>... */
struct bitcoin_block *bitcoin_block_from_hex(const tal_t *ctx,
					     const char *hex, size_t hexlen)
{
	struct bitcoin_block *b;
	u8 *linear_tx;
	const u8 *p;
	size_t len, i, num;

	if (hexlen && hex[hexlen-1] == '\n')
		hexlen--;

	/* Set up the block for success. */
	b = tal(ctx, struct bitcoin_block);

	/* De-hex the array. */
	len = hex_data_size(hexlen);
	p = linear_tx = tal_arr(ctx, u8, len);
	if (!hex_decode(hex, hexlen, linear_tx, len))
		return tal_free(b);

	pull(&p, &len, &b->hdr, sizeof(b->hdr));
	num = pull_varint(&p, &len);
	b->tx = tal_arr(b, struct bitcoin_tx *, num);
	for (i = 0; i < num; i++)
		b->tx[i] = pull_bitcoin_tx(b->tx, &p, &len);

	/* We should end up not overrunning, nor have extra */
	if (!p || len)
		return tal_free(b);

	tal_free(linear_tx);
	return b;
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
