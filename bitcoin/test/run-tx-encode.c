#include <assert.h>
#include <bitcoin/pullpush.c>
#include <bitcoin/shadouble.c>
#include <bitcoin/tx.c>
#include <bitcoin/varint.c>
#include <ccan/str/hex/hex.h>
#include <common/utils.c>

const char extended_tx[] = "02000000000101b5bef485c41d0d1f58d1e8a561924ece5c476d86cff063ea10c8df06136eb31d00000000171600144aa38e396e1394fb45cbf83f48d1464fbc9f498fffffffff0140330f000000000017a9140580ba016669d3efaf09a0b2ec3954469ea2bf038702483045022100f2abf9e9cf238c66533af93f23937eae8ac01fb6f105a00ab71dbefb9637dc9502205c1ac745829b3f6889607961f5d817dfa0c8f52bdda12e837c4f7b162f6db8a701210204096eb817f7efb414ef4d3d8be39dd04374256d3b054a322d4a6ee22736d03b00000000";

static void hexeq(const void *p, size_t len, const char *hex)
{
	char *tmphex = tal_hexstr(NULL, p, len);

	if (!streq(hex, tmphex)) {
		fprintf(stderr, "Expected '%s' got '%s'", hex, tmphex);
		abort();
	}
	tal_free(tmphex);
}

static void tal_hexeq(const u8 *p, const char *hex)
{
	hexeq(p, tal_count(p),hex);
}

int main(void)
{
	setup_locale();

	struct bitcoin_tx *tx;

	tx = bitcoin_tx_from_hex(NULL, extended_tx, strlen(extended_tx));
	assert(tx);

	/* Canonical results from Nichola Dorier's
	 *	   http://n.bitcoin.ninja/checktx
	 * With much thanks!
	 */
	assert(tal_count(tx->input) == 1);
	assert(tal_count(tx->output) == 1);

	reverse_bytes(tx->input[0].txid.shad.sha.u.u8,
		      sizeof(tx->input[0].txid));
	hexeq(&tx->input[0].txid, sizeof(tx->input[0].txid),
	      "1db36e1306dfc810ea63f0cf866d475cce4e9261a5e8d1581f0d1dc485f4beb5");
	assert(tx->input[0].index == 0);

	/* This is a p2sh-p2wpkh: */
	/* ScriptSig is push of "version 0 + hash of pubkey" */
	hexeq(tx->input[0].script, tal_count(tx->input[0].script),
	      "16" "00" "144aa38e396e1394fb45cbf83f48d1464fbc9f498f");

	/* Witness with 2 items */
	assert(tx->input[0].witness);
	assert(tal_count(tx->input[0].witness) == 2);

	tal_hexeq(tx->input[0].witness[0],
		  "3045022100f2abf9e9cf238c66533af93f23937eae8ac01fb6f105a00ab71dbefb9637dc9502205c1ac745829b3f6889607961f5d817dfa0c8f52bdda12e837c4f7b162f6db8a701");
	tal_hexeq(tx->input[0].witness[1],
		  "0204096eb817f7efb414ef4d3d8be39dd04374256d3b054a322d4a6ee22736d03b");

	tal_free(tx);
	return 0;
}
