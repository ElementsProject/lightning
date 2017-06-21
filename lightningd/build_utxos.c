#include <bitcoin/base58.h>
#include <bitcoin/script.h>
#include <ccan/structeq/structeq.h>
#include <daemon/jsonrpc.h>
#include <lightningd/build_utxos.h>
#include <lightningd/lightningd.h>
#include <utils.h>
#include <wally_bip32.h>


const struct utxo **build_utxos(const tal_t *ctx,
				struct lightningd *ld, u64 satoshi_out,
				u32 feerate_per_kw, u64 dust_limit,
				u64 *change_satoshis, u32 *change_keyindex)
{
	u64 fee_estimate = 0;
	u64 bip32_max_index = db_get_intvar(ld->wallet->db, "bip32_max_index", 0);
	const struct utxo **utxos =
	    wallet_select_coins(ctx, ld->wallet, satoshi_out, feerate_per_kw,
				&fee_estimate, change_satoshis);

	/* Oops, didn't have enough coins available */
	if (!utxos)
		return NULL;

	/* Do we need a change output? */
	if (*change_satoshis < dust_limit) {
		*change_satoshis = 0;
		*change_keyindex = 0;
	} else {
		*change_keyindex = bip32_max_index + 1;
		db_set_intvar(ld->wallet->db, "bip32_max_index", *change_keyindex);
	}
	return utxos;
}
