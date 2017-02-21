#include <lightningd/utxo.h>
#include <wire/wire.h>

void towire_utxo(u8 **pptr, const struct utxo *utxo)
{
	towire_sha256_double(pptr, &utxo->txid);
	towire_u32(pptr, utxo->outnum);
	towire_u64(pptr, utxo->amount);
	towire_u32(pptr, utxo->keyindex);
	towire_bool(pptr, utxo->is_p2sh);
}

void fromwire_utxo(const u8 **ptr, size_t *max, struct utxo *utxo)
{
	fromwire_sha256_double(ptr, max, &utxo->txid);
	utxo->outnum = fromwire_u32(ptr, max);
	utxo->amount = fromwire_u64(ptr, max);
	utxo->keyindex = fromwire_u32(ptr, max);
	utxo->is_p2sh = fromwire_bool(ptr, max);
}

void fromwire_utxo_array(const u8 **ptr, size_t *max,
			 struct utxo *utxo, size_t num)
{
	size_t i;

	for (i = 0; i < num; i++)
		fromwire_utxo(ptr, max, &utxo[i]);
}

void towire_utxo_array(u8 **pptr, const struct utxo *utxo, size_t num)
{
	size_t i;

	for (i = 0; i < num; i++)
		towire_utxo(pptr, &utxo[i]);
}
