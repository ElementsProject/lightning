#include "config.h"
#include <common/wallet.h>

enum wallet_tx_type fromwire_wallet_tx_type(const u8 **cursor, size_t *max)
{
	enum wallet_tx_type type = fromwire_u16(cursor, max);
	return type;
}

void towire_wallet_tx_type(u8 **pptr, const enum wallet_tx_type type)
{
	towire_u16(pptr, type);
}
