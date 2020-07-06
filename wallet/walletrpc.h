#ifndef LIGHTNING_WALLET_WALLETRPC_H
#define LIGHTNING_WALLET_WALLETRPC_H
#include "config.h"

struct json_stream;
struct utxo;

void json_add_utxos(struct json_stream *response,
		    struct wallet *wallet,
		    struct utxo **utxos);

#endif /* LIGHTNING_WALLET_WALLETRPC_H */
