#ifndef LIGHTNING_COMMON_WALLET_H
#define LIGHTNING_COMMON_WALLET_H

#include "config.h"
#include <wire/wire.h>

/* Types of transactions we store in the `transactions` table. Mainly used for
 * display purposes later. */
enum wallet_tx_type {
       TX_UNKNOWN = 0,
       TX_THEIRS = 1,  /* This only affects their funds in the channel */
       TX_WALLET_DEPOSIT = 2,
       TX_WALLET_WITHDRAWAL = 4,
       TX_CHANNEL_FUNDING = 8,
       TX_CHANNEL_CLOSE = 16,
       TX_CHANNEL_UNILATERAL = 32,
       TX_CHANNEL_SWEEP = 64,
       TX_CHANNEL_HTLC_SUCCESS = 128,
       TX_CHANNEL_HTLC_TIMEOUT = 256,
       TX_CHANNEL_PENALTY = 512,
       TX_CHANNEL_CHEAT = 1024,
};

/* What part of a transaction are we annotating? The entire transaction, an
 * input or an output. */
enum wallet_tx_annotation_type {
	TX_ANNOTATION = 0,
	OUTPUT_ANNOTATION = 1,
	INPUT_ANNOTATION = 2,
};

enum wallet_tx_type fromwire_wallet_tx_type(const u8 **cursor, size_t *max);
void towire_wallet_tx_type(u8 **pptr, const enum wallet_tx_type type);

#endif /* LIGHTNING_COMMON_WALLET_H */
