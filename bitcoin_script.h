#ifndef LIGHTNING_BITCOIN_SCRIPT_H
#define LIGHTNING_BITCOIN_SCRIPT_H
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include "lightning.pb-c.h"

struct bitcoin_address;
struct bitcoin_compressed_pubkey;

/* tal_count() gives the length of the script. */
u8 *bitcoin_redeem_2of2(const tal_t *ctx,
			const BitcoinPubkey *key1,
			const BitcoinPubkey *key2);

/* tal_count() gives the length of the script. */
u8 *bitcoin_redeem_single(const tal_t *ctx, const u8 *key, size_t keylen);

/* Create an output script using p2sh for this redeem script. */
u8 *scriptpubkey_p2sh(const tal_t *ctx, const u8 *redeemscript);

/* Create an output script to pay to pubkey hash */
u8 *scriptpubkey_pay_to_pubkeyhash(const tal_t *ctx,
				   const struct bitcoin_address *addr);

/* Create an input script to accept pay to pubkey */
u8 *scriptsig_pay_to_pubkeyhash(const tal_t *ctx,
				const struct bitcoin_address *addr,
				const u8 *signature,
				size_t sig_len);

/* Is this a normal pay to pubkey hash? */
bool is_pay_to_pubkey_hash(const ProtobufCBinaryData *script);

#endif /* LIGHTNING_BITCOIN_SCRIPT_H */
