#ifndef LIGHTNING_DAEMON_WALLET_H
#define LIGHTNING_DAEMON_WALLET_H
#include "config.h"

struct wallet;
struct lightningd_state;
struct bitcoin_tx;
struct bitcoin_tx_output;

bool restore_wallet_address(struct lightningd_state *dstate,
			    const struct privkey *privkey);

void wallet_add_signed_input(struct lightningd_state *dstate,
			     const struct wallet *w,
			     struct bitcoin_tx *tx,
			     unsigned int input_num);

struct wallet *wallet_can_spend(struct lightningd_state *dstate,
				const struct bitcoin_tx_output *output);

#endif /* LIGHTNING_DAEMON_WALLET_H */
