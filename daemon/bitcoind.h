#ifndef LIGHTNING_DAEMON_BITCOIND_H
#define LIGHTNING_DAEMON_BITCOIND_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/typesafe_cb/typesafe_cb.h>

struct sha256_double;
struct lightningd_state;
struct ripemd160;
struct bitcoin_tx;
struct peer;

void bitcoind_watch_addr(struct lightningd_state *dstate,
			 const struct ripemd160 *redeemhash);

void bitcoind_poll_transactions(struct lightningd_state *dstate,
				void (*cb)(struct lightningd_state *dstate,
					   const struct sha256_double *txid,
					   int confirmations));

void bitcoind_txid_lookup_(struct lightningd_state *dstate,
			  const struct sha256_double *txid,
			  void (*cb)(struct lightningd_state *dstate,
				     const struct bitcoin_tx *tx, void *),
			   void *arg);

#define bitcoind_txid_lookup(dstate, txid, cb, arg)			\
	bitcoind_txid_lookup_((dstate), (txid),				\
			      typesafe_cb_preargs(struct io_plan *, void *, \
						  (cb), (arg),		\
						  struct lightningd_state *, \
						  const struct bitcoin_tx *), \
			      (arg))

void bitcoind_send_tx(struct lightningd_state *dstate,
		      const struct bitcoin_tx *tx);

void bitcoind_create_payment(struct lightningd_state *dstate,
			     const char *addr,
			     u64 satoshis,
			     void (*cb)(struct lightningd_state *dstate,
					const struct bitcoin_tx *tx,
					struct peer *peer),
			     struct peer *peer);

#endif /* LIGHTNING_DAEMON_BITCOIND_H */
