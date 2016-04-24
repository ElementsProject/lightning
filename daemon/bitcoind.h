#ifndef LIGHTNING_DAEMON_BITCOIND_H
#define LIGHTNING_DAEMON_BITCOIND_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/typesafe_cb/typesafe_cb.h>
#include <stdbool.h>

struct sha256_double;
struct lightningd_state;
struct ripemd160;
struct bitcoin_tx;
struct peer;
/* -datadir arg for bitcoin-cli. */
extern char *bitcoin_datadir;

void bitcoind_watch_addr(struct lightningd_state *dstate,
			 const struct ripemd160 *redeemhash);

void bitcoind_poll_transactions(struct lightningd_state *dstate,
				void (*cb)(struct lightningd_state *dstate,
					   const struct sha256_double *txid,
					   int confirmations,
					   bool is_coinbase,
					   const struct sha256_double *blkhash));

void bitcoind_txid_lookup_(struct lightningd_state *dstate,
			  const struct sha256_double *txid,
			  void (*cb)(struct lightningd_state *dstate,
				     const struct bitcoin_tx *tx, void *),
			   void *arg);

#define bitcoind_txid_lookup(dstate, txid, cb, arg)			\
	bitcoind_txid_lookup_((dstate), (txid),				\
			      typesafe_cb_preargs(void, void *,		\
						  (cb), (arg),		\
						  struct lightningd_state *, \
						  const struct bitcoin_tx *), \
			      (arg))

void bitcoind_estimate_fee_(struct lightningd_state *dstate,
			    void (*cb)(struct lightningd_state *dstate,
				       u64, void *),
			    void *arg);

#define bitcoind_estimate_fee(dstate, cb, arg)				\
	bitcoind_estimate_fee_((dstate),				\
			       typesafe_cb_preargs(void, void *, \
						   (cb), (arg),		\
						   struct lightningd_state *, \
						   u64),		\
			       (arg))

void bitcoind_send_tx(struct lightningd_state *dstate,
		      const struct bitcoin_tx *tx);

void bitcoind_get_mediantime(struct lightningd_state *dstate,
			     const struct sha256_double *blockid,
			     u32 *mediantime);

void bitcoind_get_chaintips_(struct lightningd_state *dstate,
			     void (*cb)(struct lightningd_state *dstate,
					struct sha256_double *blockids,
					void *arg),
			     void *arg);

#define bitcoind_get_chaintips(dstate, cb, arg)				\
	bitcoind_get_chaintips_((dstate),				\
				typesafe_cb_preargs(void, void *,	\
						    (cb), (arg),	\
						    struct lightningd_state *, \
						    struct sha256_double *), \
				(arg))

void bitcoind_getblock_(struct lightningd_state *dstate,
			const struct sha256_double *blockid,
			void (*cb)(struct lightningd_state *dstate,
				   struct sha256_double *blkid,
				   struct sha256_double *prevblock,
				   struct sha256_double *txids,
				   u32 mediantime,
				   void *arg),
			void *arg);

#define bitcoind_getblock(dstate, blockid, cb, arg)		\
	bitcoind_getblock_((dstate), (blockid),			\
			   typesafe_cb_preargs(void, void *,		\
					       (cb), (arg),		\
					       struct lightningd_state *, \
					       struct sha256_double *,	\
					       struct sha256_double *,	\
					       struct sha256_double *,	\
					       u32 mediantime),		\
			   (arg))

void bitcoind_getblockcount_(struct lightningd_state *dstate,
			     void (*cb)(struct lightningd_state *dstate,
					u32 blockcount,
					void *arg),
			     void *arg);

#define bitcoind_getblockcount(dstate, cb, arg)		\
	bitcoind_getblockcount_((dstate),				\
				typesafe_cb_preargs(void, void *,	\
						    (cb), (arg),	\
						    struct lightningd_state *, \
						    u32 blockcount),	\
				(arg))

void bitcoind_getblockhash_(struct lightningd_state *dstate,
			    u32 height,
			    void (*cb)(struct lightningd_state *dstate,
				       const struct sha256_double *blkid,
				       void *arg),
			    void *arg);
#define bitcoind_getblockhash(dstate, height, cb, arg)			\
	bitcoind_getblockhash_((dstate),				\
			       (height),				\
			       typesafe_cb_preargs(void, void *,	\
						   (cb), (arg),		\
						   struct lightningd_state *, \
						   const struct sha256_double *), \
			       (arg))

void normalized_txid(const struct bitcoin_tx *tx, struct sha256_double *txid);

void check_bitcoind_config(struct lightningd_state *dstate);
#endif /* LIGHTNING_DAEMON_BITCOIND_H */
