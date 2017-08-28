#ifndef LIGHTNING_LIGHTNINGD_BITCOIND_H
#define LIGHTNING_LIGHTNINGD_BITCOIND_H
#include "config.h"
#include <bitcoin/chainparams.h>
#include <ccan/list/list.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <ccan/typesafe_cb/typesafe_cb.h>
#include <stdbool.h>

struct sha256_double;
struct lightningd;
struct ripemd160;
struct bitcoin_tx;
struct peer;
struct bitcoin_block;

enum bitcoind_mode {
	BITCOIND_MAINNET = 1,
	BITCOIND_TESTNET,
	BITCOIND_REGTEST
};

struct bitcoind {
	/* -datadir arg for bitcoin-cli. */
	char *datadir;

	/* Where to do logging. */
	struct log *log;

	/* Are we currently running a bitcoind request (it's ratelimited) */
	bool req_running;

	/* Pending requests. */
	struct list_head pending;

	/* What network are we on? */
	const struct chainparams *chainparams;
};

struct bitcoind *new_bitcoind(const tal_t *ctx, struct log *log);

void bitcoind_estimate_fee_(struct bitcoind *bitcoind,
			    void (*cb)(struct bitcoind *bitcoind,
				       u64, void *),
			    void *arg);

#define bitcoind_estimate_fee(bitcoind_, cb, arg)			\
	bitcoind_estimate_fee_((bitcoind_),				\
			       typesafe_cb_preargs(void, void *,	\
						   (cb), (arg),		\
						   struct bitcoind *,	\
						   u64),		\
			       (arg))

void bitcoind_sendrawtx_(struct bitcoind *bitcoind,
			 const char *hextx,
			 void (*cb)(struct bitcoind *bitcoind,
				    int exitstatus, const char *msg, void *),
			 void *arg);

#define bitcoind_sendrawtx(bitcoind_, hextx, cb, arg)			\
	bitcoind_sendrawtx_((bitcoind_), (hextx),			\
			    typesafe_cb_preargs(void, void *,		\
						(cb), (arg),		\
						struct bitcoind *,	\
						int, const char *),	\
			    (arg))

void bitcoind_get_chaintip_(struct bitcoind *bitcoind,
			    void (*cb)(struct bitcoind *bitcoind,
				       const struct sha256_double *tipid,
				       void *arg),
			    void *arg);

#define bitcoind_get_chaintip(bitcoind_, cb, arg)			\
	bitcoind_get_chaintip_((bitcoind_),				\
			       typesafe_cb_preargs(void, void *,	\
						   (cb), (arg),		\
						   struct bitcoind *,	\
						   const struct sha256_double *), \
			       (arg))

void bitcoind_getblockcount_(struct bitcoind *bitcoind,
			     void (*cb)(struct bitcoind *bitcoind,
					u32 blockcount,
					void *arg),
			     void *arg);

#define bitcoind_getblockcount(bitcoind_, cb, arg)			\
	bitcoind_getblockcount_((bitcoind_),				\
				typesafe_cb_preargs(void, void *,	\
						    (cb), (arg),	\
						    struct bitcoind *,	\
						    u32 blockcount),	\
				(arg))

void bitcoind_getblockhash_(struct bitcoind *bitcoind,
			    u32 height,
			    void (*cb)(struct bitcoind *bitcoind,
				       const struct sha256_double *blkid,
				       void *arg),
			    void *arg);
#define bitcoind_getblockhash(bitcoind_, height, cb, arg)		\
	bitcoind_getblockhash_((bitcoind_),				\
			       (height),				\
			       typesafe_cb_preargs(void, void *,	\
						   (cb), (arg),		\
						   struct bitcoind *,	\
						   const struct sha256_double *), \
			       (arg))

void bitcoind_getrawblock_(struct bitcoind *bitcoind,
			   const struct sha256_double *blockid,
			   void (*cb)(struct bitcoind *bitcoind,
				      struct bitcoin_block *blk,
				      void *arg),
			   void *arg);
#define bitcoind_getrawblock(bitcoind_, blkid, cb, arg)			\
	bitcoind_getrawblock_((bitcoind_), (blkid),			\
			      typesafe_cb_preargs(void, void *,		\
						  (cb), (arg),		\
						  struct bitcoind *,	\
						  struct bitcoin_block *), \
			      (arg))
#endif /* LIGHTNING_LIGHTNINGD_BITCOIND_H */
