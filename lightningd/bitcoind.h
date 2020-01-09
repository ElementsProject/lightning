#ifndef LIGHTNING_LIGHTNINGD_BITCOIND_H
#define LIGHTNING_LIGHTNINGD_BITCOIND_H
#include "config.h"
#include <bitcoin/chainparams.h>
#include <bitcoin/tx.h>
#include <ccan/list/list.h>
#include <ccan/short_types/short_types.h>
#include <ccan/strmap/strmap.h>
#include <ccan/tal/tal.h>
#include <ccan/time/time.h>
#include <ccan/typesafe_cb/typesafe_cb.h>
#include <stdbool.h>

struct bitcoin_blkid;
struct bitcoin_tx_output;
struct block;
struct lightningd;
struct ripemd160;
struct bitcoin_tx;
struct bitcoin_block;

enum bitcoind_prio {
	BITCOIND_LOW_PRIO,
	BITCOIND_HIGH_PRIO
};
#define BITCOIND_NUM_PRIO (BITCOIND_HIGH_PRIO+1)

struct bitcoind {
	/* eg. "bitcoin-cli" */
	char *cli;

	/* -datadir arg for bitcoin-cli. */
	char *datadir;

	/* Where to do logging. */
	struct log *log;

	/* Main lightningd structure */
	struct lightningd *ld;

	/* Is bitcoind synced?  If not, we retry. */
	bool synced;

	/* How many high/low prio requests are we running (it's ratelimited) */
	size_t num_requests[BITCOIND_NUM_PRIO];

	/* Pending requests (high and low prio). */
	struct list_head pending[BITCOIND_NUM_PRIO];

	/* If non-zero, time we first hit a bitcoind error. */
	unsigned int error_count;
	struct timemono first_error_time;

	/* Ignore results, we're shutting down. */
	bool shutdown;

	/* How long to keep trying to contact bitcoind
	 * before fatally exiting. */
	u64 retry_timeout;

	/* Passthrough parameters for bitcoin-cli */
	char *rpcuser, *rpcpass, *rpcconnect, *rpcport;

	struct list_head pending_getfilteredblock;

	/* Map each method to a plugin, so we can have multiple plugins
	 * handling different functionalities. */
	STRMAP(struct plugin *) pluginsmap;
};

/* A single outpoint in a filtered block */
struct filteredblock_outpoint {
	struct bitcoin_txid txid;
	u32 outnum;
	u32 txindex;
	const u8 *scriptPubKey;
	struct amount_sat amount;
};

/* A struct representing a block with most of the parts filtered out. */
struct filteredblock {
	struct bitcoin_blkid id;
	u32 height;
	struct bitcoin_blkid prev_hash;
	struct filteredblock_outpoint **outpoints;
};

struct bitcoind *new_bitcoind(const tal_t *ctx,
			      struct lightningd *ld,
			      struct log *log);

void bitcoind_estimate_fees_(struct bitcoind *bitcoind,
			     const u32 blocks[], const char *estmode[],
			     size_t num_estimates,
			     void (*cb)(struct bitcoind *bitcoind,
					const u32 satoshi_per_kw[], void *),
			     void *arg);

#define bitcoind_estimate_fees(bitcoind_, blocks, estmode, num, cb, arg) \
	bitcoind_estimate_fees_((bitcoind_), (blocks), (estmode), (num), \
				typesafe_cb_preargs(void, void *,	\
						    (cb), (arg),	\
						    struct bitcoind *,	\
						    const u32 *),	\
				(arg))

void bitcoind_sendrawtx_(struct bitcoind *bitcoind,
			 const char *hextx,
			 void (*cb)(struct bitcoind *bitcoind,
				    bool success, const char *msg, void *),
			 void *arg);

#define bitcoind_sendrawtx(bitcoind_, hextx, cb, arg)			\
	bitcoind_sendrawtx_((bitcoind_), (hextx),			\
			    typesafe_cb_preargs(void, void *,		\
						(cb), (arg),		\
						struct bitcoind *,	\
						bool, const char *),	\
			    (arg))

void bitcoind_getfilteredblock_(struct bitcoind *bitcoind, u32 height,
				void (*cb)(struct bitcoind *bitcoind,
					   const struct filteredblock *fb,
					   void *arg),
				void *arg);
#define bitcoind_getfilteredblock(bitcoind_, height, cb, arg)		\
	bitcoind_getfilteredblock_((bitcoind_),				\
				   (height),				\
				   typesafe_cb_preargs(void, void *,	\
						       (cb), (arg),	\
						       struct bitcoind *, \
						       const struct filteredblock *), \
				   (arg))

void bitcoind_getchaininfo_(struct bitcoind *bitcoind,
			    const bool first_call,
			    void (*cb)(struct bitcoind *bitcoind,
				       const char *chain,
				       u32 headercount,
				       u32 blockcount,
				       const bool ibd,
				       const bool first_call, void *),
			    void *cb_arg);
#define bitcoind_getchaininfo(bitcoind_, first_call_, cb, arg)		   \
	bitcoind_getchaininfo_((bitcoind_), (first_call_),		   \
			      typesafe_cb_preargs(void, void *,		   \
						  (cb), (arg),		   \
						  struct bitcoind *,	   \
						  const char *, u32, u32,  \
						  const bool, const bool), \
			      (arg))

void bitcoind_getrawblockbyheight_(struct bitcoind *bitcoind,
				   u32 height,
				   void (*cb)(struct bitcoind *bitcoind,
					      struct bitcoin_blkid *blkid,
					      struct bitcoin_block *blk,
					      void *arg),
				   void *arg);
#define bitcoind_getrawblockbyheight(bitcoind_, height_, cb, arg)		\
	bitcoind_getrawblockbyheight_((bitcoind_), (height_),			\
				      typesafe_cb_preargs(void, void *,		\
							  (cb), (arg),		\
							  struct bitcoind *,	\
							  struct bitcoin_blkid *, \
							  struct bitcoin_block *),\
				      (arg))

void bitcoind_getutxout_(struct bitcoind *bitcoind,
			 const struct bitcoin_txid *txid, const u32 outnum,
			 void (*cb)(struct bitcoind *bitcoind,
				    const struct bitcoin_tx_output *txout,
				    void *arg),
			 void *arg);
#define bitcoind_getutxout(bitcoind_, txid_, vout_, cb, arg)		\
	bitcoind_getutxout_((bitcoind_), (txid_), (vout_),		\
			    typesafe_cb_preargs(void, void *,		\
					        (cb), (arg),		\
					        struct bitcoind *,	\
					        struct bitcoin_tx_output *),\
			    (arg))

void bitcoind_getclientversion(struct bitcoind *bitcoind);

void bitcoind_check_commands(struct bitcoind *bitcoind);

#endif /* LIGHTNING_LIGHTNINGD_BITCOIND_H */
