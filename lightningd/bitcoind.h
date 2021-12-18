#ifndef LIGHTNING_LIGHTNINGD_BITCOIND_H
#define LIGHTNING_LIGHTNINGD_BITCOIND_H
#include "config.h"
#include <bitcoin/chainparams.h>
#include <bitcoin/tx.h>
#include <ccan/list/list.h>
#include <ccan/strmap/strmap.h>

struct bitcoin_blkid;
struct bitcoin_tx_output;
struct block;
struct lightningd;
struct ripemd160;
struct bitcoin_tx;
struct bitcoin_block;

struct bitcoind {
	/* Where to do logging. */
	struct log *log;

	/* Main lightningd structure */
	struct lightningd *ld;

	/* Is our Bitcoin backend synced?  If not, we retry. */
	bool synced;

	/* Ignore results, we're shutting down. */
	bool shutdown;

	/* Timer if we're waiting for it to warm up. */
	struct oneshot *checkchain_timer;

	struct list_head pending_getfilteredblock;

	/* Map each method to a plugin, so we can have multiple plugins
	 * handling different functionalities. */
	STRMAP(struct plugin *) pluginsmap;
};

/* A single outpoint in a filtered block */
struct filteredblock_outpoint {
	struct bitcoin_outpoint outpoint;
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
			     size_t num_estimates,
			     void (*cb)(struct bitcoind *bitcoind,
					const u32 satoshi_per_kw[], void *),
			     void *arg);

#define bitcoind_estimate_fees(bitcoind_, num, cb, arg) \
	bitcoind_estimate_fees_((bitcoind_), (num), \
				typesafe_cb_preargs(void, void *,	\
						    (cb), (arg),	\
						    struct bitcoind *,	\
						    const u32 *),	\
				(arg))

void bitcoind_sendrawtx_ahf_(struct bitcoind *bitcoind,
			     const char *hextx,
			     bool allowhighfees,
			     void (*cb)(struct bitcoind *bitcoind,
					bool success, const char *msg, void *),
			     void *arg);
#define bitcoind_sendrawtx_ahf(bitcoind_, hextx, allowhighfees, cb, arg)\
	bitcoind_sendrawtx_ahf_((bitcoind_), (hextx),			\
				(allowhighfees),			\
				typesafe_cb_preargs(void, void *,	\
						    (cb), (arg),	\
						    struct bitcoind *,	\
						    bool, const char *),\
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
			 const struct bitcoin_outpoint *outpoint,
			 void (*cb)(struct bitcoind *bitcoind,
				    const struct bitcoin_tx_output *txout,
				    void *arg),
			 void *arg);
#define bitcoind_getutxout(bitcoind_, outpoint_, cb, arg)		\
	bitcoind_getutxout_((bitcoind_), (outpoint_),			\
			    typesafe_cb_preargs(void, void *,		\
					        (cb), (arg),		\
					        struct bitcoind *,	\
					        struct bitcoin_tx_output *),\
			    (arg))

void bitcoind_getclientversion(struct bitcoind *bitcoind);

void bitcoind_check_commands(struct bitcoind *bitcoind);

#endif /* LIGHTNING_LIGHTNINGD_BITCOIND_H */
