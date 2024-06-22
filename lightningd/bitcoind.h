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
struct feerate_est;
struct lightningd;
struct ripemd160;
struct bitcoin_tx;
struct bitcoin_block;

struct bitcoind {
	/* Where to do logging. */
	struct logger *log;

	/* Main lightningd structure */
	struct lightningd *ld;

	/* Is our Bitcoin backend synced?  If not, we retry. */
	bool synced;

	/* Ignore results, we're shutting down. */
	bool shutdown;

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
			      struct logger *log);

#define bitcoind_estimate_fees(ctx, bitcoind_, cb, arg)			\
	bitcoind_estimate_fees_((ctx), (bitcoind_),			\
				typesafe_cb_preargs(void, void *,	\
						    (cb), (arg),	\
						    struct lightningd *, \
						    u32,		\
						    const struct feerate_est *), \
				(arg))

void bitcoind_estimate_fees_(const tal_t *ctx,
			     struct bitcoind *bitcoind,
			     void (*cb)(struct lightningd *ld,
					u32 feerate_floor,
					const struct feerate_est *feerates,
					void *arg),
			     void *cb_arg);

/* If ctx is freed, cb won't be called! */
void bitcoind_sendrawtx_(const tal_t *ctx,
			 struct bitcoind *bitcoind,
			 const char *id_prefix TAKES,
			 const char *hextx,
			 bool allowhighfees,
			 void (*cb)(struct bitcoind *bitcoind,
				    bool success, const char *msg, void *),
			 void *arg);
#define bitcoind_sendrawtx(ctx, bitcoind_, id_prefix, hextx, allowhighfees, cb, arg) \
	bitcoind_sendrawtx_((ctx), (bitcoind_), (id_prefix), (hextx),	\
			    (allowhighfees),				\
			    typesafe_cb_preargs(void, void *,		\
						(cb), (arg),		\
						struct bitcoind *,	\
						bool, const char *),	\
			    (arg))

void bitcoind_getfilteredblock_(const tal_t *ctx,
				struct bitcoind *bitcoind, u32 height,
				void (*cb)(struct bitcoind *bitcoind,
					   const struct filteredblock *fb,
					   void *arg),
				void *arg);
#define bitcoind_getfilteredblock(ctx, bitcoind_, height, cb, arg)	\
	bitcoind_getfilteredblock_((ctx), (bitcoind_),			\
				   (height),				\
				   typesafe_cb_preargs(void, void *,	\
						       (cb), (arg),	\
						       struct bitcoind *, \
						       const struct filteredblock *), \
				   (arg))

void bitcoind_getchaininfo_(const tal_t *ctx,
			    struct bitcoind *bitcoind,
			    const u32 height,
			    void (*cb)(struct bitcoind *bitcoind,
				       const char *chain,
				       u32 headercount,
				       u32 blockcount,
				       bool ibd,
				       void *),
			    void *cb_arg);
#define bitcoind_getchaininfo(ctx, bitcoind_, height_, cb, arg)		\
	bitcoind_getchaininfo_((ctx), (bitcoind_), (height_),		\
			      typesafe_cb_preargs(void, void *,		   \
						  (cb), (arg),		   \
						  struct bitcoind *,	   \
						  const char *, u32, u32,  \
						  bool),		   \
			      (arg))

void bitcoind_getrawblockbyheight_(const tal_t *ctx,
				   struct bitcoind *bitcoind,
				   u32 height,
				   void (*cb)(struct bitcoind *bitcoind,
					      u32 height,
					      struct bitcoin_blkid *blkid,
					      struct bitcoin_block *blk,
					      void *arg),
				   void *arg);
#define bitcoind_getrawblockbyheight(ctx, bitcoind_, height_, cb, arg)	\
	bitcoind_getrawblockbyheight_((ctx), (bitcoind_), (height_),	\
				      typesafe_cb_preargs(void, void *,		\
							  (cb), (arg),		\
							  struct bitcoind *,	\
							  u32,			\
							  struct bitcoin_blkid *, \
							  struct bitcoin_block *),\
				      (arg))

void bitcoind_getutxout_(const tal_t *ctx,
			 struct bitcoind *bitcoind,
			 const struct bitcoin_outpoint *outpoint,
			 void (*cb)(struct bitcoind *,
				    const struct bitcoin_tx_output *,
				    void *),
			 void *arg);
#define bitcoind_getutxout(ctx, bitcoind_, outpoint_, cb, arg)		\
	bitcoind_getutxout_((ctx), (bitcoind_), (outpoint_),		\
			    typesafe_cb_preargs(void, void *,		\
					        (cb), (arg),		\
					        struct bitcoind *,	\
					        const struct bitcoin_tx_output *),\
			    (arg))

void bitcoind_check_commands(struct bitcoind *bitcoind);

#endif /* LIGHTNING_LIGHTNINGD_BITCOIND_H */
