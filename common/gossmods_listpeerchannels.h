#ifndef LIGHTNING_COMMON_GOSSMODS_LISTPEERCHANNELS_H
#define LIGHTNING_COMMON_GOSSMODS_LISTPEERCHANNELS_H
#include "config.h"
#include <bitcoin/short_channel_id.h>
#include <ccan/typesafe_cb/typesafe_cb.h>
#include <common/amount.h>
#include <common/json_parse_simple.h>

struct node_id;

/**
 * gossmods_from_listpeerchannels: create gossmap_localmods from `listpeerchannels`
 * @ctx: context to allocate return from
 * @buf: the JSON buffer from listpeerchannels
 * @toks: the JSON tokens
 * @zero_rates: set fees and cltv delay for these channels to 0 (better for routing)
 * @cb: optional per-channel callback.
 * @cbarg: arg for @cb.
 *
 * This constructs a set of modifications you can apply to your gossmap to include
 * local (esp. private) channels.  You can also have an optional per-channel callback
 * for special effects.
 */
struct gossmap_localmods *gossmods_from_listpeerchannels_(const tal_t *ctx,
							  const struct node_id *self,
							  const char *buf,
							  const jsmntok_t *toks,
							  bool zero_rates,
							  void (*cb)(struct gossmap_localmods *mods,
								     const struct node_id *self_,
								     const struct node_id *peer,
								     const struct short_channel_id_dir *scidd,
								     struct amount_msat htlcmin,
								     struct amount_msat htlcmax,
								     struct amount_msat spendable,
								     struct amount_msat fee_base,
								     u32 fee_proportional,
								     u32 cltv_delta,
								     bool enabled,
								     bool is_local,
								     const char *buf_,
								     const jsmntok_t *chantok,
								     void *cbarg_),
							  void *cbarg);

#define gossmods_from_listpeerchannels(ctx, self, buf, toks, zero_rates, cb, cbarg) \
	gossmods_from_listpeerchannels_((ctx), (self), (buf), (toks), (zero_rates), \
					typesafe_cb_preargs(void, void *, (cb), (cbarg), \
							    struct gossmap_localmods *, \
							    const struct node_id *, \
							    const struct node_id *, \
							    const struct short_channel_id_dir *, \
							    struct amount_msat,	\
							    struct amount_msat,	\
							    struct amount_msat,	\
							    struct amount_msat,	\
							    u32,	\
							    u32,	\
							    bool,	\
							    bool,	\
							    const char *, \
							    const jsmntok_t *), \
					(cbarg))

/* Callback which simply adds to gossmap. */
void gossmod_add_localchan(struct gossmap_localmods *mods,
			   const struct node_id *self,
			   const struct node_id *peer,
			   const struct short_channel_id_dir *scidd,
			   struct amount_msat htlcmin,
			   struct amount_msat htlcmax,
			   struct amount_msat spendable,
			   struct amount_msat fee_base,
			   u32 fee_proportional,
			   u32 cltv_delta,
			   bool enabled,
			   bool is_local,
			   const char *buf UNUSED,
			   const jsmntok_t *chantok UNUSED,
			   void *cbarg UNUSED);

#endif /* LIGHTNING_COMMON_GOSSMODS_LISTPEERCHANNELS_H */
