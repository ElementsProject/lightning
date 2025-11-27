#ifndef LIGHTNING_PLUGINS_ASKRENE_DATASTORE_WIRE_H
#define LIGHTNING_PLUGINS_ASKRENE_DATASTORE_WIRE_H
#include "config.h"
#include <bitcoin/short_channel_id.h>
#include <ccan/short_types/short_types.h>
#include <common/amount.h>
#include <common/node_id.h>
#include <stdbool.h>

/* Different elements in the datastore */
enum dstore_layer_type {
	/* We don't use type 0, which fromwire_u16 returns on trunction */
	DSTORE_CHANNEL = 1,
	DSTORE_CHANNEL_UPDATE = 2,
	DSTORE_CHANNEL_CONSTRAINT = 3,
	DSTORE_CHANNEL_BIAS = 4,
	DSTORE_DISABLED_NODE = 5,
	DSTORE_CHANNEL_BIAS_V2 = 6,
	DSTORE_NODE_BIAS = 7,
};

bool fromwire_dstore_channel(const u8 **cursor, size_t *len,
			     struct node_id *n1,
			     struct node_id *n2,
			     struct short_channel_id *scid,
			     struct amount_msat *capacity);
void towire_dstore_channel(u8 **data,
			   const struct node_id *n1,
			   const struct node_id *n2,
			   struct short_channel_id scid,
			   struct amount_msat capacity);

bool fromwire_dstore_channel_update(const tal_t *ctx,
				    const u8 **cursor, size_t *len,
				    struct short_channel_id_dir *scidd,
				    bool **enabled,
				    struct amount_msat **htlc_min,
				    struct amount_msat **htlc_max,
				    struct amount_msat **base_fee,
				    u32 **proportional_fee,
				    u16 **delay);
void towire_dstore_channel_update(u8 **data,
				  const struct short_channel_id_dir *scidd,
				  const bool *enabled,
				  const struct amount_msat *htlc_min,
				  const struct amount_msat *htlc_max,
				  const struct amount_msat *base_fee,
				  const u32 *proportional_fee,
				  const u16 *delay);

bool fromwire_dstore_channel_constraint(const tal_t *ctx,
					const u8 **cursor, size_t *len,
					struct short_channel_id_dir *scidd,
					u64 *timestamp,
					struct amount_msat **min,
					struct amount_msat **max);
void towire_dstore_channel_constraint(u8 **data,
				      const struct short_channel_id_dir *scidd,
				      u64 timestamp,
				      const struct amount_msat *min,
				      const struct amount_msat *max);

bool fromwire_dstore_channel_bias(const tal_t *ctx,
				  const u8 **cursor, size_t *len,
				  struct short_channel_id_dir *scidd,
				  s8 *bias_factor,
				  const char **description);
void towire_dstore_channel_bias(u8 **data,
				const struct short_channel_id_dir *scidd,
				s8 bias_factor,
				const char *description);

bool fromwire_dstore_channel_bias_v2(const tal_t *ctx,
				     const u8 **cursor, size_t *len,
				     struct short_channel_id_dir *scidd,
				     s8 *bias_factor,
				     const char **description,
				     u64 *timestamp);
void towire_dstore_channel_bias_v2(u8 **data,
				   const struct short_channel_id_dir *scidd,
				   s8 bias_factor,
				   const char *description,
				   u64 timestamp);

bool fromwire_dstore_node_bias(const tal_t *ctx,
			       const u8 **cursor, size_t *len,
			       struct node_id *node,
			       const char **description,
			       s8 *in_bias, s8 *out_bias,
			       u64 *timestamp);
void towire_dstore_node_bias(u8 **data,
			     const struct node_id *node,
			     const char *description,
			     s8 in_bias, s8 out_bias,
			     u64 timestamp);

void towire_dstore_disabled_node(u8 **data, const struct node_id *node);
bool fromwire_dstore_disabled_node(const u8 **cursor, size_t *len,
				   struct node_id *node);

#endif /* LIGHTNING_PLUGINS_ASKRENE_DATASTORE_WIRE_H */
