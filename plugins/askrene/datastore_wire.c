#include "config.h"
#include <plugins/askrene/datastore_wire.h>
#include <wire/wire.h>

/* FIXME: Generate this! */

/* Helper to append bool to data, and return value */
static bool towire_bool_val(u8 **pptr, bool v)
{
	towire_bool(pptr, v);
	return v;
}

static void towire_short_channel_id_dir(u8 **pptr, const struct short_channel_id_dir *scidd)
{
	towire_short_channel_id(pptr, scidd->scid);
	towire_u8(pptr, scidd->dir);
}

static void fromwire_short_channel_id_dir(const u8 **cursor, size_t *max,
					  struct short_channel_id_dir *scidd)
{
	scidd->scid = fromwire_short_channel_id(cursor, max);
	scidd->dir = fromwire_u8(cursor, max);
}

static struct amount_msat *fromwire_opt_amount_msat(const tal_t *ctx,
						    const u8 **cursor, size_t *len)
{
	struct amount_msat *msat;

	if (!fromwire_bool(cursor, len))
		return NULL;
	msat = tal(ctx, struct amount_msat);
	*msat = fromwire_amount_msat(cursor, len);
	return msat;
}

static u32 *fromwire_opt_u32(const tal_t *ctx, const u8 **cursor, size_t *len)
{
	u32 *v;

	if (!fromwire_bool(cursor, len))
		return NULL;
	v = tal(ctx, u32);
	*v = fromwire_u32(cursor, len);
	return v;
}

static u16 *fromwire_opt_u16(const tal_t *ctx, const u8 **cursor, size_t *len)
{
	u16 *v;

	if (!fromwire_bool(cursor, len))
		return NULL;
	v = tal(ctx, u16);
	*v = fromwire_u16(cursor, len);
	return v;
}

static bool *fromwire_opt_bool(const tal_t *ctx, const u8 **cursor, size_t *len)
{
	bool *v;

	if (!fromwire_bool(cursor, len))
		return NULL;
	v = tal(ctx, bool);
	*v = fromwire_bool(cursor, len);
	return v;
}

static const char *fromwire_opt_wirestring(const tal_t *ctx,
					   const u8 **cursor, size_t *len)
{
	if (!fromwire_bool(cursor, len))
		return NULL;
	return fromwire_wirestring(ctx, cursor, len);
}

static void towire_opt_u32(u8 **p, const u32 *v)
{
	if (towire_bool_val(p, v != NULL))
		towire_u32(p, *v);
}

static void towire_opt_u16(u8 **p, const u16 *v)
{
	if (towire_bool_val(p, v != NULL))
		towire_u16(p, *v);
}

static void towire_opt_bool(u8 **p, const bool *v)
{
	if (towire_bool_val(p, v != NULL))
		towire_bool(p, *v);
}

static void towire_opt_amount_msat(u8 **p, const struct amount_msat *v)
{
	if (towire_bool_val(p, v != NULL))
		towire_amount_msat(p, *v);
}

static void towire_opt_wirestring(u8 **p, const char *v)
{
	if (towire_bool_val(p, v != NULL))
		towire_wirestring(p, v);
}

bool fromwire_dstore_channel(const u8 **cursor, size_t *len,
			     struct node_id *n1,
			     struct node_id *n2,
			     struct short_channel_id *scid,
			     struct amount_msat *capacity)
{
	if (fromwire_u16(cursor, len) != DSTORE_CHANNEL) {
		fromwire_fail(cursor, len);
		return false;
	}
	fromwire_node_id(cursor, len, n1);
	fromwire_node_id(cursor, len, n2);
	*scid = fromwire_short_channel_id(cursor, len);
	*capacity = fromwire_amount_msat(cursor, len);

	return *cursor != NULL;
}

void towire_dstore_channel(u8 **data,
			   const struct node_id *n1,
			   const struct node_id *n2,
			   struct short_channel_id scid,
			   struct amount_msat capacity)
{
	towire_u16(data, DSTORE_CHANNEL);
	towire_node_id(data, n1);
	towire_node_id(data, n2);
	towire_short_channel_id(data, scid);
	towire_amount_msat(data, capacity);
}

bool fromwire_dstore_channel_update(const tal_t *ctx,
				    const u8 **cursor, size_t *len,
				    struct short_channel_id_dir *scidd,
				    bool **enabled,
				    struct amount_msat **htlc_min,
				    struct amount_msat **htlc_max,
				    struct amount_msat **base_fee,
				    u32 **proportional_fee,
				    u16 **delay)
{
	if (fromwire_u16(cursor, len) != DSTORE_CHANNEL_UPDATE) {
		fromwire_fail(cursor, len);
		return false;
	}

	fromwire_short_channel_id_dir(cursor, len, scidd);
	*enabled = fromwire_opt_bool(ctx, cursor, len);
	*htlc_min = fromwire_opt_amount_msat(ctx, cursor, len);
	*htlc_max = fromwire_opt_amount_msat(ctx, cursor, len);
	*base_fee = fromwire_opt_amount_msat(ctx, cursor, len);
	*proportional_fee = fromwire_opt_u32(ctx, cursor, len);
	*delay = fromwire_opt_u16(ctx, cursor, len);

	return *cursor != NULL;
}

void towire_dstore_channel_update(u8 **data,
				  const struct short_channel_id_dir *scidd,
				  const bool *enabled,
				  const struct amount_msat *htlc_min,
				  const struct amount_msat *htlc_max,
				  const struct amount_msat *base_fee,
				  const u32 *proportional_fee,
				  const u16 *delay)
{
	towire_u16(data, DSTORE_CHANNEL_UPDATE);
	towire_short_channel_id_dir(data, scidd);
	towire_opt_bool(data, enabled);
	towire_opt_amount_msat(data, htlc_min);
	towire_opt_amount_msat(data, htlc_max);
	towire_opt_amount_msat(data, base_fee);
	towire_opt_u32(data, proportional_fee);
	towire_opt_u16(data, delay);
}

bool fromwire_dstore_channel_constraint(const tal_t *ctx,
					const u8 **cursor, size_t *len,
					struct short_channel_id_dir *scidd,
					u64 *timestamp,
					struct amount_msat **min,
					struct amount_msat **max)
{
	if (fromwire_u16(cursor, len) != DSTORE_CHANNEL_CONSTRAINT) {
		fromwire_fail(cursor, len);
		return false;
	}

	fromwire_short_channel_id_dir(cursor, len, scidd);
	*timestamp = fromwire_u64(cursor, len);
	*min = fromwire_opt_amount_msat(ctx, cursor, len);
	*max = fromwire_opt_amount_msat(ctx, cursor, len);

	return *cursor != NULL;
}

void towire_dstore_channel_constraint(u8 **data,
				      const struct short_channel_id_dir *scidd,
				      u64 timestamp,
				      const struct amount_msat *min,
				      const struct amount_msat *max)
{
	towire_u16(data, DSTORE_CHANNEL_CONSTRAINT);
	towire_short_channel_id_dir(data, scidd);
	towire_u64(data, timestamp);
	towire_opt_amount_msat(data, min);
	towire_opt_amount_msat(data, max);
}

bool fromwire_dstore_channel_bias(const tal_t *ctx,
				  const u8 **cursor, size_t *len,
				  struct short_channel_id_dir *scidd,
				  s8 *bias_factor,
				  const char **description)
{
	if (fromwire_u16(cursor, len) != DSTORE_CHANNEL_BIAS) {
		fromwire_fail(cursor, len);
		return false;
	}

	fromwire_short_channel_id_dir(cursor, len, scidd);
	*bias_factor = fromwire_s8(cursor, len);
	*description = fromwire_opt_wirestring(ctx, cursor, len);

	return *cursor != NULL;
}

void towire_dstore_channel_bias(u8 **data,
				const struct short_channel_id_dir *scidd,
				s8 bias_factor,
				const char *description)
{
	towire_u16(data, DSTORE_CHANNEL_BIAS);
	towire_short_channel_id_dir(data, scidd);
	towire_s8(data, bias_factor);
	towire_opt_wirestring(data, description);
}

bool fromwire_dstore_channel_bias_v2(const tal_t *ctx,
				     const u8 **cursor, size_t *len,
				     struct short_channel_id_dir *scidd,
				     s8 *bias_factor,
				     const char **description,
				     u64 *timestamp)
{
	if (fromwire_u16(cursor, len) != DSTORE_CHANNEL_BIAS_V2) {
		fromwire_fail(cursor, len);
		return false;
	}

	fromwire_short_channel_id_dir(cursor, len, scidd);
	*bias_factor = fromwire_s8(cursor, len);
	*description = fromwire_opt_wirestring(ctx, cursor, len);
	*timestamp = fromwire_u64(cursor, len);

	return *cursor != NULL;
}

void towire_dstore_channel_bias_v2(u8 **data,
				   const struct short_channel_id_dir *scidd,
				   s8 bias_factor,
				   const char *description,
				   u64 timestamp)
{
	towire_u16(data, DSTORE_CHANNEL_BIAS_V2);
	towire_short_channel_id_dir(data, scidd);
	towire_s8(data, bias_factor);
	towire_opt_wirestring(data, description);
	towire_u64(data, timestamp);
}

bool fromwire_dstore_node_bias(const tal_t *ctx,
			       const u8 **cursor, size_t *len,
			       struct node_id *node,
			       const char **description,
			       s8 *in_bias, s8 *out_bias,
			       u64 *timestamp)
{
	if (fromwire_u16(cursor, len) != DSTORE_NODE_BIAS) {
		fromwire_fail(cursor, len);
		return false;
	}

	fromwire_node_id(cursor, len, node);
	*in_bias = fromwire_s8(cursor, len);
	*out_bias = fromwire_s8(cursor, len);
	*description = fromwire_opt_wirestring(ctx, cursor, len);
	*timestamp = fromwire_u64(cursor, len);

	return *cursor != NULL;
}

void towire_dstore_node_bias(u8 **data,
			     const struct node_id *node,
			     const char *description,
			     s8 in_bias, s8 out_bias,
			     u64 timestamp)
{
	towire_u16(data, DSTORE_NODE_BIAS);
	towire_node_id(data, node);
	towire_s8(data, in_bias);
	towire_s8(data, out_bias);
	towire_opt_wirestring(data, description);
	towire_u64(data, timestamp);
}

bool fromwire_dstore_disabled_node(const u8 **cursor, size_t *len,
				   struct node_id *node)
{
	if (fromwire_u16(cursor, len) != DSTORE_DISABLED_NODE) {
		fromwire_fail(cursor, len);
		return false;
	}

	fromwire_node_id(cursor, len, node);
	return *cursor != NULL;
}

void towire_dstore_disabled_node(u8 **data, const struct node_id *node)
{
	towire_u16(data, DSTORE_DISABLED_NODE);
	towire_node_id(data, node);
}
