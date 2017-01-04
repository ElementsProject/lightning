#ifndef LIGHTNING_TYPE_TO_STRING_H
#define LIGHTNING_TYPE_TO_STRING_H
#include "config.h"
#include <ccan/tal/tal.h>

/* This must match the type_to_string_ cases. */
union printable_types {
	const struct pubkey *pubkey;
	const struct sha256_double *sha256_double;
	const struct sha256 *sha256;
	const struct rel_locktime *rel_locktime;
	const struct abs_locktime *abs_locktime;
	const struct bitcoin_tx *bitcoin_tx;
	const struct htlc *htlc;
	const struct rval *rval;
	const struct channel_state *cstate;
	const struct channel_oneside *channel_oneside;
	const struct netaddr *netaddr;
	const char *charp_;
};

#define type_to_string(ctx, type, ptr)					\
	type_to_string_((ctx), stringify(type),				\
			((void)sizeof((ptr) == (type *)NULL),		\
			 ((union printable_types)((const type *)ptr))))

char *type_to_string_(const tal_t *ctx, const char *typename,
		      union printable_types u);

#endif /* LIGHTNING_UTILS_H */
