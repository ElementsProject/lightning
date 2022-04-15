#include "config.h"
#include <assert.h>
#include <common/zeroconf.h>
#include <wire/wire.h>


struct zeroconf_options *zeroconf_options_new(const tal_t *ctx)
{
	struct zeroconf_options *z = tal(ctx, struct zeroconf_options);
	z->allow_all = false;
	z->allowlist = tal_arr(z, struct node_id, 0);
	return z;
}

bool fromwire_zeroconf_options(const u8 **cursor, size_t *max,
			       struct zeroconf_options *opts)
{
	size_t listsize;
	opts->allow_all = fromwire_bool(cursor, max);

	listsize = fromwire_u16(cursor, max);
	opts->allowlist = tal_arr(opts, struct node_id, listsize);
	for (size_t i = 0; i < listsize; i++)
		fromwire_node_id(cursor, max, &opts->allowlist[i]);
	return *cursor != NULL;
}
void towire_zeroconf_options(u8 **pptr, const struct zeroconf_options *opts)
{
	towire_bool(pptr, opts->allow_all);
	assert(opts->allowlist != NULL);
	towire_u16(pptr, tal_count(opts->allowlist));
	for (size_t i = 0; i < tal_count(opts->allowlist); i++)
		towire_node_id(pptr, &opts->allowlist[i]);
}

bool zeroconf_allow_peer(const struct zeroconf_options *zopts,
			 const struct node_id *node_id)
{
	if (zopts->allow_all)
		return true;

	for (size_t i=0; i<tal_count(zopts->allowlist); i++)
		if (node_id_eq(node_id, &zopts->allowlist[i]))
			return true;
	return false;
}
