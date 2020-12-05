#include <wire/wire.h>

#if !EXPERIMENTAL_FEATURES
/* Stubs, as this subtype is only defined when EXPERIMENTAL_FEATURES */
void towire_onionmsg_path(u8 **p, const struct onionmsg_path *onionmsg_path)
{
	abort();
}

struct onionmsg_path *
fromwire_onionmsg_path(const tal_t *ctx, const u8 **cursor, size_t *plen)
{
	abort();
}
#endif
