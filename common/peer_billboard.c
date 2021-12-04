#include "config.h"
#include <ccan/tal/str/str.h>
#include <common/peer_billboard.h>
#include <common/status.h>
#include <common/status_wiregen.h>

void peer_billboard(bool perm, const char *fmt, ...)
{
	va_list ap;
	char *str;

	va_start(ap, fmt);
	str = tal_vfmt(NULL, fmt, ap);
	va_end(ap);

	status_debug("billboard%s: %s", perm ? " perm" : "", str);
	status_send(take(towire_status_peer_billboard(NULL, perm, str)));
	tal_free(str);
}
