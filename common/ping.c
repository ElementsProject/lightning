#include "config.h"
#include <common/ping.h>
#include <common/status.h>
#include <common/version.h>
#include <wire/peer_wire.h>

bool check_ping_make_pong(const tal_t *ctx, const u8 *ping, u8 **pong)
{
	u16 num_pong_bytes;
	u8 *ignored;

	if (!fromwire_ping(ctx, ping, &num_pong_bytes, &ignored))
		return false;
	tal_free(ignored);

	/* BOLT #1:
	 *
	 * A node receiving a `ping` message:
	 *  - if `num_pong_bytes` is less than 65532:
	 *    - MUST respond by sending a `pong` message, with `byteslen` equal
	 *      to `num_pong_bytes`.
	 *  - otherwise (`num_pong_bytes` is **not** less than 65532):
	 *    - MUST ignore the `ping`.
	 */
	if (num_pong_bytes < 65532) {
		/* BOLT #1:
		 *
		 * A node sending a `pong` message:
		 *   - SHOULD set `ignored` to 0s.
		 *   - MUST NOT set `ignored` to sensitive data such as secrets
		 *     or portions of initialized memory.
		 */
		ignored = tal_arrz(ctx, u8, num_pong_bytes);
#if DEVELOPER
		/* Embed version */
		strncpy((char *)ignored, version(), num_pong_bytes);
#endif
		*pong = towire_pong(ctx, ignored);
		tal_free(ignored);
	} else
		*pong = NULL;

	return true;
}

u8 *make_ping(const tal_t *ctx, u16 num_pong_bytes, u16 padlen)
{
	/* BOLT #1:
	 *
	 * A node sending a `ping` message:
	 *  - SHOULD set `ignored` to 0s.
	 *  - MUST NOT set `ignored` to sensitive data such as secrets or
	 *    portions of initialized memory.
	 */
	u8 *ping, *ignored = tal_arrz(ctx, u8, padlen);

	ping = towire_ping(ctx, num_pong_bytes, ignored);
	tal_free(ignored);
	return ping;
}
