#include <lightningd/ping.h>
#include <wire/gen_peer_wire.h>

bool check_ping_make_pong(const tal_t *ctx, const u8 *ping, u8 **pong)
{
	u16 num_pong_bytes;
	u8 *ignored;

	if (!fromwire_ping(ctx, ping, NULL, &num_pong_bytes, &ignored))
		return false;
	tal_free(ignored);

	/* FIXME: */
	/* BOLT #1:
	 *
	 * A node receiving a `ping` message SHOULD fail the channels if it
	 * has received significantly in excess of one `ping` per 30 seconds,
	 */

	/* BOLT #1:
	 *
	 * ... otherwise if `num_pong_bytes` is less than 65532 it MUST
	 * respond by sending a `pong` message with `byteslen` equal to
	 * `num_pong_bytes`, otherwise it MUST ignore the `ping`.
	 */
	if (num_pong_bytes < 65532) {
		/* BOLT #1:
		 *
		 * A node sending `pong` or `ping` SHOULD set `ignored` to
		 * zeroes, but MUST NOT set `ignored` to sensitive data such
		 * as secrets, or portions of initialized memory.
		*/
		ignored = tal_arrz(ctx, u8, num_pong_bytes);
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
	 * A node sending `pong` or `ping` SHOULD set `ignored` to zeroes, but
	 * MUST NOT set `ignored` to sensitive data such as secrets, or
	 * portions of initialized memory.
	 */
	u8 *ping, *ignored = tal_arrz(ctx, u8, padlen);

	ping = towire_ping(ctx, num_pong_bytes, ignored);
	tal_free(ignored);
	return ping;
}
