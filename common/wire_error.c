#include <ccan/mem/mem.h>
#include <ccan/tal/str/str.h>
#include <common/type_to_string.h>
#include <common/utils.h>
#include <common/wire_error.h>
#include <wire/gen_peer_wire.h>

u8 *towire_errorfmtv(const tal_t *ctx,
		     const struct channel_id *channel,
		     const char *fmt,
		     va_list ap)
{
	/* BOLT #1:
	 *
	 * The channel is referred to by `channel_id`, unless `channel_id` is
	 * 0 (i.e. all bytes are 0), in which case it refers to all
	 * channels. */
	static const struct channel_id all_channels;
	char *estr;
	u8 *msg;

	estr = tal_vfmt(ctx, fmt, ap);
	/* We need tal_len to work, so we use copy. */
	msg = towire_error(ctx, channel ? channel : &all_channels,
			   (u8 *)tal_dup_arr(estr, char, estr, strlen(estr), 0));
	tal_free(estr);

	return msg;
}

u8 *towire_errorfmt(const tal_t *ctx,
		    const struct channel_id *channel,
		    const char *fmt, ...)
{
	va_list ap;
	u8 *msg;

	va_start(ap, fmt);
	msg = towire_errorfmtv(ctx, channel, fmt, ap);
	va_end(ap);

	return msg;
}

bool channel_id_is_all(const struct channel_id *channel_id)
{
	return memeqzero(channel_id, sizeof(*channel_id));
}

char *sanitize_error(const tal_t *ctx, const u8 *errmsg,
		     struct channel_id *channel_id)
{
	struct channel_id dummy;
	u8 *data;
	size_t i;

	if (!channel_id)
		channel_id = &dummy;

	if (!fromwire_error(ctx, errmsg, channel_id, &data))
		return tal_fmt(ctx, "Invalid ERROR message '%s'",
			       tal_hex(ctx, errmsg));

	/* BOLT #1:
	 *
	 * The receiving node:
	 *...
	 *  - if `data` is not composed solely of printable ASCII characters
	 *   (For reference: the printable character set includes byte values 32
	 *   through 126, inclusive):
	 *    - SHOULD NOT print out `data` verbatim.
	 */
	for (i = 0; i < tal_len(data); i++) {
		if (data[i] < 32 || data[i] > 127) {
			/* Convert to hex, minus NUL term */
			data = (u8 *)tal_hex(ctx, data);
			tal_resize(&data, tal_len(data)-1);
			break;
		}
	}

	return tal_fmt(ctx, "channel %s: %.*s",
		       channel_id_is_all(channel_id)
		       ? "ALL"
		       : type_to_string(ctx, struct channel_id, channel_id),
		       (int)tal_len(data), (char *)data);
}
