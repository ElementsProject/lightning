#include <bitcoin/tx.h>
#include <common/channel_id.h>
#include <common/type_to_string.h>
#include <wire/wire.h>

void derive_channel_id(struct channel_id *channel_id,
		       const struct bitcoin_txid *txid, u16 txout)
{
	BUILD_ASSERT(sizeof(*channel_id) == sizeof(*txid));
	memcpy(channel_id, txid, sizeof(*channel_id));
	channel_id->id[sizeof(*channel_id)-2] ^= txout >> 8;
	channel_id->id[sizeof(*channel_id)-1] ^= txout;
}

void towire_channel_id(u8 **pptr, const struct channel_id *channel_id)
{
	towire(pptr, channel_id, sizeof(*channel_id));
}

void fromwire_channel_id(const u8 **cursor, size_t *max,
			 struct channel_id *channel_id)
{
	fromwire(cursor, max, channel_id, sizeof(*channel_id));
}

REGISTER_TYPE_TO_HEXSTR(channel_id);
