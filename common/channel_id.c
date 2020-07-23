#include <bitcoin/pubkey.h>
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

void derive_channel_id_v2(struct channel_id *channel_id,
			  const struct pubkey *basepoint_1,
			  const struct pubkey *basepoint_2)
{
	u8 der_keys[PUBKEY_CMPR_LEN * 2];
	struct sha256 sha;
	int offset_1, offset_2;

	/* basepoint_1 is first? */
	if (pubkey_idx(basepoint_1, basepoint_2) == 0) {
		offset_1 = 0;
		offset_2 = PUBKEY_CMPR_LEN;
	} else {
		offset_1 = PUBKEY_CMPR_LEN;
		offset_2 = 0;
	}
	pubkey_to_der(der_keys + offset_1, basepoint_1);
	pubkey_to_der(der_keys + offset_2, basepoint_2);
	sha256(&sha, der_keys, sizeof(der_keys));
	BUILD_ASSERT(sizeof(*channel_id) == sizeof(sha));
	memcpy(channel_id, &sha, sizeof(*channel_id));
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
