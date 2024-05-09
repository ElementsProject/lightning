#include "config.h"
#include <assert.h>
#include <common/node_id.h>
#include <common/sciddir_or_pubkey.h>
#include <wire/wire.h>

/* BOLT-sciddir_or_pubkey #1:
 * * `sciddir_or_pubkey`: either 9 or 33 bytes referencing or identifying a node, respectively
 *    * if the first byte is 0 or 1, then an 8-byte `short_channel_id` follows for a total of 9 bytes
 *        * 0 for the first byte indicates this refers to `node_id_1` in the `channel_announcement` for `short_channel_id` (see [BOLT #7](07-routing-gossip.md#the-channel_announcement-message))
 *        * 1 for the first byte indicates this refers to `node_id_2` in the `channel_announcement` for `short_channel_id` (see [BOLT #7](07-routing-gossip.md#the-channel_announcement-message))
 *    * if the first byte is 2 or 3, then the value is a 33-byte `point`
 */
void towire_sciddir_or_pubkey(u8 **pptr,
			      const struct sciddir_or_pubkey *sciddpk)
{
	if (sciddpk->is_pubkey)
		towire_pubkey(pptr, &sciddpk->pubkey);
	else {
		assert(sciddpk->scidd.dir == 0 || sciddpk->scidd.dir == 1);
		towire_u8(pptr, sciddpk->scidd.dir);
		towire_short_channel_id(pptr, sciddpk->scidd.scid);
	}
}

void fromwire_sciddir_or_pubkey(const u8 **cursor, size_t *max,
				struct sciddir_or_pubkey *sciddpk)
{
	const u8 *peek = *cursor;
	size_t peek_max = *max;
	u8 firstbyte = fromwire_u8(&peek, &peek_max);

	if (firstbyte == 0 || firstbyte == 1) {
		sciddpk->is_pubkey = false;
		sciddpk->scidd.dir = fromwire_u8(cursor, max);
		sciddpk->scidd.scid = fromwire_short_channel_id(cursor, max);
	} else {
		sciddpk->is_pubkey = true;
		fromwire_pubkey(cursor, max, &sciddpk->pubkey);
	}
}

void sciddir_or_pubkey_from_pubkey(struct sciddir_or_pubkey *sciddpk,
				   const struct pubkey *pubkey)
{
	sciddpk->is_pubkey = true;
	sciddpk->pubkey = *pubkey;
}

bool sciddir_or_pubkey_from_node_id(struct sciddir_or_pubkey *sciddpk,
				    const struct node_id *node_id)
{
	sciddpk->is_pubkey = true;
	return pubkey_from_node_id(&sciddpk->pubkey, node_id);
}

void sciddir_or_pubkey_from_scidd(struct sciddir_or_pubkey *sciddpk,
				  const struct short_channel_id_dir *scidd)
{
	sciddpk->is_pubkey = false;
	sciddpk->scidd = *scidd;
	assert(sciddpk->scidd.dir == 0 || sciddpk->scidd.dir == 1);
}

const char *fmt_sciddir_or_pubkey(const tal_t *ctx,
				  const struct sciddir_or_pubkey *sciddpk)
{
	if (sciddpk->is_pubkey)
		return fmt_pubkey(ctx, &sciddpk->pubkey);
	return fmt_short_channel_id_dir(ctx, &sciddpk->scidd);
}
