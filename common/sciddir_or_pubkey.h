#ifndef LIGHTNING_COMMON_SCIDDIR_OR_PUBKEY_H
#define LIGHTNING_COMMON_SCIDDIR_OR_PUBKEY_H
#include "config.h"
#include <bitcoin/pubkey.h>
#include <bitcoin/short_channel_id.h>

struct node_id;

struct sciddir_or_pubkey {
	bool is_pubkey;
	/* Only valid if is_pubkey is true */
	struct pubkey pubkey;
	/* Only valid if is_pubkey is false */
	struct short_channel_id_dir scidd;
};
void towire_sciddir_or_pubkey(u8 **pptr,
			      const struct sciddir_or_pubkey *sciddpk);
void fromwire_sciddir_or_pubkey(const u8 **cursor, size_t *max,
				struct sciddir_or_pubkey *sciddpk);

void sciddir_or_pubkey_from_pubkey(struct sciddir_or_pubkey *sciddpk,
				   const struct pubkey *pubkey);
WARN_UNUSED_RESULT
bool sciddir_or_pubkey_from_node_id(struct sciddir_or_pubkey *sciddpk,
				    const struct node_id *node_id);
void sciddir_or_pubkey_from_scidd(struct sciddir_or_pubkey *sciddpk,
				  const struct short_channel_id_dir *scidd);
const char *fmt_sciddir_or_pubkey(const tal_t *ctx,
				  const struct sciddir_or_pubkey *sciddpk);
#endif /* LIGHTNING_COMMON_SCIDDIR_OR_PUBKEY_H */
