#ifndef LIGHTNING_COMMON_BOLT12_MERKLE_H
#define LIGHTNING_COMMON_BOLT12_MERKLE_H
#include "config.h"
#include <common/bolt12.h>

/**
 * merkle_tlv - bolt12-style merkle hash of this tlv minus signature fields
 * @fields: tal_arr of fields from tlv.
 * @merkle: returned merkle hash.
 */
void merkle_tlv(const struct tlv_field *fields, struct sha256 *merkle);

/**
 * sighash_from_merkle - bolt12-style signature hash using this merkle root.
 * @messagename: message name, such as "offer".
 * @fieldname: field name, such as "recurrence_signature".
 * @merkle: the merkle root as calculated by merkle_tlv.
 * @sighash: the returned hash.
 */
void sighash_from_merkle(const char *messagename,
			 const char *fieldname,
			 const struct sha256 *merkle,
			 struct sha256 *sighash);

/**
 * payer_key_tweak - get the actual tweak to use for a payer_key
 */
void payer_key_tweak(const struct point32 *bolt12,
		     const u8 *publictweak, size_t publictweaklen,
		     struct sha256 *tweak);

#endif /* LIGHTNING_COMMON_BOLT12_MERKLE_H */
