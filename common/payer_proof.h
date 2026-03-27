#ifndef LIGHTNING_COMMON_PAYER_PROOF_H
#define LIGHTNING_COMMON_PAYER_PROOF_H
#include "config.h"
#include <bitcoin/preimage.h>
#include <bitcoin/privkey.h>
#include <wire/bolt12_wiregen.h>
#include <wire/tlvstream.h>

#define PAYER_PROOF_TLV_SIGNATURE 240
#define PAYER_PROOF_TLV_PREIMAGE 242
#define PAYER_PROOF_TLV_OMITTED_TLVS 244
#define PAYER_PROOF_TLV_MISSING_HASHES 246
#define PAYER_PROOF_TLV_LEAF_HASHES 248
#define PAYER_PROOF_TLV_PAYER_SIGNATURE 250

struct payer_proof {
	struct tlv_field *fields;
	struct tlv_invoice *invoice;
	struct bip340sig *invoice_signature;
	struct preimage *preimage;
	u64 *omitted_tlvs;
	struct sha256 *missing_hashes;
	struct sha256 *leaf_hashes;
	struct bip340sig *payer_signature;
	char *payer_note;
	struct sha256 merkle_root;
};

bool payer_proof_has_prefix(const char *str);

char *payer_proof_encode(const tal_t *ctx, const struct payer_proof *proof);

u8 *payer_proof_serialize(const tal_t *ctx, const struct payer_proof *proof);

struct payer_proof *payer_proof_decode(const tal_t *ctx,
				       const char *b12, size_t b12len,
				       char **fail);

struct payer_proof *payer_proof_from_invoice(const tal_t *ctx,
					     const struct tlv_invoice *invoice,
					     const struct preimage *preimage,
					     const struct secret *payer_secret,
					     const u64 *extra_include_types,
					     const char *note,
					     char **fail);
#endif /* LIGHTNING_COMMON_PAYER_PROOF_H */
