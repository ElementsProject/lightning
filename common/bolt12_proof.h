#ifndef LIGHTNING_COMMON_BOLT12_PROOF_H
#define LIGHTNING_COMMON_BOLT12_PROOF_H
#include "config.h"
#include <ccan/typesafe_cb/typesafe_cb.h>
#include <wire/bolt12_wiregen.h>

struct preimage;

/**
 * make_unsigned_proof - make an unsigned proof from this invoice
 * @ctx: tal context for the returned tlv
 * @inv: invoice we're creating the proof for
 * @preimage: preimage proving payment.
 * @note: optional string (can be NULL) to include in the proof.
 * @includefn: the function which indicates whether an invoice field should be included.
 * @arg: parameter for includefn.
 *
 * This is a generic helper to make a proof for an invoice.  To create a valid proof,
 * @includefn must return false for the following TLV type 0, and true for various other
 * fields (see spec quote below).
 */
/* BOLT-payer_proof #12:
 * A writer of a payer_proof:
 *  - MUST NOT include `invreq_metadata`.
 *  - MUST include `invreq_payer_id`, `invoice_payment_hash`,
 *    `invoice_node_id`, `signature` and (if present) `invoice_features` from
 *    the invoice.
 */
#define make_unsigned_proof(ctx, inv, preimage, note, includefn, arg)	\
	make_unsigned_proof_((ctx), (inv), (preimage), (note),		\
			     typesafe_cb_preargs(bool,			\
						 void *,		\
						 (includefn),		\
						 (arg),			\
						 const struct tlv_field *), \
			     arg)

struct tlv_payer_proof *make_unsigned_proof_(const tal_t *ctx,
					     const struct tlv_invoice *inv,
					     const struct preimage *preimage,
					     const char *note,
					     bool (*include_field)(const struct tlv_field *f, void *),
					     void *arg);

/**
 * payer_proof_signature - make a signature for a payer_proof
 * @ctx: tal context for the returned proof signature
 * @unsignedproof: merkle root hash, from make_unsigned_proof.
 * @signfn: function to sign using the `invreq_payer_id`.
 * @arg: parameter for @signfn.
 *
 * The signfn messagename will be "payer_proof", and fieldname will be
 * "proof_signature".  The msg is the concatentated hash of the note and
 * the merkle root.  It should sign using the invreq_payer_id key, and
 * return true on success.
 */
#define payer_proof_signature(ctx, unsignedproof, signfn, arg)		\
	payer_proof_signature_((ctx), (unsignedproof),			\
			       typesafe_cb_preargs(bool,		\
						   void *,		\
						   (signfn),		\
						   (arg),		\
						   const char *,	\
						   const char *,	\
						   const struct sha256 *, \
						   struct bip340sig *),	\
			       (arg))

struct bip340sig *payer_proof_signature_(const tal_t *ctx,
					 const struct tlv_payer_proof *unsignedproof,
					 bool (*sign)(const char *messagename,
						      const char *fieldname,
						      const struct sha256 *msg,
						      struct bip340sig *sig,
						      void *arg),
					 void *arg);
/**
 * bolt12_payer_proof_merkle - get the merkle root of this proof for signing.
 */
void bolt12_payer_proof_merkle(const struct tlv_payer_proof *proof,
			       struct sha256 *merkle);

/* Check the payer proof signatures are valid: returns NULL if so,
 * otherwise error string */
const char *check_payer_proof(const tal_t *ctx,
			      const struct tlv_payer_proof *pptlv);

/**
 * payer_proof_encode - encode this complete bolt12 payer_proof TLV into text.
 */
const char *payer_proof_encode(const tal_t *ctx, const struct tlv_payer_proof *pptlv);

/**
 * payer_proof_decode - decode this complete bolt12 text into a TLV.
 * @ctx: the context to allocate return or *@fail off.
 * @b12: the payer_proof string
 * @b12len: the payer_proof string length
 * @fail: pointer to descriptive error string, set if this returns NULL.
 */
struct tlv_payer_proof *payer_proof_decode(const tal_t *ctx,
					   const char *b12, size_t b12len,
					   const char **fail);

#endif /* LIGHTNING_COMMON_BOLT12_PROOF_H */
