#ifndef LIGHTNING_COMMON_BOLT12_MERKLE_H
#define LIGHTNING_COMMON_BOLT12_MERKLE_H
#include "config.h"
#include <ccan/typesafe_cb/typesafe_cb.h>
#include <common/bolt12.h>

/**
 * merkle_tlv - bolt12-style merkle hash of this tlv minus signature fields
 * @fields: tal_arr of fields from tlv.
 * @merkle: returned merkle hash.
 */
void merkle_tlv(const struct tlv_field *fields, struct sha256 *merkle);

/**
 * merkle_tlv_full - generic TLV merkle, handling omitted fields.
 * @merkle: returned merkle hash.
 * @next_field: iterator to return next field, setting is_omitted true
 *   if it is omitted from the hash.
 * @calc_nonce: function to determine the nonce hash.  lnnonce_ctx
 *   is the partial H("LnNonce"||first-tlv,...) of the first TLV.
 * @resolve_omitted: called when an omitted hash is used (or must be retrieved).
 * @arg: parameter to pass to @next_field and @resolve_omitted.
 */
#define merkle_tlv_full(merkle, next_field, calc_nonce, resolve_omitted, arg) \
	merkle_tlv_full_((merkle),					\
			 typesafe_cb_preargs(const struct tlv_field *,	\
					     void *,			\
					     (next_field),		\
					     (arg),			\
					     bool *),			\
			 typesafe_cb_preargs(void,			\
					     void *,			\
					     (calc_nonce),		\
					     (arg),			\
					     const struct sha256_ctx *, \
					     bigsize_t,			\
					     struct sha256 *),		\
			 typesafe_cb_preargs(void,			\
					     void *,			\
					     (resolve_omitted),		\
					     (arg),			\
					     struct sha256 *),		\
			 (arg))

void merkle_tlv_full_(struct sha256 *merkle,
		      const struct tlv_field *(*next_field)(bool *is_omitted,
							    void *arg),
		      void (*calc_nonce)(const struct sha256_ctx *lnnonce_ctx,
					 bigsize_t fieldtype,
					 struct sha256 *hash, void *arg),
		      void (*resolve_omitted)(struct sha256 *h, void *arg),
		      void *arg);

/* Helper to create lnnonce_ctx from TLV0 */
void bolt12_lnnonce_ctx(struct sha256_ctx *sctx, const struct tlv_field *field);

/* Helper to calculate the nonce hash given lnnonce_ctx and a field type */
void bolt12_calc_nonce(const struct sha256_ctx *lnnonce_ctx,
		       bigsize_t fieldtype,
		       struct sha256 *hash,
		       void *unused);

/* BOLT #12:
 * Each form is signed using one or more *signature TLV elements*: TLV
 * types 240 through 1000 (inclusive).
 */
bool is_tlv_signature_field(const struct tlv_field *field);

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
#endif /* LIGHTNING_COMMON_BOLT12_MERKLE_H */
