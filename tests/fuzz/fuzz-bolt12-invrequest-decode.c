#include "config.h"
#include <assert.h>
#include <ccan/mem/mem.h>
#include <common/bolt12.h>
#include <common/utils.h>
#include <stddef.h>
#include <tests/fuzz/bolt12.h>
#include <tests/fuzz/libfuzz.h>

const char *bech32_hrp = "lnr";

static bool sciddir_or_pubkey_eq(const struct sciddir_or_pubkey *a,
				 const struct sciddir_or_pubkey *b)
{
	if (a->is_pubkey != b->is_pubkey)
		return false;
	if (a->is_pubkey)
		return pubkey_eq(&a->pubkey, &b->pubkey);
	else
		return short_channel_id_dir_eq(&a->scidd, &b->scidd);
}

static bool recurrence_eq(const struct recurrence *a, const struct recurrence *b)
{
	return a->time_unit == b->time_unit && a->period == b->period;
}

static bool recurrence_paywindow_eq(const struct recurrence_paywindow *a,
				    const struct recurrence_paywindow *b)
{
	return a->seconds_before == b->seconds_before &&
		a->seconds_after == b->seconds_after;
}

static bool recurrence_base_eq(const struct recurrence_base *a,
			       const struct recurrence_base *b)
{
	return a->proportional_amount == b->proportional_amount &&
		a->basetime == b->basetime;
}

static bool bip340sig_eq(const struct bip340sig *a, const struct bip340sig *b)
{
	return !memcmp(a, b, sizeof(struct bip340sig));
}

static bool blinded_path_eq(const struct blinded_path *a, const struct blinded_path *b)
{
	if (!sciddir_or_pubkey_eq(&a->first_node_id, &b->first_node_id))
		return false;
	if (!pubkey_eq(&a->first_path_key, &b->first_path_key))
		return false;
	if (tal_count(a->path) != tal_count(b->path))
		return false;
	for (size_t i = 0; i < tal_count(a->path); i++) {
		const struct blinded_path_hop *h1 = a->path[i];
		const struct blinded_path_hop *h2 = b->path[i];
		if (h1 == h2)
			continue;
		if (!h1 || !h2)
			return false;
		if (!pubkey_eq(&h1->blinded_node_id, &h2->blinded_node_id))
			return false;
		if (tal_bytelen(h1->encrypted_recipient_data) !=
			tal_bytelen(h2->encrypted_recipient_data))
			return false;
		if (memcmp(h1->encrypted_recipient_data, h2->encrypted_recipient_data,
				tal_bytelen(h1->encrypted_recipient_data)) != 0)
			return false;
	}
	return true;
}

static bool invreq_bip_353_name_eq(const struct bip_353_name *a,
				   const struct bip_353_name *b)
{
	if (a == b)
		return true;
	if (!a || !b)
		return false;
	if (!memeq(a->name, tal_bytelen(a->name), b->name, tal_bytelen(b->name)))
		return false;
	if (!memeq(a->domain, tal_bytelen(a->domain), b->domain, tal_bytelen(b->domain)))
		return false;
	return true;
}

static bool tlv_invoice_request_eq(const struct tlv_invoice_request *a, const struct tlv_invoice_request *b)
{

#define PTR_EQ(field, eqfn)							\
do {										\
	if (a->field != b->field) {						\
		if (!a->field || !b->field)					\
			return false;						\
		if (!eqfn(a->field, b->field))					\
			return false;						\
        }									\
} while (0)

#define MEM_EQ(field)								\
do {										\
	if (a->field != b->field) {						\
		if (!a->field || !b->field)					\
			return false;						\
		if (tal_bytelen(a->field) != tal_bytelen(b->field))		\
			return false;						\
		if (memcmp(a->field, b->field, tal_bytelen(a->field)) != 0)	\
			return false;						\
        }									\
} while (0)

#define VAL_EQ(field)								\
do {										\
	if (a->field != b->field) {						\
		if (!a->field || !b->field)					\
			return false;						\
		if (*a->field != *b->field)					\
			return false;						\
	}									\
} while (0)

#define ARR_EQ(field, eqfn)							\
do {										\
	if (a->field != b->field) {						\
		if (!a->field || !b->field)					\
			return false;						\
		if (tal_count(a->field) != tal_count(b->field))			\
			return false;						\
		for (size_t i = 0; i < tal_count(a->field); i++) {		\
			if (!eqfn(&a->field[i], &b->field[i]))			\
				return false;					\
		}								\
        }									\
} while (0)

#define PTR_ARR_EQ(field, eqfn)							\
do {										\
	if (a->field != b->field) {						\
		if (!a->field || !b->field)					\
			return false;						\
		if (tal_count(a->field) != tal_count(b->field))			\
			return false;						\
		for (size_t i = 0; i < tal_count(a->field); i++) {		\
			if (!eqfn(a->field[i], b->field[i]))			\
				return false;					\
		}								\
	}									\
} while (0)

	MEM_EQ(invreq_metadata);
	ARR_EQ(offer_chains, bitcoin_blkid_eq);
	MEM_EQ(offer_metadata);
	MEM_EQ(offer_currency);
	VAL_EQ(offer_amount);
	MEM_EQ(offer_description);
	MEM_EQ(offer_features);
	VAL_EQ(offer_absolute_expiry);
	PTR_ARR_EQ(offer_paths, blinded_path_eq);
	MEM_EQ(offer_issuer);
	VAL_EQ(offer_quantity_max);
	PTR_EQ(offer_issuer_id, pubkey_eq);
	PTR_EQ(offer_recurrence_optional, recurrence_eq);
	PTR_EQ(offer_recurrence_compulsory, recurrence_eq);
	PTR_EQ(offer_recurrence_paywindow, recurrence_paywindow_eq);
	VAL_EQ(offer_recurrence_limit);
	PTR_EQ(offer_recurrence_base, recurrence_base_eq);
	PTR_EQ(invreq_chain, bitcoin_blkid_eq);
	VAL_EQ(invreq_amount);
	MEM_EQ(invreq_features);
	VAL_EQ(invreq_quantity);
	PTR_EQ(invreq_payer_id, pubkey_eq);
	MEM_EQ(invreq_payer_note);
	PTR_ARR_EQ(invreq_paths, blinded_path_eq);
	PTR_EQ(invreq_bip_353_name, invreq_bip_353_name_eq);
	VAL_EQ(invreq_recurrence_counter);
	VAL_EQ(invreq_recurrence_start);
	PTR_EQ(signature, bip340sig_eq);

	return true;
}

void run(const u8 *data, size_t size)
{
	struct tlv_invoice_request *invreq, *decoded_invreq;
	char *fail = NULL, *encoded_invreq;

	invreq = invrequest_decode(tmpctx, (const char *)data, size,
			/*feature_set=*/NULL, /*must_be_chain=*/NULL, &fail);
	if (!invreq)
		goto cleanup;

	encoded_invreq = invrequest_encode(tmpctx, invreq);

	decoded_invreq = invrequest_decode(tmpctx, encoded_invreq, strlen(encoded_invreq),
					NULL, NULL, &fail);
	assert(!fail);
	assert(decoded_invreq);
	assert(tlv_invoice_request_eq(invreq, decoded_invreq));

cleanup:
	clean_tmpctx();
}
