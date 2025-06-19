#include "config.h"
#include <ccan/mem/mem.h>
#include <wire/bolt12_wiregen.h>
#include <common/setup.h>
#include <tests/fuzz/libfuzz.h>
#include <wire/peer_wire.h>

static bool sciddir_or_pubkey_eq(const struct sciddir_or_pubkey *a,
                                 const struct sciddir_or_pubkey *b)
{
	return memcmp(a, b, sizeof(*a)) == 0;
}

static bool blinded_path_eq(const struct blinded_path *a,
                            const struct blinded_path *b)
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

static bool invreq_bip_353_name_eq(const struct tlv_invoice_request_invreq_bip_353_name *a,
                                   const struct tlv_invoice_request_invreq_bip_353_name *b)
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

#define PTR_ARR_EQ(field, eqfn)						\
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

#define STRUCT_EQ(field, type)							\
do {										\
	if (a->field != b->field) {						\
		if (!a->field || !b->field)					\
			return false;						\
		if (memcmp(a->field, b->field, sizeof(type)) != 0)		\
			return false;						\
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
	STRUCT_EQ(offer_recurrence, struct recurrence);
	STRUCT_EQ(offer_recurrence_paywindow, struct recurrence_paywindow);
	VAL_EQ(offer_recurrence_limit);
	STRUCT_EQ(offer_recurrence_base, struct recurrence_base);
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
	STRUCT_EQ(signature, struct bip340sig);

	return true;
}


void init(int *argc, char ***argv)
{
	common_setup("fuzzer");
}

void run(const u8 *data, size_t size)
{
	if (size < sizeof(struct tlv_invoice_request))
		return;

	struct tlv_invoice_request *invreq = fromwire_tlv_invoice_request(tmpctx, &data, &size);

	if (!invreq)
		return;

	u8 *output_buffer = tal_arr(tmpctx, u8, 0);
	towire_tlv_invoice_request(&output_buffer, invreq);
	size_t len = tal_bytelen(output_buffer);

	struct tlv_invoice_request *decoded_invreq = fromwire_tlv_invoice_request(tmpctx, (const u8 **) &output_buffer, &len);

	assert(len == 0);
	assert(tlv_invoice_request_eq(invreq, decoded_invreq));

	clean_tmpctx();
}

