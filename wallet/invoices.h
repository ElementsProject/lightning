#ifndef LIGHTNING_WALLET_INVOICES_H
#define LIGHTNING_WALLET_INVOICES_H
#include "config.h"
#include <bitcoin/preimage.h>
#include <ccan/tal/tal.h>

struct amount_msat;
struct db;
struct json_escape;
struct invoice;
struct invoice_details;
struct invoice_iterator;
struct invoices;
struct sha256;
struct timers;

/**
 * invoices_new - Constructor for a new invoice handler
 *
 * @ctx - the owner of the invoice handler.
 * @db - the database connection to use for saving invoice.
 * @timers - the timers object to use for expirations.
 */
struct invoices *invoices_new(const tal_t *ctx,
			      struct db *db,
			      struct timers *timers);

/**
 * invoices_create - Create a new invoice.
 *
 * @invoices - the invoice handler.
 * @pinvoice - pointer to location to load new invoice in.
 * @msat - the amount the invoice should have, or
 * NULL for any-amount invoices.
 * @label - the unique label for this invoice. Must be
 * non-NULL.
 * @expiry - the number of seconds before the invoice
 * expires
 *
 * Returns false if label already exists or expiry is 0.
 * Returns true if created invoice.
 * FIXME: Fallback addresses
 */
bool invoices_create(struct invoices *invoices,
		     struct invoice *pinvoice,
		     const struct amount_msat *msat TAKES,
		     const struct json_escape *label TAKES,
		     u64 expiry,
		     const char *b11enc,
		     const char *description,
		     const u8 *features,
		     const struct preimage *r,
		     const struct sha256 *rhash,
		     const struct sha256 *local_offer_id);

/**
 * invoices_find_by_label - Search for an invoice by label
 *
 * @param invoices - the invoice handler.
 * @param pinvoice - pointer to location to load found invoice in.
 * @param label - the label to search for.
 *
 * Returns false if no invoice with that label exists.
 * Returns true if found.
 */
bool invoices_find_by_label(struct invoices *invoices,
			    struct invoice *pinvoice,
			    const struct json_escape *label);

/**
 * invoices_find_by_rhash - Search for an invoice by
 * payment_hash
 *
 * @invoices - the invoice handler.
 * @pinvoice - pointer to location to load found invoice in.
 * @rhash - the payment_hash to search for.
 *
 * Returns false if no invoice with that rhash exists.
 * Returns true if found.
 */
bool invoices_find_by_rhash(struct invoices *invoices,
			    struct invoice *pinvoice,
			    const struct sha256 *rhash);

/**
 * invoices_find_unpaid - Search for an unpaid, unexpired invoice by
 * payment_hash
 *
 * @invoices - the invoice handler.
 * @pinvoice - pointer to location to load found invoice in.
 * @rhash - the payment_hash to search for.
 *
 * Returns false if no unpaid invoice with that rhash exists.
 * Returns true if found.
 */
bool invoices_find_unpaid(struct invoices *invoices,
			  struct invoice *pinvoice,
			  const struct sha256 *rhash);

/**
 * invoices_delete - Delete an invoice
 *
 * @invoices - the invoice handler.
 * @invoice - the invoice to delete.
 *
 * Return false on failure.
 */
bool invoices_delete(struct invoices *invoices,
		     struct invoice invoice);

/**
 * invoices_delete_expired - Delete all expired invoices
 * with expiration time less than or equal to the given.
 *
 * @invoices - the invoice handler.
 * @max_expiry_time - the maximum expiry time to delete.
 */
void invoices_delete_expired(struct invoices *invoices,
			     u64 max_expiry_time);

/**
 * invoices_iterate - Iterate over all existing invoices
 *
 * @invoices - the invoice handler.
 * @iterator - the iterator object to use.
 *
 * Return false at end-of-sequence, true if still iterating.
 * Usage:
 *
 *   struct invoice_iterator it;
 *   memset(&it, 0, sizeof(it))
 *   while (invoices_iterate(wallet, &it)) {
 *       ...
 *   }
 */
bool invoices_iterate(struct invoices *invoices,
		      struct invoice_iterator *it);

/**
 * wallet_invoice_iterator_deref - Read the details of the
 * invoice currently pointed to by the given iterator.
 *
 * @ctx - the owner of the label and msatoshi fields returned.
 * @wallet - the wallet whose invoices are to be iterated over.
 * @iterator - the iterator object to use.
 * @return The invoice details allocated off of `ctx`
 *
 */
const struct invoice_details *invoices_iterator_deref(
	const tal_t *ctx, struct invoices *invoices,
	const struct invoice_iterator *it);

/**
 * invoices_resolve - Mark an invoice as paid
 *
 * @invoices - the invoice handler.
 * @invoice - the invoice to mark as paid.
 * @received - the actual amount received.
 *
 * If the invoice is not UNPAID, returns false.
 */
bool invoices_resolve(struct invoices *invoices,
		      struct invoice invoice,
		      struct amount_msat received);

/**
 * invoices_waitany - Wait for any invoice to be paid.
 *
 * @ctx - the owner of the callback. If the owner is freed,
 * the callback is cancelled.
 * @invoices - the invoice handler.
 * @lastpay_index - wait for invoices after the specified
 * pay_index. Use 0 to wait for the first invoice.
 * @cb - the callback to invoke. If an invoice is already
 * paid with pay_index greater than lastpay_index, this
 * is called immediately, otherwise it is called during
 * an invoices_resolve call.
 * @cbarg - the callback data.
 */
void invoices_waitany(const tal_t *ctx,
		      struct invoices *invoices,
		      u64 lastpay_index,
		      void (*cb)(const struct invoice *, void*),
		      void *cbarg);

/**
 * invoices_waitone - Wait for a specific invoice to be paid,
 * deleted, or expired.
 *
 * @ctx - the owner of the callback. If the owner is freed,
 * the callback is cancelled.
 * @invoices - the invoice handler,
 * @invoice - the invoice to wait on.
 * @cb - the callback to invoice. If invoice is already paid
 * or expired, this is called immediately, otherwise it is
 * called during an invoices_resolve or invoices_delete call.
 * If the invoice was deleted, the callback is given a NULL
 * invoice.
 * @cbarg - the callback data.
 *
 */
void invoices_waitone(const tal_t *ctx,
		      struct invoices *invoices,
		      struct invoice invoice,
		      void (*cb)(const struct invoice *, void*),
		      void *cbarg);

/**
 * invoices_get_details - Get the invoice_details of an invoice.
 *
 * @ctx - the owner of the label and msatoshi fields returned.
 * @invoices - the invoice handler,
 * @invoice - the invoice to get details on.
 * @return pointer to the invoice details allocated off of `ctx`.
 */
const struct invoice_details *invoices_get_details(const tal_t *ctx,
						   struct invoices *invoices,
						   struct invoice invoice);

#endif /* LIGHTNING_WALLET_INVOICES_H */
