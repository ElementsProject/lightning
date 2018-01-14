#ifndef LIGHTNING_WALLET_INVOICES_H
#define LIGHTNING_WALLET_INVOICES_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <ccan/take/take.h>

struct db;
struct invoice;
struct invoices;
struct log;
struct sha256;

/**
 * invoices_new - Constructor for a new invoice handler
 *
 * @ctx - the owner of the invoice handler.
 * @db - the database connection to use for saving invoice.
 * @log - the log to report to.
 */
struct invoices *invoices_new(const tal_t *ctx,
			      struct db *db,
			      struct log *log);

/**
 * invoices_load - Second-stage constructor for invoice handler.
 * Must be called before the other functions are called
 *
 * @invoices - the invoice handler.
 */
bool invoices_load(struct invoices *invoices);

/**
 * invoices_create - Create a new invoice.
 *
 * @invoices - the invoice handler.
 * @msatoshi - the amount the invoice should have, or
 * NULL for any-amount invoices.
 * @label - the unique label for this invoice. Must be
 * non-NULL. Must be null-terminated.
 * @expiry - the number of seconds before the invoice
 * expires
 *
 * Returns NULL if label already exists or expiry is 0.
 * FIXME: Fallback addresses
 */
const struct invoice *invoices_create(struct invoices *invoices,
				      u64 *msatoshi TAKES,
				      const char *label TAKES,
				      u64 expiry);

/**
 * invoices_find_by_label - Search for an invoice by label
 *
 * @invoices - the invoice handler.
 * @label - the label to search for. Must be null-terminated.
 *
 * Returns NULL if no invoice with that label exists.
 */
const struct invoice *invoices_find_by_label(struct invoices *invoices,
					     const char *label);

/**
 * invoices_find_unpaid - Search for an unpaid, unexpired invoice by
 * payment_hash
 *
 * @invoices - the invoice handler.
 * @rhash - the payment_hash to search for.
 *
 * Rerturns NULL if no invoice with that payment hash exists.
 */
const struct invoice *invoices_find_unpaid(struct invoices *invoices,
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
		     const struct invoice *invoice);

/**
 * invoices_iterate - Iterate over all existing invoices
 *
 * @invoices - the invoice handler.
 * @invoice - the previous invoice you iterated over.
 *
 * Return NULL at end-of-sequence. Usage:
 *
 *   const struct invoice *i;
 *   i = NULL;
 *   while ((i = invoices_iterate(invoices, i))) {
 *       ...
 *   }
 */
const struct invoice *invoices_iterate(struct invoices *invoices,
				       const struct invoice *invoice);

/**
 * invoices_resolve - Mark an invoice as paid
 *
 * @invoices - the invoice handler.
 * @invoice - the invoice to mark as paid.
 * @msatoshi_received - the actual amount received.
 *
 * Precondition: the invoice must not yet be expired (invoices
 * does not check).
 */
void invoices_resolve(struct invoices *invoices,
		      const struct invoice *invoice,
		      u64 msatoshi_received);

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
 * FIXME: actually trigger on expired invoices.
 */
void invoices_waitone(const tal_t *ctx,
		      struct invoices *invoices,
		      struct invoice const *invoice,
		      void (*cb)(const struct invoice *, void*),
		      void *cbarg);

#endif /* LIGHTNING_WALLET_INVOICES_H */
