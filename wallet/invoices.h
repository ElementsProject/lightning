#ifndef LIGHTNING_WALLET_INVOICES_H
#define LIGHTNING_WALLET_INVOICES_H
#include "config.h"
#include <bitcoin/preimage.h>
#include <ccan/tal/tal.h>
#include <wallet/wallet.h>

struct amount_msat;
struct db;
struct json_escape;
struct invoice;
struct invoice_details;
struct invoices;
struct sha256;
struct timers;
struct wallet;

/**
 * invoices_new - Constructor for a new invoice handler
 *
 * @ctx - the owner of the invoice handler.
 * @wallet - the wallet
 * @timers - the timers object to use for expirations.
 */
struct invoices *invoices_new(const tal_t *ctx,
			      struct wallet *wallet,
			      struct timers *timers);

/**
 * invoices_start_expiration - Once ld->wallet complete, we can start expiring.
 *
 * @ld - the lightningd object
 */
void invoices_start_expiration(struct lightningd *ld);

/**
 * invoices_create - Create a new invoice.
 *
 * @invoices - the invoice handler.
 * @inv_dbid - pointer to location to put the invoice dbid in
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
		     u64 *inv_dbid,
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
 * @param inv_dbid - pointer to location to put the found dbid in
 * @param label - the label to search for.
 *
 * Returns false if no invoice with that label exists.
 * Returns true if found.
 */
bool invoices_find_by_label(struct invoices *invoices,
			    u64 *inv_dbid,
			    const struct json_escape *label);

/**
 * invoices_find_by_rhash - Search for an invoice by
 * payment_hash
 *
 * @invoices - the invoice handler.
 * @inv_dbid - pointer to location to put the found dbid in
 * @rhash - the payment_hash to search for.
 *
 * Returns false if no invoice with that rhash exists.
 * Returns true if found.
 */
bool invoices_find_by_rhash(struct invoices *invoices,
			    u64 *inv_dbid,
			    const struct sha256 *rhash);
/**
 * invoices_find_by_fallback_script - Search for an invoice by
 * scriptpubkey in invoice_fallbacks child table
 *
 * @invoices - the invoice handler.
 * @inv_dbid - pointer to location to put the found dbid in
 * @scriptPubKey - the scriptpubkey to search for.
 *
 * Returns false if no invoice with that scriptpubkey exists.
 * Returns true if found.
 */
bool invoices_find_by_fallback_script(struct invoices *invoices,
			    u64 *inv_dbid,
			    const u8 *scriptPubkey);

/**
 * invoices_find_unpaid - Search for an unpaid, unexpired invoice by
 * payment_hash
 *
 * @invoices - the invoice handler.
 * @inv_dbid - pointer to location to load found invoice dbid in.
 * @rhash - the payment_hash to search for.
 *
 * Returns false if no unpaid invoice with that rhash exists.
 * Returns true if found.
 */
bool invoices_find_unpaid(struct invoices *invoices,
			  u64 *inv_dbid,
			  const struct sha256 *rhash);

/**
 * invoices_delete - Delete an invoice
 *
 * @invoices - the invoice handler.
 * @inv_dbid - the invoice to delete.
 *
 * Return false on failure.
 */
bool invoices_delete(struct invoices *invoices,
		     u64 inv_dbid,
		     enum invoice_status status,
		     const struct json_escape *label,
		     const char *invstring);

/**
 * invoices_delete_description - Remove description from an invoice
 *
 * @invoices - the invoice handler.
 * @inv_dbid - the invoice to remove description from.
 *
 * Return false on failure.
 */
bool invoices_delete_description(struct invoices *invoices,
				 u64 inv_dbid,
				 const struct json_escape *label,
				 const char *description);

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
 * Iterate through all the invoices.
 * @invoices: the invoices
 * @listindex: what index order to use (if you care)
 * @liststart: first index to return (0 == all).
 * @listlimit: limit on number of entries to return (NULL == no limit).
 * @inv_dbid: the first invoice dbid (if returns non-NULL)
 *
 * Returns pointer to hand as @stmt to invoices_next(), or NULL.
 * If you choose not to call invoices_next() you must free it!
 */
struct db_stmt *invoices_first(struct invoices *invoices,
			       const enum wait_index *listindex,
			       u64 liststart,
			       const u32 *listlimit,
			       u64 *inv_dbid);

/**
 * Iterate through all the offers.
 * @invoices: the invoices
 * @stmt: return from invoices_first() or previous invoices_next()
 * @inv_dbid: the first invoice dbid (if returns non-NULL)
 *
 * Returns NULL once we're out of invoices.  If you choose not to call
 * invoices_next() again you must free return.
 */
struct db_stmt *invoices_next(struct invoices *invoices,
			      struct db_stmt *stmt,
			      u64 *inv_dbid);

/**
 * invoices_resolve - Mark an invoice as paid
 *
 * @invoices - the invoice handler.
 * @inv_dbid - the invoice to mark as paid.
 * @received - the actual amount received.
 * @label    - the label of the invoice.
 *
 * If the invoice is not UNPAID, returns false.
 */
bool invoices_resolve(struct invoices *invoices,
		      u64 inv_dbid,
		      struct amount_msat received,
		      const struct json_escape *label);

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
 * If the invoice was deleted, the callback is given a NULL
 * first argument.
 * @cbarg - the callback data.
 */
void invoices_waitany(const tal_t *ctx,
		      struct invoices *invoices,
		      u64 lastpay_index,
		      void (*cb)(const u64 *, void*),
		      void *cbarg);

/**
 * invoices_waitone - Wait for a specific invoice to be paid,
 * deleted, or expired.
 *
 * @ctx - the owner of the callback. If the owner is freed,
 * the callback is cancelled.
 * @invoices - the invoice handler,
 * @inv_dbid - the invoice to wait on.
 * @cb - the callback to invoice. If invoice is already paid
 * or expired, this is called immediately, otherwise it is
 * called during an invoices_resolve or invoices_delete call.
 * If the invoice was deleted, the callback is given a NULL
 * first argument (inv_dbid).
 * @cbarg - the callback data.
 *
 */
void invoices_waitone(const tal_t *ctx,
		      struct invoices *invoices,
		      u64 inv_dbid,
		      void (*cb)(const u64 *, void*),
		      void *cbarg);

/**
 * invoices_get_details - Get the invoice_details of an invoice.
 *
 * @ctx - the owner of the label and msatoshi fields returned.
 * @invoices - the invoice handler,
 * @inv_dbid - the invoice to get details on.
 * @return pointer to the invoice details allocated off of `ctx`.
 */
struct invoice_details *invoices_get_details(const tal_t *ctx,
					     struct invoices *invoices,
					     u64 inv_dbid);

/* Returns the id to use for the new invoice, and increments it. */
u64 invoice_index_created(struct lightningd *ld,
			  enum invoice_status state,
			  const struct json_escape *label,
			  const char *invstring);

/* Returns the current updated_index, and increments it. */
u64 invoice_index_update_status(struct lightningd *ld,
				const struct json_escape *label,
				enum invoice_status state);

/* Returns the current updated_index, and increments it. */
u64 invoice_index_update_deldesc(struct lightningd *ld,
				 const struct json_escape *label,
				 const char *description);

void invoice_index_deleted(struct lightningd *ld,
			   enum invoice_status state,
			   const struct json_escape *label,
			   const char *invstring);
#endif /* LIGHTNING_WALLET_INVOICES_H */
