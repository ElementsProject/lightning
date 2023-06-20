# cln-grpc-hodl - Adds Hold-invoice methods

- HodlInvoice is just a wrapper for Invoice that will make a database entry to mark it as a hold invoice.
- HodlInvoiceSettle marks the invoice related htlcs to be settled
- HodlInvoiceCancel marks the invoice related htlcs to be rejected
- HodlInvoiceLookup returns the status of a hold invoice, which has more possible states than a regular invoice. Will wait with a timeout to confirm final settlement/rejection.

An example and more infos can be found in plugins/grpc-plugin-hodl/README.md
