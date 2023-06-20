# cln-grpc-hold - Adds Hold-invoice methods

- HoldInvoice is just a wrapper for Invoice that will make a database entry to mark it as a hold invoice.
- HoldInvoiceSettle marks the invoice related htlcs to be settled
- HoldInvoiceCancel marks the invoice related htlcs to be rejected
- HoldInvoiceLookup returns the status of a hold invoice, which has more possible states than a regular invoice. Will wait with a timeout to confirm final settlement/rejection.

An example and more infos can be found in plugins/grpc-plugin-hold/README.md
