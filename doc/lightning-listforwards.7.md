lightning-listforwards -- Command showing all htlcs and their information
=========================================================================

SYNOPSIS
--------

**listforwards**

DESCRIPTION
-----------

The **listforwards** RPC command displays all htlcs that have been
attempted to be forwarded by the c-lightning node.

RETURN VALUE
------------

On success one array will be returned: *forwards* with htlcs that have
been processed

Each entry in *forwards* will include:
- *in\_channel*: the short\_channel\_id of the channel that recieved the incoming htlc.
- *in\_msatoshi*, *in\_msat* - amount of msatoshis that are forwarded to this node.
- *status*: status can be either *offered* if the routing process is still ongoing,
*settled* if the routing process is completed or *failed* if the routing process could not be completed.
- *received\_time*: timestamp when incoming htlc was received.

The following additional fields are usually present, but will not be for some
variants of status *local\_failed* (if it failed before we determined these):

- *out\_channel*: the short\_channel\_id of to which the outgoing htlc is supposed to be forwarded.
- *fee*, *fee\_msat*: fee offered for forwarding the htlc in msatoshi.
- *out\_msatoshi*, *out\_msat* - amount of msatoshis to be forwarded.

The following fields may be offered, but for old forgotten HTLCs they will be omitted:

- *payment\_hash* - the payment_hash belonging to the HTLC.

If the status is not 'offered', the following additional fields are present:

- *resolved\_time* - timestamp when htlc was resolved (settled or failed).

AUTHOR
------

Rene Pickhardt <<r.pickhardt@gmail.com>> is mainly responsible.

SEE ALSO
--------

lightning-getinfo(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

