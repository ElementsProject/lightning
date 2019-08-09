lightning-listforwards

7

lightning-listforwards

Command showing all htlcs and their information.

**listforwards**

DESCRIPTION
===========

The **listforwards** RPC command displays all htlcs that have been
attempted to be forwarded by the c-lightning node.

RETURN VALUE
============

On success one array will be returned: *forwards* with htlcs that have
been processed

Each entry in *forwards* will include:

-   *in\_channel* - the short\_channel\_id of the channel that recieved
    the incoming htlc.

-   *out\_channel* - the short\_channel\_id of to which the outgoing
    htlc is supposed to be forwarded.

-   *in\_msatoshi*, *in\_msat* - amount of msatoshis that are forwarded
    to this node.

-   *out\_msatoshi*, *out\_msat* - amount of msatoshis to be forwarded.

-   *fee*, *fee\_msat* - fee offered for forwarding the htlc in
    msatoshi.

-   *status* - status can be either *offered* if the routing process is
    still ongoing, *settled* if the routing process is completed or
    *failed* if the routing process could not be completed.

-   *received\_time* - timestamp when incoming htlc was received.

-   *resolved\_time* - timestamp when htlc was resolved (settled or
    failed).

AUTHOR
======

Rene Pickhardt &lt;<r.pickhardt@gmail.com>&gt; is mainly responsible.

SEE ALSO
========

lightning-getinfo(7)

RESOURCES
=========

Main web site: <https://github.com/ElementsProject/lightning>
