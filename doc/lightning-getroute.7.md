lightning-getroute -- Command for routing a payment (low-level)
===============================================================

SYNOPSIS
--------

**getroute** *id* *msatoshi* *riskfactor* \[*cltv*\] \[*fromid*\]
\[*fuzzpercent*\] \[*exclude*\] \[*maxhops*\]

DESCRIPTION
-----------

The **getroute** RPC command attempts to find the best route for the
payment of *msatoshi* to lightning node *id*, such that the payment will
arrive at *id* with *cltv*-blocks to spare (default 9).

*msatoshi* is in millisatoshi precision; it can be a whole number, or a
whole number ending in *msat* or *sat*, or a number with three decimal
places ending in *sat*, or a number with 1 to 11 decimal places ending
in *btc*.

There are two considerations for how good a route is: how low the fees
are, and how long your payment will get stuck in a delayed output if a
node goes down during the process. The *riskfactor* non-negative
floating-point field controls this tradeoff; it is the annual cost of
your funds being stuck (as a percentage).

For example, if you thought the convenience of keeping your funds liquid
(not stuck) was worth 20% per annum interest, *riskfactor* would be 20.

If you didn’t care about risk, *riskfactor* would be zero.

*fromid* is the node to start the route from: default is this node.

The *fuzzpercent* is a non-negative floating-point number, representing a
percentage of the actual fee. The *fuzzpercent* is used to distort
computed fees along each channel, to provide some randomization to the
route generated. 0.0 means the exact fee of that channel is used, while
100.0 means the fee used might be from 0 to twice the actual fee. The
default is 5.0, or up to 5% fee distortion.

*exclude* is a JSON array of short-channel-id/direction (e.g. \[
"564334x877x1/0", "564195x1292x0/1" \]) or node-id which should be excluded
from consideration for routing. The default is not to exclude any channels
or nodes. Note if the source or destination is excluded, the command result
is undefined.

*maxhops* is the maximum number of channels to return; default is 20.

RISKFACTOR EFFECT ON ROUTING
----------------------------

The risk factor is treated as if it were an additional fee on the route,
for the purposes of comparing routes.

The formula used is the following approximation:

    risk-fee = amount x blocks-timeout x per-block-cost

We are given a *riskfactor* expressed as a percentage. There are 52596
blocks per year, thus *per-block-cost* is *riskfactor* divided by
5,259,600.

The final result is:

    risk-fee = amount x blocks-timeout x riskfactor / 5259600

Here are the risk fees in millisatoshis, using various parameters. I
assume a channel charges the default of 1000 millisatoshis plus 1
part-per-million. Common to\_self\_delay values on the network at 14 and
144 blocks.

<table>
<colgroup>
<col style="width: 20%" />
<col style="width: 20%" />
<col style="width: 20%" />
<col style="width: 20%" />
<col style="width: 20%" />
</colgroup>
<thead>
<tr class="header">
<th style="text-align: left;">Amount (msat)</th>
<th style="text-align: left;">Riskfactor</th>
<th style="text-align: left;">Delay</th>
<th style="text-align: left;">Risk Fee</th>
<th style="text-align: left;">Route fee</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td style="text-align: left;"><p>10,000</p></td>
<td style="text-align: left;"><p>1</p></td>
<td style="text-align: left;"><p>14</p></td>
<td style="text-align: left;"><p>0</p></td>
<td style="text-align: left;"><p>1001</p></td>
</tr>
<tr class="even">
<td style="text-align: left;"><p>10,000</p></td>
<td style="text-align: left;"><p>10</p></td>
<td style="text-align: left;"><p>14</p></td>
<td style="text-align: left;"><p>0</p></td>
<td style="text-align: left;"><p>1001</p></td>
</tr>
<tr class="odd">
<td style="text-align: left;"><p>10,000</p></td>
<td style="text-align: left;"><p>100</p></td>
<td style="text-align: left;"><p>14</p></td>
<td style="text-align: left;"><p>2</p></td>
<td style="text-align: left;"><p>1001</p></td>
</tr>
<tr class="even">
<td style="text-align: left;"><p>10,000</p></td>
<td style="text-align: left;"><p>1000</p></td>
<td style="text-align: left;"><p>14</p></td>
<td style="text-align: left;"><p>26</p></td>
<td style="text-align: left;"><p>1001</p></td>
</tr>
<tr class="odd">
<td style="text-align: left;"><p>1,000,000</p></td>
<td style="text-align: left;"><p>1</p></td>
<td style="text-align: left;"><p>14</p></td>
<td style="text-align: left;"><p>2</p></td>
<td style="text-align: left;"><p>1001</p></td>
</tr>
<tr class="even">
<td style="text-align: left;"><p>1,000,000</p></td>
<td style="text-align: left;"><p>10</p></td>
<td style="text-align: left;"><p>14</p></td>
<td style="text-align: left;"><p>26</p></td>
<td style="text-align: left;"><p>1001</p></td>
</tr>
<tr class="odd">
<td style="text-align: left;"><p>1,000,000</p></td>
<td style="text-align: left;"><p>100</p></td>
<td style="text-align: left;"><p>14</p></td>
<td style="text-align: left;"><p>266</p></td>
<td style="text-align: left;"><p>1001</p></td>
</tr>
<tr class="even">
<td style="text-align: left;"><p>1,000,000</p></td>
<td style="text-align: left;"><p>1000</p></td>
<td style="text-align: left;"><p>14</p></td>
<td style="text-align: left;"><p>2661</p></td>
<td style="text-align: left;"><p>1001</p></td>
</tr>
<tr class="odd">
<td style="text-align: left;"><p>100,000,000</p></td>
<td style="text-align: left;"><p>1</p></td>
<td style="text-align: left;"><p>14</p></td>
<td style="text-align: left;"><p>266</p></td>
<td style="text-align: left;"><p>1100</p></td>
</tr>
<tr class="even">
<td style="text-align: left;"><p>100,000,000</p></td>
<td style="text-align: left;"><p>10</p></td>
<td style="text-align: left;"><p>14</p></td>
<td style="text-align: left;"><p>2661</p></td>
<td style="text-align: left;"><p>1100</p></td>
</tr>
<tr class="odd">
<td style="text-align: left;"><p>100,000,000</p></td>
<td style="text-align: left;"><p>100</p></td>
<td style="text-align: left;"><p>14</p></td>
<td style="text-align: left;"><p>26617</p></td>
<td style="text-align: left;"><p>1100</p></td>
</tr>
<tr class="even">
<td style="text-align: left;"><p>100,000,000</p></td>
<td style="text-align: left;"><p>1000</p></td>
<td style="text-align: left;"><p>14</p></td>
<td style="text-align: left;"><p>266179</p></td>
<td style="text-align: left;"><p>1100</p></td>
</tr>
<tr class="odd">
<td style="text-align: left;"><p>10,000</p></td>
<td style="text-align: left;"><p>1</p></td>
<td style="text-align: left;"><p>144</p></td>
<td style="text-align: left;"><p>0</p></td>
<td style="text-align: left;"><p>1001</p></td>
</tr>
<tr class="even">
<td style="text-align: left;"><p>10,000</p></td>
<td style="text-align: left;"><p>10</p></td>
<td style="text-align: left;"><p>144</p></td>
<td style="text-align: left;"><p>2</p></td>
<td style="text-align: left;"><p>1001</p></td>
</tr>
<tr class="odd">
<td style="text-align: left;"><p>10,000</p></td>
<td style="text-align: left;"><p>100</p></td>
<td style="text-align: left;"><p>144</p></td>
<td style="text-align: left;"><p>27</p></td>
<td style="text-align: left;"><p>1001</p></td>
</tr>
<tr class="even">
<td style="text-align: left;"><p>10,000</p></td>
<td style="text-align: left;"><p>1000</p></td>
<td style="text-align: left;"><p>144</p></td>
<td style="text-align: left;"><p>273</p></td>
<td style="text-align: left;"><p>1001</p></td>
</tr>
<tr class="odd">
<td style="text-align: left;"><p>1,000,000</p></td>
<td style="text-align: left;"><p>1</p></td>
<td style="text-align: left;"><p>144</p></td>
<td style="text-align: left;"><p>27</p></td>
<td style="text-align: left;"><p>1001</p></td>
</tr>
<tr class="even">
<td style="text-align: left;"><p>1,000,000</p></td>
<td style="text-align: left;"><p>10</p></td>
<td style="text-align: left;"><p>144</p></td>
<td style="text-align: left;"><p>273</p></td>
<td style="text-align: left;"><p>1001</p></td>
</tr>
<tr class="odd">
<td style="text-align: left;"><p>1,000,000</p></td>
<td style="text-align: left;"><p>100</p></td>
<td style="text-align: left;"><p>144</p></td>
<td style="text-align: left;"><p>2737</p></td>
<td style="text-align: left;"><p>1001</p></td>
</tr>
<tr class="even">
<td style="text-align: left;"><p>1,000,000</p></td>
<td style="text-align: left;"><p>1000</p></td>
<td style="text-align: left;"><p>144</p></td>
<td style="text-align: left;"><p>27378</p></td>
<td style="text-align: left;"><p>1001</p></td>
</tr>
<tr class="odd">
<td style="text-align: left;"><p>100,000,000</p></td>
<td style="text-align: left;"><p>1</p></td>
<td style="text-align: left;"><p>144</p></td>
<td style="text-align: left;"><p>2737</p></td>
<td style="text-align: left;"><p>1100</p></td>
</tr>
<tr class="even">
<td style="text-align: left;"><p>100,000,000</p></td>
<td style="text-align: left;"><p>10</p></td>
<td style="text-align: left;"><p>144</p></td>
<td style="text-align: left;"><p>27378</p></td>
<td style="text-align: left;"><p>1100</p></td>
</tr>
<tr class="odd">
<td style="text-align: left;"><p>100,000,000</p></td>
<td style="text-align: left;"><p>100</p></td>
<td style="text-align: left;"><p>144</p></td>
<td style="text-align: left;"><p>273785</p></td>
<td style="text-align: left;"><p>1100</p></td>
</tr>
<tr class="even">
<td style="text-align: left;"><p>100,000,000</p></td>
<td style="text-align: left;"><p>1000</p></td>
<td style="text-align: left;"><p>144</p></td>
<td style="text-align: left;"><p>2737850</p></td>
<td style="text-align: left;"><p>1100</p></td>
</tr>
</tbody>
</table>

RECOMMENDED RISKFACTOR VALUES
-----------------------------

The default *fuzz* factor is 5%, so as you can see from the table above,
that tends to overwhelm the effect of *riskfactor* less than about 5.

1 is a conservative value for a stable lightning network with very few
failures.

1000 is an aggressive value for trying to minimize timeouts at all
costs.

The default for lightning-pay(7) is 10, which starts to become a major
factor for larger amounts, and is basically ignored for tiny ones.

RETURN VALUE
------------

On success, a "route" array is returned. Each array element contains
*id* (the node being routed through), *msatoshi* (the millisatoshis
sent), *amount\_msat* (the same, with *msat* appended), *delay* (the
number of blocks to timeout at this node), and *style* (indicating
the features which can be used for this hop).

The final *id* will be the destination *id* given in the input. The
difference between the first *msatoshi* minus the *msatoshi* given in
the input is the fee. The first *delay* is the very worst case timeout
for the payment failure, in blocks.

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-pay(7), lightning-sendpay(7).

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

