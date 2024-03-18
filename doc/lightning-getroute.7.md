lightning-getroute -- Command for routing a payment (low-level)
===============================================================

SYNOPSIS
--------

**getroute** *id* *amount\_msat* *riskfactor* [*cltv*] [*fromid*]
[*fuzzpercent*] [*exclude*] [*maxhops*]

DESCRIPTION
-----------

The **getroute** RPC command attempts to find the best route for the
payment of *amount\_msat* to lightning node *id*, such that the payment will
arrive at *id* with *cltv*.

There are two considerations for how good a route is: how low the fees
are, and how long your payment will get stuck in a delayed output if a
node goes down during the process. 

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

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object containing **route** is returned.  It is an array of objects, where each object contains:

- **id** (pubkey): The node at the end of this hop
- **channel** (short\_channel\_id): The channel joining these nodes
- **direction** (u32): 0 if this channel is traversed from lesser to greater **id**, otherwise 1
- **amount\_msat** (msat): The amount expected by the node at the end of this hop
- **delay** (u32): The total CLTV expected by the node at the end of this hop
- **style** (string): The features understood by the destination node (always "tlv")

[comment]: # (GENERATE-FROM-SCHEMA-END)

The final *id* will be the destination *id* given in the input. The
difference between the first *amount\_msat* minus the *amount\_msat* given in
the input is the fee (assuming the first hop is free). The first
*delay* is the very worst case timeout for the payment failure, in
blocks.

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-pay(7), lightning-sendpay(7).

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:24cb35c00acd4a803c9558c9cd80922b9f83e6ad7f1358bc74e7f816c79c1705)
