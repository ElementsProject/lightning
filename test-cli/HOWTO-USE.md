There are two sides, A and B.

You can see my example test script in `test-cli/test.sh`.  As these
utilities don't keep any state, and don't talk to bitcoind, the
commandlines get ugly fast (and don't handle all cases).  They're only
for testing.

Opening a Generalized Channel
=============================

You will need a running bitcoin node, in regtest mode, and two or more
pay-to-pubkey-hash outputs (ie. not the results of mining), which you
can create like this:

	$ bitcoin-cli -regtest generate 101
	$ A1=`bitcoin-cli -regtest getnewaddress`
	$ A2=`bitcoin-cli -regtest getnewaddress`
	$ TX1=`bitcoin-cli -regtest sendtoaddress $A1 10`
	$ TX2=`bitcoin-cli -regtest sendtoaddress $A2 10`
	$ bitcoin-cli -regtest generate 1
	# Find the inputs numbers corresponding to those 10 btc outs
	for i in `seq 103`; do ./getinput.sh $i | grep -q "\($TX1\|$TX2\).*/1000000000/" && echo $i; done

For each side A and B you need:

1. SEED: A secret 256-bit seed, in hex.
	Try 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
2. CHANGEADDR: An anchor change address (unless amounts are exact).
	eg. `bitcoin-cli -regtest getnewaddress`
3. CHANGEPUBKEY: The public key for CHANGEADDR.
	eg. `bitcoin-cli -regtest validateaddress <CHANGEADDR> | grep pubkey`
4. TMPADDR: An address for the anchor output to the commitment transaction.
	eg. `bitcoin-cli -regtest getnewaddress`
5. TMPKEY: The private key for TMPADDR
	eg. `bitcoin-cli -regtest dumpprivkey <TMPADDR>`
6. FINALADDR: An output address for when channel is closed.
	eg. `bitcoin-cli -regtest getnewaddress`
7. FINALKEY: The private key for FINALADDR
   	eg. `bitcoin-cli -regtest dumpprivkey <FINALADDR>`
8. TXIN{1-n}: One or more unspent transaction outputs on testnet.
	These are in form "<txid>/<outnum>/<amount>/<scriptsig>".
	eg. ./getinput.sh (`./getinput.sh 2`, etc).
9. TXINKEY{1-n}: The private keys to spend the TXINs.
	eg. `./getinput.sh --privkey` can get these.

STEP 1
------
First each side needs to tell the other what it wants the channel
to look like, including how many satoshis to put in the channel.

Note that the default anchor fee is 5000 satoshi each, (use
`--anchor-fee=` to override), so your amount must be less than or equal
to the total inputs plus this fee.

A: Create a channel open request packet:

	test-cli/open-channel <A-SEED> <amount> <A-CHANGEPUBKEY> <A-TMPKEY> <A-FINALKEY> <txid>/<outnum>/<amount>/<scriptsig>... > A-open.pb

B: The same:

	test-cli/open-channel <B-SEED> <amount> <B-CHANGEPUBKEY> <B-TMPKEY> <B-FINALKEY> <txid>/<outnum>/<amount>/<scriptsig>... > B-open.pb

STEP 2
------
Create the signatures for the anchor transaction: we don't send them
until we have completed the commitment transaction though, so we're sure
we can get our funds back.  We need one TXINKEY for each TXIN:

A:

	test-cli/open-anchor-scriptsigs A-open.pb B-open.pb <A-TXINKEY>... > A-anchor-scriptsigs.pb
B:

	test-cli/open-anchor-scriptsigs B-open.pb A-open.pb <B-TXINKEY>... > B-anchor-scriptsigs.pb

STEP 3 (The INSECURE hack!)
------
Because we don't have tx normalization or equivalent, we need to
share the signed anchor inputs so the other side can create the
first commitment transaction.

A:

	test-cli/leak-anchor-sigs A-anchor-scriptsigs.pb > A-leak-anchor-sigs.pb

B:

	test-cli/leak-anchor-sigs B-anchor-scriptsigs.pb > B-leak-anchor-sigs.pb

STEP 4
------
Now both sides create the commitment transaction signatures which spend
the transaction output:

A:

	test-cli/open-commit-sig A-open.pb B-open.pb <A-TMPKEY> A-leak-anchor-sigs.pb B-leak-anchor-sigs.pb > A-commit-sig.pb
B:

	test-cli/open-commit-sig B-open.pb A-open.ob <B-TMPKEY> B-leak-anchor-sigs.pb A-leak-anchor-sigs.pb > B-commit-sig.pb

STEP 5
------
Check the commitment signatures from the other side, and produce commit txs.

A:

	test-cli/check-commit-sig A-open.pb B-open.pb B-commit-sig.pb <A-TMPKEY> A-leak-anchor-sigs.pb B-leak-anchor-sigs.pb > A-commit-0.tx
B:

	test-cli/check-commit-sig B-open.pb A-open.pb A-commit-sig.pb <B-TMPKEY> B-leak-anchor-sigs.pb A-leak-anchor-sigs.pb > B-commit-0.tx

STEP 6
------
Check the anchor signatures from the other side, and use them to generate the
anchor transaction (as a hex string, suitable for bitcoind).

A:

	test-cli/check-anchor-scriptsigs A-open.pb B-open.pb A-anchor-scriptsigs.pb B-anchor-scriptsigs.pb > A-anchor.tx
B:

	test-cli/check-anchor-scriptsigs B-open.pb A-open.pb B-anchor-scriptsigs.pb A-anchor-scriptsigs.pb > B-anchor.tx

They should be identical:

	cmp A-anchor.tx B-anchor.tx || echo FAIL

STEP 7
------
Broadcast the anchor transaction:

Either one:

	bitcoin-cli -regtest sendrawtransaction `cat A-anchor.tx` > anchor.txid

Generate blocks until we have enough confirms (I don't do this, so I
can reset the entire state by restarting bitcoind with
`-zapwallettxes=1`):

A:

	while [ 0$(bitcoin-cli -regtest getrawtransaction $(cat anchor.txid) 1 | sed -n 's/.*"confirmations" : \([0-9]*\),/\1/p') -lt $(test-cli/get-anchor-depth A-open.pb) ]; do bitcoin-cli -regtest generate 1; done

B:

	while [ 0$(bitcoin-cli -regtest getrawtransaction $(cat anchor.txid) 1 | sed -n 's/.*"confirmations" : \([0-9]*\),/\1/p') -lt $(test-cli/get-anchor-depth B-open.pb) ]; do bitcoin-cli -regtest generate 1; done

Using a Generalized Channel
===========================

Let's make a payment now!  Either end can propose a change to the
latest commitment tx, like so:

A:

	test-cli/update-channel (--to-them=xxx or --from-them=xxx) <A-SEED> > A-update-1.pb

The other end accepts the update, and provides the signature for the new tx and
revocation hash for the new tx:

B:

	test-cli/update-channel-accept <B-SEED> B-anchor.tx B-open.pb A-open.pb <B-TMPKEY> A-update-1.pb > B-update-accept-1.pb

A completes its side by signing the new tx, and revoking the old:

A:

	test-cli/update-channel-signature <A_SEED> A-anchor.tx A-open.pb B-open.pb <A-TMPKEY> A-update-1.pb B-update-accept-1.pb > A-update-sig-1.pb

B now revokes its old tx:

B:

	test-cli/update-channel-complete <B_SEED> B-anchor.tx B-open.pb A-open.pb A-update-1.pb A-update-sig-1.pb > B-update-complete-1.pb

B checks that the commit tx is indeed revoked.

B:

	./check-commit-complete A-open.pb A-commit-complete-1.pb 

To update it again, simply re-run the commands with the previous
updates appended, as shown in `test-cli/test.sh`.

(Optional)
Generate new commitment txs, by including all the update proposals
since the initial tx (here we just have one, A-update-1.pb):

A:

	test-cli/create-commit-tx A-anchor.tx A-open.pb B-open.pb A-update-1.pb B-update-accept-1.pb <A-TMPKEY> > A-commit-1.tx

Special Effects: Trying To Cheat
================================

A now tries to spend an old (revoked) commitment tx:

A:

	test-cli/create-commit-tx A-anchor.tx A-open.pb B-open.pb <A-TMPKEY> B-commit-sig.pb > commit-0.tx

A:

	bitcoin-cli -regtest sendrawtransaction `cat A-commit-0.tx`

B can steal the money, using the revocation hash from A-update-sig-1:

B:

	./create-steal-tx A-commit-0.tx A-update-sig-1.pb <A-FINALKEY> B-open.pb A-open.pb <SOME-PUBKEY-TO-PAYTO> > B-commit-steal.tx

B:

	bitcoin-cli -regtest sendrawtransaction `cat B-commit-steal.tx`

Closing the Channel: Unilaterally
=================================

To close unilaterally, one side broadcasts its latest commitment tx:

A:

	bitcoin-cli -regtest sendrawtransaction `cat A-commit-1.tx`

Now, we can create the transaction to spend the output:

A:

	./create-commit-spend-tx A-commit-1.tx <A-FINALKEY> <someaddress> > spend.tx

Normally A would have to wait 1 day, but because
OP_CHECKSEQUENCEVERIFY is a nop, we can actually claim this
immediately:

A:

	bitcoin-cli -regtest sendrawtransaction `cat spend.tx`

Closing the Channel By Mutual Consent
=====================================

This is the normal way to do it.  Include all the update proposals at
the end of the command line (eg. `?-update-?.pb`), so the transaction outputs
reflect the final commitment total:

A:

	./close-channel A-anchor.tx A-open.pb B-open.pb <A-TMPKEY> A-update-1.pb > A-close.pb
B:

	./close-channel --complete A-anchor.tx B-open.pb A-open.pb <B-TMPKEY> A-update-1.pb > B-close-accept.pb

Both ends have both signatures now, so either can create the close tx:

A:

	./create-close-tx A-anchor.tx A-open.pb B-open.pb A-close.pb B-close-accept.pb > A-close.tx

B:

	./create-close-tx A-anchor.tx B-open.pb A-open.pb A-close.pb B-close-accept.pb > B-close.tx

They should be identical:

	cmp A-close.tx B-close.tx || echo FAIL

Good luck!

Rusty.
