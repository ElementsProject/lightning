There are two sides, A and B.

You can see my example test scripts `test-cli/scripts/setup.sh` and
`test-cli/scripts/test.sh`.  As these utilities don't keep any state,
and don't talk to bitcoind/alphad, the commandlines get ugly fast (and
don't handle all cases).  They're only for testing.

Opening a Generalized Channel
=============================

You will need a running alphad node in regtest mode (which will give
you 10500000 coins once you generate a block):

	$ alphad -regtest -testnet=0 &
	$ alpha-cli -regtest -testnet=0 setgenerate true

You will also need two (non-confidential) transaction outputs (mined)

	$ A1=`scripts/get-new-address.sh`
	$ A2=`scripts/get-new-address.sh`
	$ TX=`alpha-cli -regtest -testnet=0 sendmany "" "{ \"$A1\":10, \"$A2\":10 }"`
	$ alpha-cli -regtest -testnet=0 setgenerate true

	# Find the inputs numbers corresponding to those 10 btc outs
	for i in $(seq 1 $(alpha-cli -regtest -testnet=0 listunspent | grep -c txid) ); do scripts/getinput.sh $i | grep -q "$TX.*/1000000000/" && echo $i; done

For each side A and B you need:

1. SEED: A secret 256-bit seed, in hex.
	Try 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
2. CHANGEADDR: An anchor change address (unless amounts are exact).
	eg. `scripts/get-new-address.sh`
3. CHANGEPUBKEY: The public key for CHANGEADDR.
	eg. `alpha-cli -regtest -testnet=0 validateaddress <CHANGEADDR> | grep pubkey`
4. TMPADDR: An address for the anchor output to the commitment transaction.
	eg. `scripts/get-new-address.sh`
5. TMPKEY: The private key for TMPADDR
	eg. `alpha-cli -regtest -testnet=0 dumpprivkey <TMPADDR>`
6. FINALADDR: An output address for when channel is closed.
	eg. `scripts/get-new-address.sh`
7. FINALKEY: The private key for FINALADDR
   	eg. `alpha-cli -regtest -testnet=0 dumpprivkey <FINALADDR>`
8. TXIN{1-n}: One or more unspent transaction outputs on testnet.
	These are in form "<txid>/<outnum>/<amount>/<scriptsig>/<privkey>".
	eg. scripts/getinput.sh (`scripts/getinput.sh 2`, etc).
9. ESCAPE-SECRET: A secret 256-bit number, in hex.
	Try 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff

STEP 1
------
First each side needs to tell the other what it wants the channel
to look like, including how many satoshis to put in the channel.

A: Create a channel open request packet:

	test-cli/open-channel <A-SEED> <amount> <A-TMPKEY> <A-FINALKEY> <A-ESCAPE-SECRET> > A-open.pb

B: The same:

	test-cli/open-channel <B-SEED> <amount> <B-TMPKEY> <B-FINALKEY> <B-ESCAPE-SECRET> > B-open.pb

STEP 2
------
Each side creates their anchor transaction which pays to a 2 of 2
(spendable with their own key and the other's TMPKEY or FINALKEY).  We
don't send them until we have completed the escape transactions
though, so we're sure we can get our funds back.

The change-pubkey arg is only used if you supply inputs which are greater
than the amount promised in the open packet.

A:
	test-cli/create-anchor-tx A-open.pb B-open.pb <A-CHANGEPUBKEY> <txid>/<outnum>/<amount>/<scriptsig>/<privkey>... > A-anchor.tx

B:
	test-cli/create-anchor-tx A-open.pb B-open.pb <B-CHANGEPUBKEY> <txid>/<outnum>/<amount>/<scriptsig>/<privkey>... > B-anchor.tx

STEP 3
------
Send transaction ID and output number of the anchor to the other side:

A:
	test-cli/open-anchor-id A-anchor.tx > A-anchor-id.pb

B:
	test-cli/open-anchor-id B-anchor.tx > B-anchor-id.pb

STEP 4
------
Create signatures for the other side's escape transaction(s) which
allow return of funds if something goes wrong:

A:
	test-cli/open-escape-sigs A-open.pb B-open.pb B-anchor-id.pb <A-TMPKEY> <A-FINALKEY> > A-escape-sigs.pb

B:
	test-cli/open-escape-sigs B-open.pb A-open.pb A-anchor-id.pb <B-TMPKEY> <B-FINALKEY> > B-escape-sigs.pb

STEP 5
------
Check the escape signatures from the other side, and use them to create our
escape txs.

A:
	test-cli/create-escape A-open.pb B-open.pb A-anchor-id.pb B-escape-sigs.pb <A-FINALKEY> > A-escape.tx
	test-cli/create-escape --fast A-open.pb B-open.pb A-anchor-id.pb B-escape-sigs.pb <A-FINALKEY> > A-fast-escape.tx

B:
	test-cli/create-escape B-open.pb A-open.pb B-anchor-id.pb A-escape-sigs.pb <B-FINALKEY> > B-escape.tx
	test-cli/create-escape --fast B-open.pb A-open.pb B-anchor-id.pb A-escape-sigs.pb <B-FINALKEY> > B-fast-escape.tx

STEP 6
------
Now both sides create the commitment transaction signatures which spend
the anchors outputs:

A:

	test-cli/open-commit-sig A-open.pb B-open.pb A-anchor-id.pb B-anchor-id.pb <A-TMPKEY> > A-commit-sig.pb
B:

	test-cli/open-commit-sig B-open.pb A-open.pb B-anchor-id.pb A-anchor-id.pb <B-TMPKEY> > B-commit-sig.pb

STEP 7
------
Check the commitment signatures from the other side, and produce commit txs.

A:

	test-cli/check-commit-sig A-open.pb B-open.pb A-anchor-id.pb B-anchor-id.pb B-commit-sig.pb <A-TMPKEY> > A-commit-0.tx
B:

	test-cli/check-commit-sig B-open.pb A-open.pb B-anchor-id.pb A-anchor-id.pb A-commit-sig.pb <B-TMPKEY> > B-commit-0.tx

STEP 8
------
Broadcast the anchor transactions (note they contain their inputs amounts
separated by colons for internal use: the daemon only wants the raw transaction):

A:
	alpha-cli -regtest -testnet=0 sendrawtransaction `cut -d: -f1 A-anchor.tx` > A-anchor.txid

B:
	alpha-cli -regtest -testnet=0 sendrawtransaction `cut -d: -f1 B-anchor.tx` > B-anchor.txid

Generate blocks until we have enough confirms (I don't do this, so I
can reset the entire state by restarting bitcoind with `-zapwallettxes=1`):

A:
	while [ 0$(alpha-cli -regtest -testnet=0 getrawtransaction $(cat B-anchor.txid) 1 | sed -n 's/.*"confirmations" : \([0-9]*\),/\1/p') -lt $(test-cli/get-anchor-depth A-open.pb) ]; do scripts/generate-block.sh; done

B:
	while [ 0$(alpha-cli -regtest -testnet=0 getrawtransaction $(cat A-anchor.txid) 1 | sed -n 's/.*"confirmations" : \([0-9]*\),/\1/p') -lt $(test-cli/get-anchor-depth B-open.pb) ]; do scripts/generate-block.sh; done

Using a Generalized Channel
===========================

Let's make a payment now!  Either end can propose a change to the
latest commitment tx, like so:

A:

	test-cli/update-channel (--to-them=xxx or --from-them=xxx) <A-SEED> > A-update-1.pb

The other end accepts the update, and provides the signature for the new tx and
revocation hash for the new tx:

B:

	test-cli/update-channel-accept <B-SEED> B-open.pb A-open.pb B-anchor-id.pb A-anchor-id.pb <B-TMPKEY> A-update-1.pb > B-update-accept-1.pb

A completes its side by signing the new tx, and revoking the old:

A:

	test-cli/update-channel-signature <A_SEED> A-open.pb B-open.pb A-anchor-id.pb B-anchor-id.pb <A-TMPKEY> A-update-1.pb B-update-accept-1.pb > A-update-sig-1.pb

B now revokes its old tx:

B:

	test-cli/update-channel-complete <B_SEED> B-open.pb A-open.pb B-anchor-id.pb A-anchor-id.pb A-update-1.pb A-update-sig-1.pb > B-update-complete-1.pb

B checks that the commit tx is indeed revoked.

B:

	./check-commit-complete A-open.pb A-commit-complete-1.pb 

To update it again, simply re-run the commands with the previous
updates appended, as shown in `test-cli/test.sh`.

(Optional)
Generate new commitment txs, by including all the update proposals
since the initial tx (here we just have one, A-update-1.pb):

A:

	test-cli/create-commit-tx A-open.pb B-open.pb A-anchor-id.pb B-anchor-id.pb A-update-1.pb B-update-accept-1.pb <A-TMPKEY> > A-commit-1.tx

Special Effects: Trying To Cheat
================================

A now tries to spend an old (revoked) commitment tx:

A:

	test-cli/create-commit-tx A-open.pb B-open.pb A-anchor-id.pb B-anchor-id.pb <A-TMPKEY> B-commit-sig.pb > commit-0.tx

A:

	alpha-cli -regtest -testnet=0 sendrawtransaction `cat A-commit-0.tx`

B can steal the money, using the revocation hash from A-update-sig-1:

B:

	./create-steal-tx A-commit-0.tx A-update-sig-1.pb <A-FINALKEY> B-open.pb A-open.pb <SOME-PUBKEY-TO-PAYTO> > B-commit-steal.tx

B:

	alpha-cli -regtest -testnet=0 sendrawtransaction `cat B-commit-steal.tx`

Closing the Channel: Unilaterally
=================================

To close unilaterally, one side broadcasts its latest commitment tx:

A:

	alpha-cli -regtest -testnet=0 sendrawtransaction `cat A-commit-1.tx`

Now, we can create the transaction to spend the output:

A:

	./create-commit-spend-tx A-commit-1.tx <A-FINALKEY> <someaddress> > spend.tx

Normally A would have to wait 1 day, but because
OP_CHECKSEQUENCEVERIFY is a nop, we can actually claim this
immediately:

A:

	alpha-cli -regtest -testnet=0 sendrawtransaction `cat spend.tx`

Closing the Channel By Mutual Consent
=====================================

This is the normal way to do it.  Include all the update proposals at
the end of the command line (eg. `?-update-?.pb`), so the transaction outputs
reflect the final commitment total:

A:

	./close-channel A-open.pb B-open.pb A-anchor-id.pb B-anchor-id.pb <A-TMPKEY> A-update-1.pb > A-close.pb
B:

	./close-channel --complete B-open.pb A-open.pb B-anchor-id.pb A-anchor-id.pb <B-TMPKEY> A-update-1.pb > B-close-accept.pb

Both ends have both signatures now, so either can create the close tx:

A:

	./create-close-tx A-open.pb B-open.pb A-anchor-id.pb B-anchor-id.pb A-close.pb B-close-accept.pb > A-close.tx

B:

	./create-close-tx B-open.pb A-open.pb B-anchor-id.pb A-anchor-id.pb A-close.pb B-close-accept.pb > B-close.tx

They should be identical:

	cmp A-close.tx B-close.tx || echo FAIL

Good luck!

Rusty.
