#! /bin/sh
set -e

# Expect to be run from test-cli dir.
. scripts/vars.sh

getpubkey()
{
    $CLI validateaddress $1 | sed -n 's/.*"pubkey" *: "\([0-9a-f]*\)".*/\1/p'
}

getprivkey()
{
    $CLI dumpprivkey $1
}

send_after_delay()
{
    # For bitcoin testing, OP_CHECKSEQUENCEVERIFY is a NOP.
    if [ $STYLE = alpha ]; then
	# Alpha has a median time bug (which can't be triggered in bitcoin),
	# triggered if we have < 11 blocks.  Generate them now.
	for i in `seq 11`; do scripts/generate-block.sh; done
	# OP_CHECKSEQUENCEVERIFY will stop us spending for 60 seconds.
	for tx; do
	    if $CLI sendrawtransaction $tx 2>/dev/null; then
		echo OP_CHECKSEQUENCEVERIFY broken! >&2
		exit 1
	    fi
	done
    fi

    # Bitcoin still respects lock_time, which is used for HTLCs.

    # Confirm them.
    scripts/generate-block.sh
    echo Waiting for CSV timeout. >&2
    sleep 61
    # Move median time, for sure!
    for i in `seq 11`; do scripts/generate-block.sh; done
	
    for tx; do
	$CLI sendrawtransaction $tx
    done
}

if [ $# = 0 ]; then
    echo Usage: "INPUT" "[--steal|--unilateral|--htlc-onchain]" >&2
    exit 1
fi
		      
A_INPUTNUM=$1
shift
#A_INPUTNUM=4
#B_INPUTNUM=1
A_AMOUNT=100000000

A_CHANGEADDR=`scripts/get-new-address.sh`
A_TMPADDR=`scripts/get-new-address.sh`
A_FINALADDR=`scripts/get-new-address.sh`

B_CHANGEADDR=`scripts/get-new-address.sh`
B_TMPADDR=`scripts/get-new-address.sh`
B_FINALADDR=`scripts/get-new-address.sh`

#A_CHANGEADDR=mzJseRSpUnmUDRJkp9Jp3XRmLKRrFk8KEF
#A_TMPADDR=mxAucVQU1WWRcMd9ubx1gisteFuy5MgSVh
#A_FINALADDR=mgjMAVHe8Kgx38SY3apjHdLwz2deJ2ZY2H

#B_CHANGEADDR=mmCiKXHPWunBMFhqZx7fg1v23HssJJesLV
#B_TMPADDR=mvY4WDonPXq3Xa3NL4uSG26PXKRuLsXGTT
#B_FINALADDR=mvQgfEX4iMSEYqD31524jASQviPwPwpvuv

A_TXIN=`scripts/getinput.sh $A_INPUTNUM`

A_SEED=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
B_SEED=112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00

A_HTLC1=deadbeefbadc0ffeedeadbeefbadc0ffeedeadbeefbadc0ffeedeadbeefbadc0
A_CHANGEPUBKEY=`getpubkey $A_CHANGEADDR`
A_TMPKEY=`getprivkey $A_TMPADDR`
A_TMPPUBKEY=`getpubkey $A_TMPADDR`
A_FINALKEY=`getprivkey $A_FINALADDR`
A_FINALPUBKEY=`getpubkey $A_FINALADDR`

B_HTLC1=badc0de5badc0de5badc0de5badc0de5badc0de5badc0de5badc0de5badc0de5
B_CHANGEPUBKEY=`getpubkey $B_CHANGEADDR`
B_TMPKEY=`getprivkey $B_TMPADDR`
B_TMPPUBKEY=`getpubkey $B_TMPADDR`
B_FINALKEY=`getprivkey $B_FINALADDR`
B_FINALPUBKEY=`getpubkey $B_FINALADDR`

# Both sides say what they want from channel (A offers anchor)
$PREFIX ./open-channel --offer-anchor $A_SEED $A_TMPPUBKEY $A_FINALPUBKEY > A-open.pb
# B asks for a (dangerously) short locktime, for testing unilateral close.
$PREFIX ./open-channel --locktime=60 $B_SEED $B_TMPPUBKEY $B_FINALPUBKEY > B-open.pb

# Now A creates anchor (does not broadcast!)
$PREFIX ./create-anchor-tx A-open.pb B-open.pb $A_AMOUNT $A_CHANGEPUBKEY $A_TXIN > A-anchor.tx

# Now A sends info about anchor output, and signature for commit tx.
$PREFIX ./open-anchor A-open.pb B-open.pb A-anchor.tx $A_TMPKEY > A-anchor.pb

# Now B signs commit sig for anchor.
$PREFIX ./open-commit-sig B-open.pb A-open.pb A-anchor.pb $B_TMPKEY > B-commit-sig.pb

# Now check sigs.
$PREFIX ./check-commit-sig A-open.pb B-open.pb A-anchor.pb $A_TMPKEY B-commit-sig.pb
$PREFIX ./check-commit-sig B-open.pb A-open.pb A-anchor.pb $B_TMPKEY

# A broadcasts anchor
$CLI sendrawtransaction `cut -d: -f1 A-anchor.tx` > A-anchor.txid

# Wait for confirms
while [ 0$($CLI getrawtransaction $(cat A-anchor.txid) 1 | sed -n 's/.*"confirmations" : \([0-9]*\),/\1/p') -lt $($PREFIX ./get-anchor-depth A-open.pb) ]; do scripts/generate-block.sh; done

while [ 0$($CLI getrawtransaction $(cat A-anchor.txid) 1 | sed -n 's/.*"confirmations" : \([0-9]*\),/\1/p') -lt $($PREFIX ./get-anchor-depth B-open.pb) ]; do scripts/generate-block.sh; done

# Update traffic sent so far.
A_UPDATE_PKTS="-- -B-commit-sig.pb"
B_UPDATE_PKTS="-- +B-commit-sig.pb"

# Just for testing, generate the first commit transactions.
$PREFIX ./create-commit-tx A-open.pb B-open.pb A-anchor.pb $A_TMPKEY $A_UPDATE_PKTS > A-commit-0.tx
$PREFIX ./create-commit-tx B-open.pb A-open.pb A-anchor.pb $B_TMPKEY $B_UPDATE_PKTS > B-commit-0.tx

# Now, update the channel, so I pay you 80000 satoshi (covers 50000 fee)
$PREFIX ./update-channel --to-them=80000 $A_SEED 1 > A-update-1.pb
A_UPDATE_PKTS="$A_UPDATE_PKTS +A-update-1.pb"
B_UPDATE_PKTS="$B_UPDATE_PKTS -A-update-1.pb"

$PREFIX ./update-channel-accept $B_SEED B-open.pb A-open.pb A-anchor.pb $B_TMPKEY $B_UPDATE_PKTS > B-update-accept-1.pb
A_UPDATE_PKTS="$A_UPDATE_PKTS -B-update-accept-1.pb"
B_UPDATE_PKTS="$B_UPDATE_PKTS +B-update-accept-1.pb"

$PREFIX ./update-channel-signature $A_SEED A-open.pb B-open.pb A-anchor.pb $A_TMPKEY $A_UPDATE_PKTS > A-update-sig-1.pb
A_UPDATE_PKTS="$A_UPDATE_PKTS +A-update-sig-1.pb"
B_UPDATE_PKTS="$B_UPDATE_PKTS -A-update-sig-1.pb"

$PREFIX ./update-channel-complete $B_SEED B-open.pb A-open.pb A-anchor.pb $B_UPDATE_PKTS > B-update-complete-1.pb
A_UPDATE_PKTS="$A_UPDATE_PKTS -B-update-complete-1.pb"
B_UPDATE_PKTS="$B_UPDATE_PKTS +B-update-complete-1.pb"

# Just for testing, generate second transaction
$PREFIX ./create-commit-tx A-open.pb B-open.pb A-anchor.pb $A_TMPKEY $A_UPDATE_PKTS > A-commit-1.tx
$PREFIX ./create-commit-tx B-open.pb A-open.pb A-anchor.pb $B_TMPKEY $B_UPDATE_PKTS > B-commit-1.tx

# Now you pay me 5000.
$PREFIX ./update-channel --to-them=5000 $B_SEED 2 > B-update-2.pb
A_UPDATE_PKTS="$A_UPDATE_PKTS -B-update-2.pb"
B_UPDATE_PKTS="$B_UPDATE_PKTS +B-update-2.pb"

$PREFIX ./update-channel-accept $A_SEED A-open.pb B-open.pb A-anchor.pb $A_TMPKEY $A_UPDATE_PKTS > A-update-accept-2.pb
A_UPDATE_PKTS="$A_UPDATE_PKTS +A-update-accept-2.pb"
B_UPDATE_PKTS="$B_UPDATE_PKTS -A-update-accept-2.pb"

$PREFIX ./update-channel-signature $B_SEED B-open.pb A-open.pb A-anchor.pb $B_TMPKEY $B_UPDATE_PKTS > B-update-sig-2.pb
A_UPDATE_PKTS="$A_UPDATE_PKTS -B-update-sig-2.pb"
B_UPDATE_PKTS="$B_UPDATE_PKTS +B-update-sig-2.pb"

$PREFIX ./update-channel-complete $A_SEED A-open.pb B-open.pb A-anchor.pb $A_UPDATE_PKTS > A-update-complete-2.pb
A_UPDATE_PKTS="$A_UPDATE_PKTS +A-update-complete-2.pb"
B_UPDATE_PKTS="$B_UPDATE_PKTS -A-update-complete-2.pb"

# Just for testing, generate third transaction
$PREFIX ./create-commit-tx A-open.pb B-open.pb A-anchor.pb $A_TMPKEY $A_UPDATE_PKTS > A-commit-2.tx
$PREFIX ./create-commit-tx B-open.pb A-open.pb A-anchor.pb $B_TMPKEY $B_UPDATE_PKTS > B-commit-2.tx

# Now, A offers an HTLC for 10001 satoshi.
$PREFIX ./update-channel-htlc $A_SEED 3 10001 $A_HTLC1 $((`date +%s` + 60)) > A-update-htlc-3.pb
A_UPDATE_PKTS="$A_UPDATE_PKTS +A-update-htlc-3.pb"
B_UPDATE_PKTS="$B_UPDATE_PKTS -A-update-htlc-3.pb"

$PREFIX ./update-channel-accept $B_SEED B-open.pb A-open.pb A-anchor.pb $B_TMPKEY $B_UPDATE_PKTS > B-update-accept-3.pb
A_UPDATE_PKTS="$A_UPDATE_PKTS -B-update-accept-3.pb"
B_UPDATE_PKTS="$B_UPDATE_PKTS +B-update-accept-3.pb"

$PREFIX ./update-channel-signature $A_SEED A-open.pb B-open.pb A-anchor.pb $A_TMPKEY $A_UPDATE_PKTS > A-update-sig-3.pb
A_UPDATE_PKTS="$A_UPDATE_PKTS +A-update-sig-3.pb"
B_UPDATE_PKTS="$B_UPDATE_PKTS -A-update-sig-3.pb"

$PREFIX ./update-channel-complete $B_SEED B-open.pb A-open.pb A-anchor.pb $B_UPDATE_PKTS > B-update-complete-3.pb
A_UPDATE_PKTS="$A_UPDATE_PKTS -B-update-complete-3.pb"
B_UPDATE_PKTS="$B_UPDATE_PKTS +B-update-complete-3.pb"

# Just for testing, generate that transaction
$PREFIX ./create-commit-tx A-open.pb B-open.pb A-anchor.pb $A_TMPKEY $A_UPDATE_PKTS > A-commit-3.tx
$PREFIX ./create-commit-tx B-open.pb A-open.pb A-anchor.pb $B_TMPKEY $B_UPDATE_PKTS > B-commit-3.tx

# Now, B offers an HTLC for 10002 satoshi.
$PREFIX ./update-channel-htlc $B_SEED 4 10002 $B_HTLC1 $((`date +%s` + 60)) > B-update-htlc-4.pb
A_UPDATE_PKTS="$A_UPDATE_PKTS -B-update-htlc-4.pb"
B_UPDATE_PKTS="$B_UPDATE_PKTS +B-update-htlc-4.pb"

$PREFIX ./update-channel-accept $A_SEED A-open.pb B-open.pb A-anchor.pb $A_TMPKEY $A_UPDATE_PKTS > A-update-accept-4.pb
A_UPDATE_PKTS="$A_UPDATE_PKTS +A-update-accept-4.pb"
B_UPDATE_PKTS="$B_UPDATE_PKTS -A-update-accept-4.pb"

$PREFIX ./update-channel-signature $B_SEED B-open.pb A-open.pb A-anchor.pb $B_TMPKEY $B_UPDATE_PKTS > B-update-sig-4.pb
A_UPDATE_PKTS="$A_UPDATE_PKTS -B-update-sig-4.pb"
B_UPDATE_PKTS="$B_UPDATE_PKTS +B-update-sig-4.pb"

$PREFIX ./update-channel-complete $A_SEED A-open.pb B-open.pb A-anchor.pb $A_UPDATE_PKTS > A-update-complete-4.pb
A_UPDATE_PKTS="$A_UPDATE_PKTS +A-update-complete-4.pb"
B_UPDATE_PKTS="$B_UPDATE_PKTS -A-update-complete-4.pb"

# Just for testing, generate that transaction
$PREFIX ./create-commit-tx A-open.pb B-open.pb A-anchor.pb $A_TMPKEY $A_UPDATE_PKTS > A-commit-4.tx
$PREFIX ./create-commit-tx B-open.pb A-open.pb A-anchor.pb $B_TMPKEY $B_UPDATE_PKTS > B-commit-4.tx

# Solve the HTLCs with the R value on the chain.
if [ x"$1" = x--htlc-onchain ]; then
    $CLI sendrawtransaction `cut -d: -f1 A-commit-4.tx` > A-commit-4.txid

    # Now, B can claim A's HTLC using R value.
    # It's A's commit tx, so most of cmdline is written from A's POV.
    $PREFIX ./create-htlc-spend-tx --rvalue=$A_HTLC1 -- A-open.pb B-open.pb A-commit-4.tx +A-update-htlc-3.pb A-update-accept-4.pb $B_FINALKEY $B_CHANGEPUBKEY > B-htlc-3-spend.tx
    $CLI sendrawtransaction `cut -d: -f1 B-htlc-3-spend.tx` > B-htlc-3-spend.txid

    # A can claim using B's HTLC using R value, after delay.
    $PREFIX ./create-htlc-spend-tx --rvalue=$B_HTLC1 -- A-open.pb B-open.pb A-commit-4.tx -B-update-htlc-4.pb A-update-accept-4.pb $A_FINALKEY $A_CHANGEPUBKEY > A-htlc-4-spend.tx
    send_after_delay `cut -d: -f1 A-htlc-4-spend.tx` > A-htlc-4-spend.txid
    exit 0
fi

if [ x"$1" = x--unilateral ]; then
    # Use commit-4, which has htlcs.
    $CLI sendrawtransaction `cut -d: -f1 A-commit-4.tx` > A-commit-4.txid
    $PREFIX ./create-commit-spend-tx A-commit-4.tx A-open.pb B-open.pb A-anchor.pb $A_FINALKEY $A_CHANGEPUBKEY $A_UPDATE_PKTS > A-spend.tx
    $PREFIX ./create-htlc-spend-tx A-open.pb B-open.pb A-commit-4.tx +A-update-htlc-3.pb A-update-accept-4.pb $A_FINALKEY $A_CHANGEPUBKEY > A-htlc-3-spend.tx
    $PREFIX ./create-htlc-spend-tx -- A-open.pb B-open.pb A-commit-4.tx -B-update-htlc-4.pb A-update-accept-4.pb $B_FINALKEY $B_CHANGEPUBKEY > B-htlc-4-spend.tx
    # HTLCs conveniently set to 60 seconds, though absolute.  Script
    # shouldn't be that slow, so they should be unspendable to start.
    send_after_delay `cut -d: -f1 A-spend.tx` `cut -d: -f1 A-htlc-3-spend.tx` `cut -d: -f1 B-htlc-4-spend.tx` > A-spend.txids
    exit 0
fi

# B completes A's HTLC using R value.
$PREFIX ./update-channel-htlc-complete $B_SEED 5 $A_HTLC1 > B-update-htlc-complete-5.pb
A_UPDATE_PKTS="$A_UPDATE_PKTS -B-update-htlc-complete-5.pb"
B_UPDATE_PKTS="$B_UPDATE_PKTS +B-update-htlc-complete-5.pb"

$PREFIX ./update-channel-accept $A_SEED A-open.pb B-open.pb A-anchor.pb $A_TMPKEY $A_UPDATE_PKTS > A-update-accept-5.pb
A_UPDATE_PKTS="$A_UPDATE_PKTS +A-update-accept-5.pb"
B_UPDATE_PKTS="$B_UPDATE_PKTS -A-update-accept-5.pb"

$PREFIX ./update-channel-signature $B_SEED B-open.pb A-open.pb A-anchor.pb $B_TMPKEY $B_UPDATE_PKTS > B-update-sig-5.pb
A_UPDATE_PKTS="$A_UPDATE_PKTS -B-update-sig-5.pb"
B_UPDATE_PKTS="$B_UPDATE_PKTS +B-update-sig-5.pb"

$PREFIX ./update-channel-complete $A_SEED A-open.pb B-open.pb A-anchor.pb $A_UPDATE_PKTS > A-update-complete-5.pb
A_UPDATE_PKTS="$A_UPDATE_PKTS +A-update-complete-5.pb"
B_UPDATE_PKTS="$B_UPDATE_PKTS -A-update-complete-5.pb"

# Just for testing, generate that transaction
$PREFIX ./create-commit-tx A-open.pb B-open.pb A-anchor.pb $A_TMPKEY $A_UPDATE_PKTS > A-commit-5.tx
$PREFIX ./create-commit-tx B-open.pb A-open.pb A-anchor.pb $B_TMPKEY $B_UPDATE_PKTS > B-commit-5.tx

# Now, B tries to remove its HTLC (A accepts)
$PREFIX ./update-channel-htlc-remove $B_SEED 6 B-update-htlc-4.pb > B-update-htlc-remove-6.pb
A_UPDATE_PKTS="$A_UPDATE_PKTS -B-update-htlc-remove-6.pb"
B_UPDATE_PKTS="$B_UPDATE_PKTS +B-update-htlc-remove-6.pb"

$PREFIX ./update-channel-accept $A_SEED A-open.pb B-open.pb A-anchor.pb $A_TMPKEY $A_UPDATE_PKTS > A-update-accept-6.pb
A_UPDATE_PKTS="$A_UPDATE_PKTS +A-update-accept-6.pb"
B_UPDATE_PKTS="$B_UPDATE_PKTS -A-update-accept-6.pb"

$PREFIX ./update-channel-signature $B_SEED B-open.pb A-open.pb A-anchor.pb $B_TMPKEY $B_UPDATE_PKTS > B-update-sig-6.pb
A_UPDATE_PKTS="$A_UPDATE_PKTS -B-update-sig-6.pb"
B_UPDATE_PKTS="$B_UPDATE_PKTS +B-update-sig-6.pb"

$PREFIX ./update-channel-complete $A_SEED A-open.pb B-open.pb A-anchor.pb $A_UPDATE_PKTS > A-update-complete-6.pb
A_UPDATE_PKTS="$A_UPDATE_PKTS +A-update-complete-6.pb"
B_UPDATE_PKTS="$B_UPDATE_PKTS -A-update-complete-6.pb"

# Just for testing, generate that transaction
$PREFIX ./create-commit-tx A-open.pb B-open.pb A-anchor.pb $A_TMPKEY $A_UPDATE_PKTS > A-commit-6.tx
$PREFIX ./create-commit-tx B-open.pb A-open.pb A-anchor.pb $B_TMPKEY $B_UPDATE_PKTS > B-commit-6.tx

if [ x"$1" = x--steal ]; then
    # A stupidly broadcasts a revoked transaction.
    $CLI sendrawtransaction `cut -d: -f1 A-commit-4.tx` > A-commit-4.txid
    
    # B uses the preimage from A-update-complete-5 to cash in.
    $PREFIX ./create-steal-tx A-commit-4.tx A-update-complete-5.pb $B_FINALKEY B-open.pb A-open.pb $B_CHANGEPUBKEY > B-commit-steal.tx

    $CLI sendrawtransaction `cut -d: -f1 B-commit-steal.tx` > B-commit-steal.txid

    # Now B uses the same preimage to get the HTLC amounts too.
    # It's A's commit tx, so most of cmdline is written from A's POV.
    $PREFIX ./create-htlc-spend-tx --commit-preimage=A-update-complete-5.pb -- A-open.pb B-open.pb A-commit-4.tx +A-update-htlc-3.pb A-update-accept-4.pb $B_FINALKEY $B_CHANGEPUBKEY > B-htlc-steal-1.tx
    $CLI sendrawtransaction `cut -d: -f1 B-htlc-steal-1.tx` > B-htlc-steal-1.txid

    $PREFIX ./create-htlc-spend-tx --commit-preimage=A-update-complete-5.pb -- A-open.pb B-open.pb A-commit-4.tx -B-update-htlc-4.pb A-update-accept-4.pb $B_FINALKEY $B_CHANGEPUBKEY > B-htlc-steal-2.tx
    $CLI sendrawtransaction `cut -d: -f1 B-htlc-steal-2.tx` > B-htlc-steal-2.txid
    exit 0
fi

# Now close channel by mutual consent.
$PREFIX ./close-channel A-open.pb B-open.pb A-anchor.pb $A_TMPKEY $A_UPDATE_PKTS > A-close.pb
$PREFIX ./close-channel --complete=A-close.pb B-open.pb A-open.pb A-anchor.pb $B_TMPKEY $B_UPDATE_PKTS > B-close-complete.pb
$PREFIX ./create-close-tx A-open.pb B-open.pb A-anchor.pb A-close.pb B-close-complete.pb $A_UPDATE_PKTS > A-close.tx

$CLI sendrawtransaction `cut -d: -f1 A-close.tx` > close.txid
