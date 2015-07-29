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
	if $CLI sendrawtransaction $1 2>/dev/null; then
	    echo OP_CHECKSEQUENCEVERIFY broken! >&2
	    exit 1
	fi
	# Mine it.
	scripts/generate-block.sh
	echo Waiting for CSV timeout. >&2
	sleep 61
	# Move median time, for sure!
	for i in `seq 11`; do scripts/generate-block.sh; done
    fi
    $CLI sendrawtransaction $1
}

if [ $# = 0 ]; then
    echo Usage: "INPUT" "[--steal|--unilateral]" >&2
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

A_CHANGEPUBKEY=`getpubkey $A_CHANGEADDR`
A_TMPKEY=`getprivkey $A_TMPADDR`
A_TMPPUBKEY=`getpubkey $A_TMPADDR`
A_FINALKEY=`getprivkey $A_FINALADDR`
A_FINALPUBKEY=`getpubkey $A_FINALADDR`

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

# Now, update the channel, so I pay you 60000 satoshi (covers 50000 fee)
$PREFIX ./update-channel --to-them=60000 $A_SEED 1 > A-update-1.pb
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

# Now you pay me 250.
$PREFIX ./update-channel --to-them=250 $B_SEED 2 > B-update-2.pb
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

if [ x"$1" = x--steal ]; then
    # A stupidly broadcasts a revoked transaction.
    $CLI sendrawtransaction `cut -d: -f1 A-commit-1.tx` > A-commit-1.txid
    
    # B uses the preimage from A-update-complete-2 to cash in.
    $PREFIX ./create-steal-tx A-commit-1.tx A-update-complete-2.pb $B_FINALKEY B-open.pb A-open.pb $B_CHANGEPUBKEY > B-commit-steal.tx

    $CLI sendrawtransaction `cut -d: -f1 B-commit-steal.tx` > B-commit-steal.txid
    exit 0
fi

if [ x"$1" = x--unilateral ]; then
    $CLI sendrawtransaction `cut -d: -f1 A-commit-2.tx` > A-commit-2.txid
    $PREFIX ./create-commit-spend-tx A-commit-2.tx A-open.pb B-open.pb A-anchor.pb $A_FINALKEY $A_CHANGEPUBKEY $A_UPDATE_PKTS > A-spend.tx
    send_after_delay `cut -d: -f1 A-spend.tx` > A-spend.txid
    exit 0
fi

# Now close channel by mutual consent.
$PREFIX ./close-channel A-open.pb B-open.pb A-anchor.pb $A_TMPKEY $A_UPDATE_PKTS > A-close.pb
$PREFIX ./close-channel --complete=A-close.pb B-open.pb A-open.pb A-anchor.pb $B_TMPKEY $B_UPDATE_PKTS > B-close-complete.pb
$PREFIX ./create-close-tx A-open.pb B-open.pb A-anchor.pb A-close.pb B-close-complete.pb $A_UPDATE_PKTS > A-close.tx

$CLI sendrawtransaction `cut -d: -f1 A-close.tx` > close.txid
