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

if [ $# -lt 2 ]; then
    echo Usage: "INPUT1" "INPUT2" "[--steal|--unilateral]" >&2
    exit 1
fi
		      
A_INPUTNUM=$1
B_INPUTNUM=$2
shift 2
#A_INPUTNUM=4
#B_INPUTNUM=1
A_AMOUNT=100000000
B_AMOUNT=200000000

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
B_TXIN=`scripts/getinput.sh $B_INPUTNUM`

A_SEED=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
B_SEED=112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00

A_ESCSECRET=00112233445566778899aabbccddeeff00112233445566778899aabbccddeef0
B_ESCSECRET=112233445566778899aabbccddeeff00112233445566778899aabbccddeeff0f

A_CHANGEPUBKEY=`getpubkey $A_CHANGEADDR`
A_TMPKEY=`getprivkey $A_TMPADDR`
A_FINALKEY=`getprivkey $A_FINALADDR`
A_FINALPUBKEY=`getpubkey $A_FINALADDR`

B_CHANGEPUBKEY=`getpubkey $B_CHANGEADDR`
B_TMPKEY=`getprivkey $B_TMPADDR`
B_FINALKEY=`getprivkey $B_FINALADDR`
B_FINALPUBKEY=`getpubkey $B_FINALADDR`

# Both sides say what they want from channel
# FIXME: Use pubkeys for tmpkey and finalkey here! 
$PREFIX ./open-channel $A_SEED $A_AMOUNT $A_TMPKEY $A_FINALKEY $A_ESCSECRET > A-open.pb
# B asks for a (dangerously) short locktime, for testing unilateral close.
$PREFIX ./open-channel --locktime=60 $B_SEED $B_AMOUNT $B_TMPKEY $B_FINALKEY $B_ESCSECRET > B-open.pb

# Now create anchors.
$PREFIX ./create-anchor-tx A-open.pb B-open.pb $A_CHANGEPUBKEY $A_TXIN > A-anchor.tx
$PREFIX ./create-anchor-tx B-open.pb A-open.pb $B_CHANGEPUBKEY $B_TXIN > B-anchor.tx

# Now tell the other side about it.
$PREFIX ./open-anchor-id A-anchor.tx $A_CHANGEPUBKEY > A-anchor-id.pb
$PREFIX ./open-anchor-id B-anchor.tx $B_CHANGEPUBKEY > B-anchor-id.pb

# Now sign escape transactions for the other side.
$PREFIX ./open-escape-sigs A-open.pb B-open.pb B-anchor-id.pb $A_FINALKEY > A-escape-sigs.pb
$PREFIX ./open-escape-sigs B-open.pb A-open.pb A-anchor-id.pb $B_FINALKEY > B-escape-sigs.pb

# Use their signature to create our escape txs.
$PREFIX ./create-escape-tx A-open.pb B-open.pb A-anchor-id.pb B-escape-sigs.pb $A_TMPKEY $A_ESCSECRET > A-escape.tx
$PREFIX ./create-escape-tx --fast A-open.pb B-open.pb A-anchor-id.pb B-escape-sigs.pb $A_TMPKEY $A_ESCSECRET > A-fast-escape.tx
$PREFIX ./create-escape-tx B-open.pb A-open.pb B-anchor-id.pb A-escape-sigs.pb $B_TMPKEY $B_ESCSECRET > B-escape.tx
$PREFIX ./create-escape-tx --fast B-open.pb A-open.pb B-anchor-id.pb A-escape-sigs.pb $B_TMPKEY $B_ESCSECRET > B-fast-escape.tx

# Broadcast anchors
$CLI sendrawtransaction `cut -d: -f1 A-anchor.tx` > A-anchor.txid
$CLI sendrawtransaction `cut -d: -f1 B-anchor.tx` > B-anchor.txid

# Now create commit signature
$PREFIX ./open-commit-sig A-open.pb B-open.pb A-anchor-id.pb B-anchor-id.pb $A_TMPKEY > A-commit-sig.pb
$PREFIX ./open-commit-sig B-open.pb A-open.pb B-anchor-id.pb A-anchor-id.pb $B_TMPKEY > B-commit-sig.pb

# Now check it.
$PREFIX ./check-commit-sig A-open.pb B-open.pb A-anchor-id.pb B-anchor-id.pb B-commit-sig.pb $A_TMPKEY > A-commit.tx
$PREFIX ./check-commit-sig B-open.pb A-open.pb B-anchor-id.pb A-anchor-id.pb A-commit-sig.pb $B_TMPKEY > B-commit.tx

# # Wait for confirms
# while [ 0$($CLI getrawtransaction $(cat B-anchor.txid) 1 | sed -n 's/.*"confirmations" : \([0-9]*\),/\1/p') -lt $($PREFIX ./get-anchor-depth A-open.pb) ]; do scripts/generate-block.sh; done

# while [ 0$($CLI getrawtransaction $(cat A-anchor.txid) 1 | sed -n 's/.*"confirmations" : \([0-9]*\),/\1/p') -lt $($PREFIX ./get-anchor-depth B-open.pb) ]; do scripts/generate-block.sh; done

# Tell other side that channel is open.
$PREFIX ./open-complete $A_ESCSECRET > A-open-complete.pb
$PREFIX ./open-complete $B_ESCSECRET > B-open-complete.pb

# Each side checks that escape preimage is correct.
$PREFIX ./check-open-complete B-open.pb B-open-complete.pb
$PREFIX ./check-open-complete A-open.pb A-open-complete.pb

# Just for testing, generate the first transaction.
$PREFIX ./create-commit-tx A-open.pb B-open.pb A-anchor-id.pb B-anchor-id.pb $A_TMPKEY B-commit-sig.pb > A-commit-0.tx

# Now, update the channel, so I pay you 500 satoshi.
$PREFIX ./update-channel --to-them=500 $A_SEED > A-update-1.pb
$PREFIX ./update-channel-accept $B_SEED B-open.pb A-open.pb B-anchor-id.pb A-anchor-id.pb $B_TMPKEY A-update-1.pb > B-update-accept-1.pb
$PREFIX ./update-channel-signature $A_SEED A-open.pb B-open.pb A-anchor-id.pb B-anchor-id.pb $A_TMPKEY A-update-1.pb B-update-accept-1.pb > A-update-sig-1.pb
$PREFIX ./update-channel-complete $B_SEED B-open.pb A-open.pb B-anchor-id.pb A-anchor-id.pb A-update-1.pb A-update-sig-1.pb > B-update-complete-1.pb

# Just for testing, generate second transaction
$PREFIX ./create-commit-tx A-open.pb B-open.pb A-anchor-id.pb B-anchor-id.pb $A_TMPKEY B-update-accept-1.pb A-update-1.pb > A-commit-1.tx

# Now you pay me 1000.
$PREFIX ./update-channel --from-them=1000 $A_SEED A-update-1.pb > A-update-2.pb
$PREFIX ./update-channel-accept $B_SEED B-open.pb A-open.pb B-anchor-id.pb A-anchor-id.pb $B_TMPKEY A-update-2.pb A-update-1.pb > B-update-accept-2.pb 2>/dev/null
$PREFIX ./update-channel-signature $A_SEED A-open.pb B-open.pb A-anchor-id.pb B-anchor-id.pb $A_TMPKEY A-update-2.pb B-update-accept-2.pb A-update-1.pb > A-update-sig-2.pb
$PREFIX ./update-channel-complete $B_SEED B-open.pb A-open.pb B-anchor-id.pb A-anchor-id.pb A-update-2.pb A-update-sig-2.pb A-update-1.pb > B-update-complete-2.pb

# Just for testing, generate third transaction
$PREFIX ./create-commit-tx A-open.pb B-open.pb A-anchor-id.pb B-anchor-id.pb $A_TMPKEY B-update-accept-2.pb A-update-1.pb A-update-2.pb > A-commit-2.tx

if [ x"$1" = x--steal ]; then
    # A stupidly broadcasts a revoked transaction.
    $CLI sendrawtransaction `cut -d: -f1 A-commit-1.tx` > A-commit-1.txid
    
    # B uses the preimage from A-update-sig-2 to cash in.
    $PREFIX ./extract-revocation-preimage A-update-sig-2.pb > A-revocation-1
    $PREFIX ./create-secret-spend-tx --secret A-commit-1.tx $A_FINALPUBKEY 60 $B_FINALKEY $B_CHANGEPUBKEY `cat A-revocation-1` > B-commit-steal.tx

    $CLI sendrawtransaction `cut -d: -f1 B-commit-steal.tx` > B-commit-steal.txid
    exit 0
fi

if [ x"$1" = x--unilateral ]; then
    $CLI sendrawtransaction `cut -d: -f1 A-commit-2.tx` > A-commit-2.txid
    $PREFIX ./get-revocation-secret --hash $A_SEED 2 > A-commit-2.rhash
    $PREFIX ./create-secret-spend-tx --no-secret A-commit-2.tx $B_FINALPUBKEY 60 $A_FINALKEY $A_CHANGEPUBKEY `cat A-commit-2.rhash` > A-spend.tx
    send_after_delay `cut -d: -f1 A-spend.tx` > A-spend.txid
    exit 0
fi

# Now close channel by mutual consent.
$PREFIX ./close-channel A-open.pb B-open.pb A-anchor-id.pb B-anchor-id.pb $A_TMPKEY A-update-1.pb A-update-2.pb > A-close.pb
$PREFIX ./close-channel --complete B-open.pb A-open.pb B-anchor-id.pb A-anchor-id.pb $B_TMPKEY A-update-1.pb A-update-2.pb > B-close-complete.pb
$PREFIX ./create-close-tx A-open.pb B-open.pb A-anchor-id.pb B-anchor-id.pb A-close.pb B-close-complete.pb A-update-1.pb A-update-2.pb > A-close.tx

$CLI sendrawtransaction `cut -d: -f1 A-close.tx` > close.txid
