#! /bin/sh

set -e

BITCOIN="bitcoin-cli -regtest"
getpubkey()
{
    $BITCOIN validateaddress $1 | sed -n 's/.*"pubkey" : "\([0-9a-f]*\)".*/\1/p'
}

getprivkey()
{
    $BITCOIN dumpprivkey $1
}

A_INPUTNUM=4
B_INPUTNUM=74
#A_INPUTNUM=4
#B_INPUTNUM=1
A_AMOUNT=100000000
B_AMOUNT=9795000

A_CHANGEADDR=`$BITCOIN getnewaddress`
A_TMPADDR=`$BITCOIN getnewaddress`
A_FINALADDR=`$BITCOIN getnewaddress`

B_CHANGEADDR=`$BITCOIN getnewaddress`
B_TMPADDR=`$BITCOIN getnewaddress`
B_FINALADDR=`$BITCOIN getnewaddress`

#A_CHANGEADDR=mzJseRSpUnmUDRJkp9Jp3XRmLKRrFk8KEF
#A_TMPADDR=mxAucVQU1WWRcMd9ubx1gisteFuy5MgSVh
#A_FINALADDR=mgjMAVHe8Kgx38SY3apjHdLwz2deJ2ZY2H

#B_CHANGEADDR=mmCiKXHPWunBMFhqZx7fg1v23HssJJesLV
#B_TMPADDR=mvY4WDonPXq3Xa3NL4uSG26PXKRuLsXGTT
#B_FINALADDR=mvQgfEX4iMSEYqD31524jASQviPwPwpvuv

A_TXIN=`./getinput.sh $A_INPUTNUM`
A_TXINKEY=`./getinput.sh --privkey $A_INPUTNUM`
B_TXIN=`./getinput.sh $B_INPUTNUM`
B_TXINKEY=`./getinput.sh --privkey $B_INPUTNUM`

A_SEED=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
B_SEED=112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00

A_CHANGEPUBKEY=`getpubkey $A_CHANGEADDR`
A_TMPKEY=`getprivkey $A_TMPADDR`
A_FINALKEY=`getprivkey $A_FINALADDR`

B_CHANGEPUBKEY=`getpubkey $B_CHANGEADDR`
B_TMPKEY=`getprivkey $B_TMPADDR`
B_FINALKEY=`getprivkey $B_FINALADDR`

# Both sides say what they want from channel
./open-channel $A_SEED $A_AMOUNT $A_CHANGEPUBKEY $A_TMPKEY $A_FINALKEY $A_TXIN > A-open.pb
./open-channel $B_SEED $B_AMOUNT $B_CHANGEPUBKEY $B_TMPKEY $B_FINALKEY $B_TXIN > B-open.pb

# Now sign anchor.
./open-anchor-scriptsigs A-open.pb B-open.pb $A_TXINKEY > A-anchor-scriptsigs.pb
./open-anchor-scriptsigs B-open.pb A-open.pb $B_TXINKEY > B-anchor-scriptsigs.pb

# Now leak that signature.
./leak-anchor-sigs A-anchor-scriptsigs.pb > A-leak-anchor-sigs.pb
./leak-anchor-sigs B-anchor-scriptsigs.pb > B-leak-anchor-sigs.pb

# Now create commit signature
./open-commit-sig A-open.pb B-open.pb $A_TMPKEY A-leak-anchor-sigs.pb B-leak-anchor-sigs.pb > A-commit-sig.pb

./open-commit-sig B-open.pb A-open.pb $B_TMPKEY B-leak-anchor-sigs.pb A-leak-anchor-sigs.pb > B-commit-sig.pb

# Now check it.
./check-commit-sig A-open.pb B-open.pb B-commit-sig.pb $A_TMPKEY A-leak-anchor-sigs.pb B-leak-anchor-sigs.pb > A-commit.tx
./check-commit-sig B-open.pb A-open.pb A-commit-sig.pb $B_TMPKEY B-leak-anchor-sigs.pb A-leak-anchor-sigs.pb > B-commit.tx

# Now check anchor sigs and make sure they're the same.
./check-anchor-scriptsigs A-open.pb B-open.pb A-anchor-scriptsigs.pb B-anchor-scriptsigs.pb > A-anchor.tx
./check-anchor-scriptsigs B-open.pb A-open.pb B-anchor-scriptsigs.pb A-anchor-scriptsigs.pb > B-anchor.tx
cmp A-anchor.tx B-anchor.tx

# Broadcast
$BITCOIN sendrawtransaction `cat A-anchor.tx` > anchor.txid

# # Wait for confirms
# while [ 0$($BITCOIN getrawtransaction $(cat anchor.txid) 1 | sed -n 's/.*"confirmations" : \([0-9]*\),/\1/p') -lt $(./get-anchor-depth A-open.pb) ]; do $BITCOIN generate 1; done

# while [ 0$($BITCOIN getrawtransaction $(cat anchor.txid) 1 | sed -n 's/.*"confirmations" : \([0-9]*\),/\1/p') -lt $(./get-anchor-depth B-open.pb) ]; do $BITCOIN generate 1; done

# Just for testing, generate the first transaction.
./create-commit-tx A-anchor.tx A-open.pb B-open.pb $A_TMPKEY B-commit-sig.pb > A-commit-0.tx

# Now, update the channel, so I pay you 500 satoshi.
./update-channel --to-them=500 $A_SEED > A-update-1.pb
./update-channel-accept $B_SEED B-anchor.tx B-open.pb A-open.pb $B_TMPKEY A-update-1.pb > B-update-accept-1.pb
./update-channel-signature $A_SEED A-anchor.tx A-open.pb B-open.pb $A_TMPKEY A-update-1.pb B-update-accept-1.pb > A-update-sig-1.pb
./update-channel-complete $B_SEED B-anchor.tx B-open.pb A-open.pb A-update-1.pb A-update-sig-1.pb > B-update-complete-1.pb

# Just for testing, generate second transaction
./create-commit-tx A-anchor.tx A-open.pb B-open.pb $A_TMPKEY B-update-accept-1.pb A-update-1.pb > A-commit-1.tx

# Now you pay me 1000.
./update-channel --from-them=1000 $A_SEED A-update-1.pb > A-update-2.pb
./update-channel-accept $B_SEED B-anchor.tx B-open.pb A-open.pb $B_TMPKEY A-update-2.pb A-update-1.pb > B-update-accept-2.pb 2>/dev/null
./update-channel-signature $A_SEED A-anchor.tx A-open.pb B-open.pb $A_TMPKEY A-update-2.pb B-update-accept-2.pb A-update-1.pb > A-update-sig-2.pb
./update-channel-complete $B_SEED B-anchor.tx B-open.pb A-open.pb A-update-2.pb A-update-sig-2.pb A-update-1.pb > B-update-complete-2.pb

# Just for testing, generate third transaction
./create-commit-tx A-anchor.tx A-open.pb B-open.pb $A_TMPKEY B-update-accept-2.pb A-update-1.pb A-update-2.pb > A-commit-2.tx

if [ x"$1" = x--steal ]; then
    # A stupidly broadcasts a revoked transaction.
    $BITCOIN sendrawtransaction `cat A-commit-1.tx` > A-commit-1.txid
    
    # B uses the preimage from A-update-sig-2 to cash in.
    ./create-steal-tx A-commit-1.tx A-update-sig-2.pb $B_FINALKEY B-open.pb A-open.pb $B_CHANGEPUBKEY > B-commit-steal.tx

    $BITCOIN sendrawtransaction `cat B-commit-steal.tx` > B-commit-steal.txid
    exit 0
fi

if [ x"$1" = x--unilateral ]; then
    $BITCOIN sendrawtransaction `cat A-commit-2.tx` > A-commit-2.txid
    # Normally we'd have to wait before redeeming, but OP_CHECKSEQUENCEVERIFY
    # is a noop.
    ./create-commit-spend-tx A-commit-2.tx A-open.pb B-open.pb $A_FINALKEY $A_CHANGEPUBKEY A-update-1.pb A-update-2.pb > A-spend.tx
    $BITCOIN sendrawtransaction `cat A-spend.tx` > A-spend.txid
    exit 0
fi

# Now close channel by mutual consent.
./close-channel A-anchor.tx A-open.pb B-open.pb $A_TMPKEY A-update-1.pb A-update-2.pb > A-close.pb
./close-channel --complete B-anchor.tx B-open.pb A-open.pb $B_TMPKEY A-update-1.pb A-update-2.pb > B-close-complete.pb
./create-close-tx A-anchor.tx A-open.pb B-open.pb A-close.pb B-close-complete.pb A-update-1.pb A-update-2.pb > A-close.tx

$BITCOIN sendrawtransaction `cat A-close.tx` > close.txid
