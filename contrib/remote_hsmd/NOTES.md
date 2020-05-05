c-lightning
----------------------------------------------------------------

Setup

    cd contrib/remote_hsmd && \
    ln -s /path/to/rust-lightning-signer/src/server/remotesigner.proto

Building

    ./configure --enable-developer
    make

Dependencies

Build libsecp256k1 with `./configure --enable-module-recovery`, see
https://github.com/golemfactory/golem/issues/2168 for background.

    pip3 install --user base58
    pip3 install --user bitstring
    pip3 install --user secp256k1

Run all of the integration tests:

    ./contrib/remote_hsmd/scripts/run-all-tests |& tee log
    
Run a single test:

    ./contrib/remote_hsmd/scripts/run-one-test $THETEST |& tee log

Some popular tests:

    # sign-invoice, handle-sign-remote-htlc-tx
    export THETEST=tests/test_connection.py::test_balance
    export THETEST=tests/test_pay.py::test_sendpay
    export THETEST=tests/test_pay.py::test_pay

    # sign-local-htlc-tx
    export THETEST=tests/test_closing.py::test_onchain_different_fees

    # sign-remote-htlc-to-us
    export THETEST=tests/test_closing.py::test_onchain_feechange
    export THETEST=tests/test_closing.py::test_onchain_all_dust
    export THETEST=tests/test_closing.py::test_permfail_new_commit

    # sign-delayed-payment-to-us
    export THETEST=tests/test_closing.py::test_onchain_multihtlc_our_unilateral
    export THETEST=tests/test_closing.py::test_onchain_multihtlc_their_unilateral
    export THETEST=tests/test_closing.py::test_permfail_htlc_in
    export THETEST=tests/test_closing.py::test_permfail_htlc_out

    # sign-penalty-to-us
    export THETEST=tests/test_closing.py::test_penalty_inhtlc
    export THETEST=tests/test_closing.py::test_penalty_outhtlc
    export THETEST=tests/test_closing.py::test_closing

    # sign-mutual-close
    export THETEST=tests/test_closing.py::test_closing
    
    # check-future-secret
    export THETEST=tests/test_connection.py::test_dataloss_protection
    
    # sign-message
    export THETEST=tests/test_misc.py::test_signmessage

    # sign-channel-announcement
    export THETEST=tests/test_closing.py::test_closing_different_fees

    # P2SH_P2WPKH
    export THETEST=tests/test_closing.py::test_onchain_first_commit 
    export THETEST=tests/test_connection.py::test_disconnect_funder 
    export THETEST=tests/test_connection.py::test_disconnect_fundee 
    export THETEST=tests/test_connection.py::test_reconnect_signed 
    export THETEST=tests/test_connection.py::test_reconnect_openingd 
    export THETEST=tests/test_connection.py::test_shutdown_awaiting_lockin
    
    # unilateral_close_info option_static_remotekey
    export THETEST=tests/test_connection.py::test_fee_limits
    export THETEST=tests/test_closing.py::test_option_upfront_shutdown_script

rust-lightning-signer
----------------------------------------------------------------

    cargo run --bin server |& tee log3


Signing Formats
```
rust-lightning  c-lightning     rust-lightning-signer
p2pkh                           P2PKH
p2sh
p2wpkh          p2wpkh          P2WPKH
p2shwpkh        p2sh-p2wpkh     P2SH_P2WPKH
p2wsh
p2shwsh
```


Failing tests after removing seed from hsmd:
```
    export THETEST=tests/test_misc.py::test_blockchaintrack
    export THETEST=tests/test_misc.py::test_new_node_is_mainnet
    export THETEST=tests/test_misc.py::test_getsharedsecret
    export THETEST=tests/test_wallet.py::test_hsm_secret_encryption
    export THETEST=tests/test_wallet.py::test_hsmtool_secret_decryption
```
