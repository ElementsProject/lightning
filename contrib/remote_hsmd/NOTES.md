c-lightning
----------------------------------------------------------------

Setup

    cd contrib/remote_hsmd && \
    ln -s /path/to/rust-lightning-signer/src/server/remotesigner.proto

Building

    ./configure --enable-developer
    make

Run all of the integration tests:
```
SUBDAEMON='hsmd:remote_hsmd' \
make \
PYTEST_PAR=1 \
DEVELOPER=1 \
VALGRIND=0 \
pytest \
|& tee log
```

Single test, excercises funding transaction:
```
PYTHONPATH=`pwd`/hsmd:`pwd`/contrib/pylightning:`pwd`/contrib/pyln-testing:`pwd`/contrib/pyln-client:$PYTHONPATH \
TEST_DEBUG=1 \
DEVELOPER=1 \
VALGRIND=0 \
SLOW_MACHINE=1 \
SUBDAEMON='hsmd:remote_hsmd' \
pytest \
$THETEST \
-v --timeout=550 --timeout_method=thread -x -s \
|& tee log
```

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

rust-lightning-signer
----------------------------------------------------------------

    cargo run --bin server |& tee log3
