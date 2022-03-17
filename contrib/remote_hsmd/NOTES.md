c-lightning
----------------------------------------------------------------

Basic Setup:

1. Follow instructions in [`doc/INSTALL.md`](../../doc/INSTALL.md)
2. Follow instructions in the "Build and Development" section in [`doc/HACKING.md`](../../doc/HACKING.md)
3. Make sure you have cloned this repository

On Ubuntu:

    sudo apt-get install -y libgrpc-dev libgrpc++-dev protobuf-compiler-grpc

On Fedora:

    sudo dnf install -y grpc-devel grpc-plugins

Validating Lightning Signer:

    # In parent directory of c-lightning root
    git clone git@gitlab.com:lightning-signer/validating-lightning-signer.git
    cargo build

C-Lightning:

    # Standing in c-lightning root, add an "upstream" reference and fetch all tags (needed for pyln-{proto,client,testing})
    # Use the HTTPS pointer if you have authentication issues with git
    git remote add upstream git@github.com:ElementsProject/lightning.git
    git fetch upstream --tags

    (cd contrib/remote_hsmd && \
    ln -s ../../../validating-lightning-signer/lightning-signer-server/src/server/remotesigner.proto)
    # Then make sure the link is valid
    if [ -f contrib/remote_hsmd/remotesigner.proto ]; then echo "Symbolic link successful"; else echo "Symbolic link failed"; fi

    # Build c-lightning
    make distclean
    ./configure --enable-developer
    make

Tests:
    
    # Run this single test to check that everything is set up correctly:
    ./contrib/remote_hsmd/scripts/run-one-test tests/test_pay.py::test_pay_no_secret

Run all of the integration tests:

    ./contrib/remote_hsmd/scripts/run-all-tests |& tee log
    
Run a single test:

    ./contrib/remote_hsmd/scripts/run-one-test $THETEST |& tee log
    
Re-run failures from prior run:

    ./contrib/remote_hsmd/scripts/rerun-failed-tests < log |& tee log2
    
To run tests using anchors, rebuild w/ experimental features:

    make distclean
    ./configure --enable-developer --enable-experimental-features
    make

    ./contrib/remote_hsmd/scripts/run-all-tests |& tee log

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

validating-lightning-signer
----------------------------------------------------------------

    cargo run --bin server -- --no-persist --test-mode |& tee log3
