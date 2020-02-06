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
tests/test_connection.py::test_balance \
-v --timeout=550 --timeout_method=thread -x -s \
|& tee log
```

Tests remote_commitment:

    tests/test_pay.py::test_sendpay

rust-lightning-signer
----------------------------------------------------------------

    cargo run --bin server |& tee log3
