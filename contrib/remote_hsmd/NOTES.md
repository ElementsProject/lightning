

Run all of the integration tests:
```
SUBDAEMON='hsmd:remote_hsmd' \
make \
DEVELOPER=1 \
VALGRIND=0 \
pytest \
|& tee log
```

Run a single integration test:
```
PYTHONPATH=`pwd`/hsmd:`pwd`/contrib/pylightning:`pwd`/contrib/pyln-testing:`pwd`/contrib/pyln-client:$PYTHONPATH \
TEST_DEBUG=1 \
DEVELOPER=1 \
VALGRIND=0 \
SLOW_MACHINE=1 \
SUBDAEMON='hsmd:remote_hsmd' \
pytest \
tests/test_gossip.py::test_gossip_notices_close \
-v --timeout=550 --timeout_method=thread -x -s \
|& tee log
```

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

rust-lightning-signer
----------------------------------------------------------------

    cargo run --bin server
