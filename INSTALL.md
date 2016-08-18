Library Requirements
--------------------

You will need several development libraries:
* libprotoc: the Google protocol buffer v2 library, 2.6.0 or above.
* protobuf-c: version 1.1.0 or above.
* libsodium: for crypto.
* libbase58: for bitcoin's base58 encoding.
* libsqlite3: for database support.

You will also need a version of bitcoind with segregated witness support,
such as the 0.13 or above.

To Build on Ubuntu 16.04
---------------------

Get dependencies:
```
sudo apt-get install libprotobuf-c-dev libsodium-dev libbase58-dev libsqlite3-dev
```

Clone lightning and initialize submodules:
```
git clone https://github.com/ElementsProject/lightning.git
cd lightning
git submodule init
git submodule update
```

Build lightning:
```
make
```

Running lightning:
```
bitcoind
./daemon/lightningd
./daemon/lightning-cli help
```
**Note**: You may need to include `testnet=1` in `bitcoin.conf`

To Build on Ubuntu 15.10
------------------------
Build protobuf-c dependency (>= 1.1.0):
```
sudo apt-get install libprotoc-dev
git clone https://github.com/protobuf-c/protobuf-c.git
cd protobuf-c
./autogen.sh
./configure
make
make install
cd ../
```

Clone lightning and initialize submodules:
```
git clone https://github.com/ElementsProject/lightning.git
cd lighting
git submodule init
git submodule update
```

Build lightning:
```
make
```

Running lightning:
```
bitcoind
export LD_LIBRARY_PATH=/usr/local/lib
./daemon/lightningd
./daemon/lightning-cli help
```
