Library Requirements
--------------------

You will need several development libraries:
* libprotoc: the Google protocol buffer v2 library, 2.6.0 or above.
* protobuf-c: version 1.1.0 or above.
* libsqlite3: for database support.
* libgmp: for secp256k1
* asciidoc: for formatting the man page (if you change them)

You will also need a version of bitcoind with segregated witness support,
such as the 0.13 or above.

To Build on Ubuntu 16.04
---------------------

Get dependencies:
```
sudo apt-get install autoconf libtool libprotobuf-c-dev libsqlite3-dev libgmp-dev libsqlite3-dev asciidoc
```

Clone lightning:
```
git clone https://github.com/ElementsProject/lightning.git
cd lightning
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

Clone lightning:
```
git clone https://github.com/ElementsProject/lightning.git
cd lighting
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
