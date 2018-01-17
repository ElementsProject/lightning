Library Requirements
--------------------

You will need several development libraries:
* libsqlite3: for database support.
* libgmp: for secp256k1

For actually doing development and running the tests, you will also need:
* pip3: to install python-bitcoinlib
* asciidoc: for formatting the man pages (if you change them)
* valgrind: for extra debugging checks

You will also need a version of bitcoind with segregated witness and estimatesmartfee economical node, such as the 0.15 or above.

To Build on Ubuntu 15.10 or above
---------------------

Get dependencies:
```
sudo apt-get install -y autoconf automake build-essential git libtool libgmp-dev libsqlite3-dev python3 net-tools
```

If you don't have Bitcoin installed locally you'll need to install that as well:
```
sudo apt-get install software-properties-common
sudo add-apt-repository ppa:bitcoin/bitcoin
sudo apt-get update
sudo apt-get install -y bitcoind
```

For development or running tests, get additional dependencies:
```
sudo apt-get install -y asciidoc valgrind python3-pip
sudo pip3 install python-bitcoinlib
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
bitcoind &
./lightningd/lightningd &
./cli/lightning-cli help
```
**Note**: You may need to include `testnet=1` in `bitcoin.conf`

