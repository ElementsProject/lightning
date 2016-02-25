Build on Ubuntu 15.10
---------------------

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
export LD_LIBRARY_PATH=/usr/local/lib
./daemon/lightningd
```
