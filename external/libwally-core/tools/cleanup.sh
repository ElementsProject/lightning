#! /usr/bin/env bash

# Clean up all generated files
make -o configure distclean >/dev/null 2>&1

find src -name Makefile -exec rm {} \;
find src -name Makefile.in -exec rm {} \;
find . -name "*.class" -exec rm {} \;
find . -name "*.gcno" -exec rm {} \;
find . -name "*.gcda" -exec rm {} \;
find . -name "*.egg-info" -exec rm -rf {} 2>/dev/null \;
find . -name "__pycache__" -exec rm -rf {} 2>/dev/null \;

rm -f */*~
rm -f *~
rm -f aclocal.m4
rm -rf build/
rm -f config.h.in
rm -f configure
rm -rf dist/
rm -rf src/wallycore.pc
rm -f src/*pyc
rm -f src/test/*pyc
rm -f src/config.h.in
rm -rf src/lcov*
rm -f src/test_bech32*
rm -f src/test_clear*
rm -f src/test_tx*
rm -f src/test-suite.log
rm -f src/swig_java/swig_java_wrap.c
rm -f src/swig_java/*java
rm -f src/swig_java/*jar
rm -rf src/swig_java/src/com/blockstream/libwally
rm -f src/swig_python/wallycore.py
rm -f src/swig_python/wallycore/__init__.py*
rm -f src/swig_python/swig_python_wrap.c
rm -f src/wrap_js/binding.gyp
rm -rf src/wrap_js/build
rm -rf src/wrap_js/node_modules/
rm -f src/wrap_js/nodejs_wrap.cc
rm -f src/wrap_js/WallyCordova.java
rm -f src/wrap_js/WallyCordova.swift
rm -f src/wrap_js/cordovaplugin/Wally.java
rm -f src/wrap_js/cordovaplugin/WallyCordova.java
rm -f src/wrap_js/cordovaplugin/WallyCordova.swift
rm -rf src/wrap_js/cordovaplugin/jniLibs/
rm -f src/wrap_js/wally.js
rm -rf src/.libs
rm -f src/secp256k1/build-aux/ltmain.sh-e
rm -f tools/build-aux/ar-lib
rm -f tools/build-aux/compile
rm -f tools/build-aux/config.guess
rm -f tools/build-aux/config.sub
rm -f tools/build-aux/depcomp
rm -f tools/build-aux/install-sh
rm -f tools/build-aux/ltmain.sh
rm -f tools/build-aux/ltmain.sh-e
rm -f tools/build-aux/missing
rm -f tools/build-aux/m4/l*.m4
rm -f tools/build-aux/test-driver
rm -rf autom4te.cache/ src/secp256k1/autom4te.cache
rm -rf docs/build docs/source/address.rst docs/source/anti_exfil.rst docs/source/bip32.rst docs/source/bip38.rst docs/source/bip39.rst docs/source/core.rst docs/source/crypto.rst docs/source/elements.rst docs/source/psbt.rst docs/source/script.rst docs/source/symmetric.rst docs/source/transaction.rst
rm -rf .venv
exit 0
