#!/bin/sh

# Clean up all generated files
make -o configure distclean >/dev/null 2>&1

find . -name Makefile -exec rm {} \;
find . -name Makefile.in -exec rm {} \;
find . -name "*.class" -exec rm {} \;
find . -name "*.gcno" -exec rm {} \;
find . -name "*.gcda" -exec rm {} \;
find . -name "*.egg-info" -exec rm -rf {} 2>/dev/null \;

rm -f */*~
rm -f *~
rm -f aclocal.m4
rm -rf build/
rm -f config.h.in
rm -f configure
rm -rf dist/
rm -f src/*pyc
rm -f src/test/*pyc
rm -f src/config.h.in
rm -rf src/lcov*
rm -f src/test_clear*
rm -f src/test-suite.log
rm -f src/swig_java/swig_java_wrap.c
rm -f src/swig_java/*java
rm -f src/swig_java/*jar
rm -rf src/swig_java/src/com/blockstream/libwally
rm -f src/swig_python/wallycore.py
rm -f src/swig_python/wallycore/__init__.py
rm -f src/swig_python/swig_python_wrap.c
rm -rf src/.libs
rm -f tools/build-aux/compile
rm -f tools/build-aux/config.guess
rm -f tools/build-aux/config.sub
rm -f tools/build-aux/depcomp
rm -f tools/build-aux/install-sh
rm -f tools/build-aux/ltmain.sh
rm -f tools/build-aux/missing
rm -f tools/build-aux/m4/l*.m4
rm -f tools/build-aux/test-driver
rm -rf autom4te.cache/
rm -rf .venv
exit 0
