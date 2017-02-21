#!/bin/sh

ENABLE_SWIG_PYTHON="--enable-swig-python"
ENABLE_SWIG_JAVA="--enable-swig-java"

if [ -n "$HOST" ]; then
   USE_HOST="--host=$HOST"
   if [ "$HOST" = "i686-linux-gnu" ]; then
       export CC="$CC -m32"
       ENABLE_SWIG_PYTHON=""
       # We only disable Java because the 64 bit jvm won't run the
       # tests given a 32 bit libwally.so. It compiles fine.
       export ENABLE_SWIG_JAVA=""
   fi
fi

./configure --disable-dependency-tracking --enable-export-all $ENABLE_SWIG_PYTHON $ENABLE_SWIG_JAVA $USE_HOST && make && make check

