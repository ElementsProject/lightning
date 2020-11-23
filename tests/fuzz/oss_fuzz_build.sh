#!/bin/bash -eu
export FUZZING_CFLAGS=$CFLAGS
FUZZING=1 OSS_FUZZ=1 CC="${CC}" ./configure && make
mv $SRC/lightning/tests/fuzz/* $OUT/
