#!/bin/sh

sed_exe=$1

result="swig_java/src/com/blockstream/libwally/Wally.java"

mkdir -p `dirname $result`

# Merge the constants and JNI interface into Wally.java
grep -v '^}$' swig_java/wallycoreJNI.java | $sed_exe 's/wallycoreJNI/Wally/g' >$result
grep 'public final static' swig_java/wallycoreConstants.java >>$result
# Append our extra functionality
cat swig_java/jni_extra.java_in >>$result

# Clean up
rm -f swig_java/*.java
