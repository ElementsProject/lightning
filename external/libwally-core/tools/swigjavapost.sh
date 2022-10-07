#! /usr/bin/env bash

sed_exe=$1
elements=$2

result="swig_java/src/com/blockstream/libwally/Wally.java"

mkdir -p `dirname $result`

# Merge the constants and JNI interface into Wally.java
grep -v '^}$' swig_java/wallycoreJNI.java | $sed_exe 's/wallycoreJNI/Wally/g' >$result
grep 'public final static' swig_java/wallycoreConstants.java >>$result
# Append our extra functionality
cat swig_java/jni_extra.java_in >>$result
if [ -n "$elements" ]; then
    # Include elements functionality wrappers in the generated result
    cat swig_java/jni_elements_extra.java_in >>$result
fi
echo "}" >>$result
# Clean up
rm -f swig_java/*.java
