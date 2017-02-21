LIBSECP256K1=secp256k1/libsecp256k1.la

$(LIBSECP256K1): $(wildcard secp256k1/src/*) $(wildcard secp256k1/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)

noinst_LTLIBRARIES =

if USE_SWIG_PYTHON
noinst_LTLIBRARIES += libswig_python.la
libswig_python_la_SOURCES = swig_python/swig_python_wrap.c

libswig_python_la_CFLAGS = -I$(top_srcdir) $(AM_CFLAGS) $(SWIG_PYTHON_CPPFLAGS) $(SWIG_WARN_CFLAGS) $(NOALIAS_CFLAGS)
libswig_python_la_LIBADD = $(PYTHON_LIBS)

# We must sed the wrapper to workaround SWIGs odd library naming conventions
swig_python/swig_python_wrap.c : swig_python/swig.i swig_python/python_extra.py_in
	$(AM_V_at)$(SWIG) $(SWIG_PYTHON_OPT) -outdir swig_python -o $@ $< && \
    $(GNU_SED) -i 's/_wallycore/libwallycore/g' swig_python/wallycore.py $@ && \
    cat swig_python/wallycore.py swig_python/python_extra.py_in > swig_python/wallycore/__init__.py && \
    rm swig_python/wallycore.py

PYTHON_TEST = PYTHONDONTWRITEBYTECODE=1 $(PYTHON)
PYTHON_SWIGTEST = PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=.libs:swig_python $(PYTHON)

.PHONY: clean-swig-python
clean-swig-python:
	$(AM_V_at)rm -f swig_python/swig_python_wrap.c swig_python/wallycore/__init__.py
clean-local: clean-swig-python

if IS_OSX
# Python requires the shared library have a .so extension for 'import'
.libs/libwallycore.so:
	$(AM_V_at)ln -s libwallycore.dylib .libs/libwallycore.so
SWIG_PYTHON_TEST_DEPS = .libs/libwallycore.so
endif

endif

if USE_SWIG_JAVA
noinst_LTLIBRARIES += libswig_java.la
libswig_java_la_SOURCES = \
    swig_java/swig_java_wrap.c

libswig_java_la_CFLAGS = -I$(top_srcdir) $(AM_CFLAGS) $(SWIG_JAVA_CPPFLAGS) $(SWIG_WARN_CFLAGS)

SWIG_JOPT = $(SWIG_JAVA_OPT) -outdir swig_java -noproxy -package com.blockstream.libwally

swig_java/swig_java_wrap.c: swig_java/swig.i swig_java/jni_extra.java_in
	$(AM_V_at)$(SWIG) $(SWIG_JOPT) -o $@ $< && \
    $(GNU_SED) -i 's/wallycoreJNI/Wally/g' $@ && \
    $(GNU_SED) -i 's/ = (char \*) (\*jenv)->Get/ = (unsigned char \*) (\*jenv)->Get/g' $@

cblw=com/blockstream/libwally
cbt=com/blockstream/test
sjs=swig_java/src
$(sjs)/$(cblw)/Wally.java: swig_java/swig_java_wrap.c
	$(AM_V_at)$(top_srcdir)/tools/swigjavapost.sh @GNU_SED@

$(sjs)/$(cblw)/Wally.class: $(sjs)/$(cblw)/Wally.java
	$(AM_V_at)$(JAVAC) -implicit:none -source $(JAVAC_TARGET) -target $(JAVAC_TARGET) -sourcepath $(sjs)/$(cblw)/ $(sjs)/$(cblw)/Wally.java

swig_java/wallycore.jar: $(sjs)/$(cblw)/Wally.class
	$(AM_V_at)$(JAR) cf swig_java/wallycore.jar -C $(sjs) '$(cblw)/Wally$$Obj.class' -C $(sjs) '$(cblw)/Wally.class'

$(sjs)/$(cbt)/%.class: $(sjs)/$(cbt)/%.java swig_java/wallycore.jar
	$(AM_V_at)$(JAVAC) -implicit:none -source $(JAVAC_TARGET) -target $(JAVAC_TARGET) -sourcepath $(sjs) $(filter %.java,$^)

if HAVE_JAVAC
all: swig_java/wallycore.jar

SWIG_JAVA_TEST_DEPS = $(sjs)/$(cbt)/test_bip32.class $(sjs)/$(cbt)/test_mnemonic.class

all: $(SWIG_JAVA_TEST_DEPS)

JAVA_TEST = @LDPATH_VAR@=.libs $(JAVA) -Djava.library.path=.libs -classpath $(sjs) com.blockstream.test.

endif # HAVE_JAVAC

.PHONY: clean-swig-java
clean-swig-java:
	$(AM_V_at)rm -rf swig_java/swig_java_wrap.c $(sjs)/$(cblw) $(sjs)/$(cbt)/*.class swig_java/*.java swig_java/*.jar
clean-local: clean-swig-java
endif # USE_SWIG_JAVA

lib_LTLIBRARIES = libwallycore.la

libwallycore_la_SOURCES = \
    aes.c \
    base58.c \
    bip32.c \
    bip38.c \
    bip39.c \
    hex.c \
    hmac.c \
    internal.c \
    mnemonic.c \
    pbkdf2.c \
    scrypt.c \
    sign.c \
    wordlist.c \
    ccan/ccan/crypto/ripemd160/ripemd160.c \
    ccan/ccan/crypto/sha256/sha256.c \
    ccan/ccan/crypto/sha512/sha512.c \
    ccan/ccan/str/hex/hex.c

libwallycore_la_INCLUDES = \
    include/wally_bip32.h \
    include/wally_bip38.h \
    include/wally_bip39.h \
    include/wally_core.h \
    include/wally-crypto.h

libwallycore_la_CFLAGS = -I$(top_srcdir) -Iccan -DWALLY_CORE_BUILD=1 $(AM_CFLAGS)
libwallycore_la_LIBADD = $(LIBADD_SECP256K1) $(noinst_LTLIBRARIES)

SUBDIRS = secp256k1

TESTS =
if USE_PTHREAD
TESTS += test_clear
noinst_PROGRAMS = test_clear
test_clear_SOURCES = ctest/test_clear.c
test_clear_CFLAGS = -I$(top_srcdir)/include $(PTHREAD_CFLAGS) $(AM_CFLAGS)
test_clear_LIBS = $(PTHREAD_LIBS)
test_clear_LDADD = $(lib_LTLIBRARIES) $(libwallycore_la_LIBADD)
endif

check-local: $(SWIG_PYTHON_TEST_DEPS) $(SWIG_JAVA_TEST_DEPS)
if RUN_PYTHON_TESTS
	$(AM_V_at)$(PYTHON_TEST) test/test_aes.py
	$(AM_V_at)$(PYTHON_TEST) test/test_base58.py
	$(AM_V_at)$(PYTHON_TEST) test/test_bip32.py
	$(AM_V_at)$(PYTHON_TEST) test/test_bip38.py
	$(AM_V_at)$(PYTHON_TEST) test/test_bip39.py
	$(AM_V_at)$(PYTHON_TEST) test/test_hash.py
	$(AM_V_at)$(PYTHON_TEST) test/test_hex.py
	$(AM_V_at)$(PYTHON_TEST) test/test_hmac.py
	$(AM_V_at)$(PYTHON_TEST) test/test_mnemonic.py
	$(AM_V_at)$(PYTHON_TEST) test/test_pbkdf2.py
	$(AM_V_at)$(PYTHON_TEST) test/test_scrypt.py
	$(AM_V_at)$(PYTHON_TEST) test/test_sign.py
	$(AM_V_at)$(PYTHON_TEST) test/test_wordlist.py
if USE_SWIG_PYTHON
	$(AM_V_at)$(PYTHON_SWIGTEST) swig_python/contrib/mnemonic.py
endif
endif # RUN_PYTHON_TESTS
if RUN_JAVA_TESTS
	$(AM_V_at)$(JAVA_TEST)test_bip32
	$(AM_V_at)$(JAVA_TEST)test_mnemonic
endif
