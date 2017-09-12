LIBSODIUM_HEADERS := external/libsodium/src/libsodium/include/sodium.h
LIBWALLY_HEADERS := external/libwally-core/include/wally_bip32.h		\
			external/libwally-core/include/wally_core.h	\
			external/libwally-core/include/wally_crypto.h
LIBSECP_HEADERS := external/libwally-core/src/secp256k1/include/secp256k1_ecdh.h		\
		external/libwally-core/src/secp256k1/include/secp256k1.h
JSMN_HEADERS := external/jsmn/jsmn.h
LIBBASE58_HEADERS := external/libbase58/libbase58.h

EXTERNAL_HEADERS := $(LIBSODIUM_HEADERS) $(LIBWALLY_HEADERS) $(LIBSECP_HEADERS) $(JSMN_HEADERS) $(LIBBASE58_HEADERS)
EXTERNAL_LIBS := external/libwallycore.a external/libsecp256k1.a external/libsodium.a external/libjsmn.a external/libbase58.a external/libbacktrace.a

EXTERNAL_INCLUDE_FLAGS :=					\
	-I external/libsodium/src/libsodium/include		\
	-I external/libwally-core/include/			\
	-I external/libwally-core/src/secp256k1/include/	\
	-I external/jsmn/					\
	-I external/libbase58/					\
	-I external/libbacktrace

EXTERNAL_LDLIBS := -Lexternal $(patsubst lib%.a,-l%,$(notdir $(EXTERNAL_LIBS)))

# We build libsodium, since Ubuntu xenial has one too old.
external/libsodium.a: external/libsodium/src/libsodium/libsodium.la
	$(MAKE) -C external/libsodium install-exec

external/libsodium/src/libsodium/include/sodium.h:
	git submodule update external/libsodium
	[ -f $@ ] || git submodule update --init external/libsodium

external/libsodium/src/libsodium/libsodium.la: external/libsodium/src/libsodium/include/sodium.h
	cd external/libsodium && ./autogen.sh && ./configure CC="$(CC)" --enable-static=yes --enable-shared=no --enable-tests=no --libdir=`pwd`/.. && $(MAKE)

# libsecp included in libwally.
# Wildcards here are magic.  See http://stackoverflow.com/questions/2973445/gnu-makefile-rule-generating-a-few-targets-from-a-single-source-file
external/libsecp256k1.% external/libwallycore.%: external/libwally-core/src/secp256k1/libsecp256k1.la external/libwally-core/src/libwallycore.la
	$(MAKE) -C external/libwally-core install-exec

external/libwally-core/src/libwallycore.% external/libwally-core/src/secp256k1/libsecp256k1.%: $(LIBWALLY_HEADERS) $(LIBSECP_HEADERS)
	cd external/libwally-core && ./tools/autogen.sh && ./configure CC="$(CC)" --enable-static=yes --enable-shared=no --libdir=`pwd`/.. && $(MAKE)

# Git submodules are seriously broken.
external/jsmn/jsmn.h:
	git submodule update external/jsmn/
	[ -f $@ ] || git submodule update --init external/jsmn/

# If we tell Make that the above builds both, it runs it twice in
# parallel.  So we lie :(
external/jsmn/jsmn.c: external/jsmn/jsmn.h
	[ -f $@ ]

external/jsmn.o: external/jsmn/jsmn.c
	$(COMPILE.c) -DJSMN_STRICT=1 $(OUTPUT_OPTION) $<

external/libjsmn.a: external/jsmn.o
	$(AR) rc $@ $<

LIBBASE58_SRC := external/libbase58/base58.c

$(LIBBASE58_SRC): $(LIBBASE58_HEADERS)

$(LIBBASE58_HEADERS):
	git submodule update external/libbase58/ || true
	[ -f $@ ] || git submodule update --init external/libbase58/

# Can't be inside submodule, as that makes git think it's dirty.
external/base58.o: $(LIBBASE58_SRC)
	$(COMPILE.c) $(OUTPUT_OPTION) $<

external/libbase58.a: external/base58.o
	$(AR) rc $@ $<

external/libbacktrace/backtrace.h:
	git submodule update external/libbacktrace/
	[ -f $@ ] || git submodule update --init external/libbacktrace/

# Need separate build dir: changes inside submodule make git think it's dirty.
external/libbacktrace.a: external/libbacktrace/backtrace.h
	@mkdir external/libbacktrace-build 2>/dev/null || true
	cd external/libbacktrace-build && ../libbacktrace/configure CC="$(CC)" --enable-static=yes --enable-shared=no --libdir=`pwd`/.. && $(MAKE)
	$(MAKE) -C external/libbacktrace-build install-exec

distclean: external-distclean
clean: external-clean

external-clean:
	$(RM) $(EXTERNAL_LIBS)

external-distclean:
	make -C external/libsodium distclean || true
	$(RM) -rf external/libbacktrace-build
	$(RM) external/libsodium.la external/libsodium/src/libsodium/libsodium.la
	$(RM) external/libwally-core/src/secp256k1/libsecp256k1.la external/libwally-core/src/libwallycore.la
	cd external/libwally-core && tools/cleanup.sh
