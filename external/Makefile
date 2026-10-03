SUBMODULES =					\
	external/libwally-core			\
	external/gheap				\
	external/jsmn				\
	external/libbacktrace

TOP := ../..
ifdef BUILD
CROSSCOMPILE_OPTS := --host="$(HOST)" --build="$(BUILD)"
endif

LIBWALLY_HEADERS := external/libwally-core/include/wally_bip32.h		\
			external/libwally-core/include/wally_core.h	\
			external/libwally-core/include/wally_psbt.h	\
			external/libwally-core/include/wally_crypto.h
LIBSECP_HEADERS := external/libwally-core/src/secp256k1/include/secp256k1_ecdh.h		\
		external/libwally-core/src/secp256k1/include/secp256k1_recovery.h		\
		external/libwally-core/src/secp256k1/include/secp256k1.h
JSMN_HEADERS := external/jsmn/jsmn.h
GHEAP_HEADERS := external/gheap/gheap.h
LIBBACKTRACE_HEADERS := external/libbacktrace/backtrace.h

EXTERNAL_HEADERS := $(LIBWALLY_HEADERS) $(LIBSECP_HEADERS) $(JSMN_HEADERS) $(GHEAP_HEADERS) $(LIBBACKTRACE_HEADERS)
EXTERNAL_LIBS := $(addprefix $(BUILDDIR)/external/,libwallycore.a libsecp256k1.a libjsmn.a libbacktrace.a)

EXTERNAL_INCLUDE_FLAGS :=					\
	-I external/libwally-core/include/			\
	-I external/libwally-core/src/secp256k1/include/	\
	-I external/jsmn/					\
	-I external/libbacktrace/				\
	-I external/gheap/					\
	-I $(BUILDDIR)/external/libbacktrace-build

LDLIBS += $(SODIUM_LDLIBS)

ifeq ($(HAVE_ZLIB),1)
LDLIBS += -lz
endif

EXTERNAL_LDLIBS := -L$(BUILDDIR)/external $(patsubst lib%.a,-l%,$(notdir $(EXTERNAL_LIBS)))

.PHONY: submodcheck

submodcheck: $(FORCE)
ifneq ($(VERSION),)
	@tools/refresh-submodules.sh $(SUBMODULES)
	@cd external/libwally-core && ../../tools/refresh-submodules.sh src/secp256k1
endif

$(EXTERNAL_HEADERS): submodcheck

# libsecp included in libwally.
# Wildcards here are magic.  See http://stackoverflow.com/questions/2973445/gnu-makefile-rule-generating-a-few-targets-from-a-single-source-file
$(BUILDDIR)/external/libsecp256k1.% $(BUILDDIR)/external/libwallycore.%: $(BUILDDIR)/external/libwally-core-build/src/secp256k1/libsecp256k1.la $(BUILDDIR)/external/libwally-core-build/src/libwallycore.la
	$(MAKE) -C $(BUILDDIR)/external/libwally-core-build DESTDIR=$$(pwd)/$(BUILDDIR)/external install-exec

# Build libwally-core.
ifeq ($(DEBUGBUILD),1)
WALLY_OPTS=--enable-debug
endif

.INTERMEDIATE: $(addprefix $(BUILDDIR)/external/libwally-core-build/src/,secp256k1/libsecp256k1.la libwallycore.la)

$(BUILDDIR)/external/libwally-core-build/src/libwallycore.% $(BUILDDIR)/external/libwally-core-build/src/secp256k1/libsecp256k1.%: $(LIBWALLY_HEADERS) $(LIBSECP_HEADERS)
	cd external/libwally-core && ./tools/autogen.sh
	$(MKDIR_P) $(BUILDDIR)/external/libwally-core-build
	cd $(BUILDDIR)/external/libwally-core-build \
	&& PYTHON_VERSION=3 CFLAGS="-std=c99 $(FUZZFLAGS)" LDFLAGS="$(FUZZFLAGS)" ${TOP}/libwally-core/configure CC="$(CC)" \
		--enable-static=yes \
		$(CROSSCOMPILE_OPTS) \
		--enable-shared=no \
		--prefix=/ \
		--libdir=/ \
		$(WALLY_OPTS) \
	&& $(MAKE)

# If we tell Make that the above builds both, it runs it twice in
# parallel.  So we lie :(
external/jsmn/jsmn.c: external/jsmn/jsmn.h
	[ -f $@ ]

$(BUILDDIR)/external/jsmn-build/jsmn.o: external/jsmn/jsmn.c Makefile
	@mkdir -p $(@D)
	$(COMPILE.c) -DJSMN_STRICT=1 -o $@ $<

$(BUILDDIR)/external/libjsmn.a: $(BUILDDIR)/external/jsmn-build/jsmn.o
	$(AR) rc $@ $<

.INTERMEDIATE: $(BUILDDIR)/external/jsmn-build/jsmn.o

# Need separate build dir: changes inside submodule make git think it's dirty.
$(BUILDDIR)/external/libbacktrace.a: external/libbacktrace/backtrace.h
	mkdir -p $(BUILDDIR)/external/libbacktrace-build
	cd $(BUILDDIR)/external/libbacktrace-build && $(TOP)/libbacktrace/configure CC="$(CC)" --enable-static=yes $(CROSSCOMPILE_OPTS) --enable-shared=no --prefix=/ --libdir=/ && $(MAKE)
	$(MAKE) -C $(BUILDDIR)/external/libbacktrace-build DESTDIR=$$(pwd)/$(BUILDDIR)/external install-exec

distclean: external-distclean
clean: external-clean

external-clean:
	$(RM) $(EXTERNAL_LIBS)
	$(RM) -r $(BUILDDIR)/external

external-distclean:
	$(RM) -r $(addprefix $(BUILDDIR)/external/,libbacktrace-build libsodium-build libwally-core-build jsmn-build)
	$(RM) -r `git status --ignored --porcelain external/libwally-core | grep '^!! ' | cut -c3-`
