# Included for one dir up.

# Note that these actually #include everything they need, except ccan/.
# That allows for unit testing of statics, and special effects.

BITCOIN_TEST_SRC := $(wildcard bitcoin/test/run-*.c)
BITCOIN_TEST_OBJS := $(BITCOIN_TEST_SRC:.c=.o)
BITCOIN_TEST_PROGRAMS := $(BITCOIN_TEST_OBJS:.o=)

$(BITCOIN_TEST_PROGRAMS): $(CCAN_OBJS)

$(BITCOIN_TEST_OBJS): $(CCAN_HEADERS) $(BITCOIN_HEADERS) $(BITCOIN_SRC)

check: bitcoin-tests

check-source-bolt: $(BITCOIN_SRC:%=bolt-check/%) $(BITCOIN_HEADERS:%=bolt-check/%)

check-whitespace: $(BITCOIN_SRC:%=check-whitespace/%) $(BITCOIN_HEADERS:%=check-whitespace/%) check-whitespace/bitcoin/Makefile

bitcoin-tests: $(BITCOIN_TEST_PROGRAMS:%=unittest/%)

LIBBASE58_HEADERS := bitcoin/libbase58/libbase58.h

LIBBASE58_SRC := bitcoin/libbase58/base58.c

# Can't be inside submodule, as that makes git think it's dirty.
LIBBASE58_OBJS := bitcoin/libbase58.o

# Wildcards trick from http://stackoverflow.com/questions/2973445/gnu-makefile-rule-generating-a-few-targets-from-a-single-source-file doesn't work with no dependency, so instead make one depend on the other:
$(LIBBASE58_SRC): $(LIBBASE58_HEADERS)

$(LIBBASE58_HEADERS):
	git submodule update bitcoin/libbase58/ || true
	[ -f $@ ] || git submodule update --init bitcoin/libbase58/

bitcoin/libbase58.o: bitcoin/libbase58/base58.c
	$(COMPILE.c) $(OUTPUT_OPTION) $<
