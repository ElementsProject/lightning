#! /usr/bin/make

# Designed to be run one level up
wallet-wrongdir:
	$(MAKE) -C .. lightningd-all

check: wallet/tests

WALLET_LIB_SRC :=		\
	wallet/db.c		\
	wallet/wallet.c		\
	wallet/walletrpc.c

WALLET_LIB_OBJS := $(WALLET_LIB_SRC:.c=.o)
WALLET_LIB_HEADERS := $(WALLET_LIB_SRC:.c=.h)

$(WALLET_LIB_OBJS): $(CCAN_OBJS)

WALLET_TEST_SRC := $(wildcard wallet/*_tests.c)
WALLET_TEST_OBJS := $(WALLET_TEST_SRC:.c=.o)
WALLET_TEST_PROGRAMS := $(WALLET_TEST_OBJS:.o=)

$(WALLET_TEST_OBJS): $(WALLET_LIB_OBJS)

$(WALLET_TEST_PROGRAMS): $(BITCOIN_OBJS) $(CCAN_OBJS)  $(LIBBASE58_OBJS) daemon/log.o type_to_string.o daemon/pseudorand.o utils.o libwallycore.a libsecp256k1.a libsodium.a

$(WALLET_TEST_OBJS): $(CCAN_HEADERS)
wallet/tests: $(WALLET_TEST_PROGRAMS:%=unittest/%)

check-whitespace: $(WALLET_LIB_SRC:%=check-whitespace/%) $(WALLET_LIB_HEADERS:%=check-whitespace/%)

check-makefile: check-lightningd-makefile

clean: wallet-clean

wallet-clean:
	$(RM) $(WALLET_LIB_OBJS)
