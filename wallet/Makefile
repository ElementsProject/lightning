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

WALLET_TEST_COMMON_OBJS :=			\
	lightningd/log.o			\
	common/type_to_string.o			\
	common/pseudorand.o			\
	common/utils.o

WALLET_TEST_SRC := $(wildcard wallet/*_tests.c)
WALLET_TEST_OBJS := $(WALLET_TEST_SRC:.c=.o)
WALLET_TEST_PROGRAMS := $(WALLET_TEST_OBJS:.o=)

# Make sure these depend on everything.
ALL_TEST_PROGRAMS += $(WALLET_TEST_PROGRAMS)
ALL_OBJS += $(WALLET_LIB_OBJS) $(WALLET_TEST_OBJS)

$(WALLET_TEST_PROGRAMS): $(BITCOIN_OBJS) $(WALLET_TEST_COMMON_OBJS)
$(WALLET_TEST_OBJS): $(WALLET_LIB_HEADERS)

wallet/tests: $(WALLET_TEST_PROGRAMS:%=unittest/%)

check-whitespace: $(WALLET_LIB_SRC:%=check-whitespace/%) $(WALLET_LIB_HEADERS:%=check-whitespace/%)

clean: wallet-clean

wallet-clean:
	$(RM) $(WALLET_LIB_OBJS)
