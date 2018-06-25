# Included for one dir up.

BITCOIN_SRC :=					\
	bitcoin/base58.c			\
	bitcoin/block.c				\
	bitcoin/chainparams.c			\
	bitcoin/locktime.c			\
	bitcoin/pubkey.c			\
	bitcoin/pullpush.c			\
	bitcoin/script.c			\
	bitcoin/shadouble.c			\
	bitcoin/short_channel_id.c		\
	bitcoin/signature.c			\
	bitcoin/tx.c				\
	bitcoin/varint.c

BITCOIN_OBJS := $(BITCOIN_SRC:.c=.o)

BITCOIN_HEADERS := bitcoin/address.h		\
	bitcoin/base58.h			\
	bitcoin/block.h				\
	bitcoin/chainparams.h			\
	bitcoin/feerate.h			\
	bitcoin/locktime.h			\
	bitcoin/preimage.h			\
	bitcoin/privkey.h			\
	bitcoin/pubkey.h			\
	bitcoin/pullpush.h			\
	bitcoin/script.h			\
	bitcoin/shadouble.h			\
	bitcoin/short_channel_id.h		\
	bitcoin/signature.h			\
	bitcoin/tx.h				\
	bitcoin/varint.h

check-source: $(BITCOIN_SRC:%=check-src-include-order/%)		\
	$(BITCOIN_HEADERS:%=check-hdr-include-order/%)

# Bitcoin objects depends on bitcoin/ external/ and ccan
$(BITCOIN_OBJS): $(CCAN_HEADERS) $(BITCOIN_HEADERS) $(EXTERNAL_HEADERS)

check-source-bolt: $(BITCOIN_SRC:%=bolt-check/%) $(BITCOIN_HEADERS:%=bolt-check/%)

check-makefile: check-bitcoin-makefile

check-bitcoin-makefile:
	@if [ "`echo bitcoin/*.h`" != "$(BITCOIN_HEADERS)" ]; then echo BITCOIN_HEADERS incorrect; exit 1; fi

check-whitespace: $(BITCOIN_SRC:%=check-whitespace/%) $(BITCOIN_HEADERS:%=check-whitespace/%) check-whitespace/bitcoin/Makefile

clean: bitcoin-clean

bitcoin-clean:
	$(RM) $(BITCOIN_OBJS) $(BITCOIN_TEST_PROGRAMS) $(BITCOIN_TEST_OBJS)

include bitcoin/test/Makefile
