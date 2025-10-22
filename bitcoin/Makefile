# Included for one dir up.

BITCOIN_SRC :=					\
	bitcoin/base58.c			\
	bitcoin/block.c				\
	bitcoin/chainparams.c			\
	bitcoin/feerate.c			\
	bitcoin/locktime.c			\
	bitcoin/preimage.c			\
	bitcoin/privkey.c			\
	bitcoin/psbt.c				\
	bitcoin/pubkey.c			\
	bitcoin/script.c			\
	bitcoin/shadouble.c			\
	bitcoin/short_channel_id.c		\
	bitcoin/signature.c			\
	bitcoin/tx.c				\
	bitcoin/tx_parts.c			\
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
	bitcoin/psbt.h				\
	bitcoin/pubkey.h			\
	bitcoin/script.h			\
	bitcoin/shadouble.h			\
	bitcoin/short_channel_id.h		\
	bitcoin/signature.h			\
	bitcoin/tx.h				\
	bitcoin/tx_parts.h			\
	bitcoin/varint.h

ALL_C_HEADERS += $(BITCOIN_HEADERS)
ALL_C_SOURCES += $(BITCOIN_SRC)

check-makefile: check-bitcoin-makefile

check-bitcoin-makefile:
	@MISSING="$(filter-out $(BITCOIN_HEADERS), $(wildcard bitcoin/*.h))"; \
	EXTRA="$(filter-out $(wildcard bitcoin/*.h), $(BITCOIN_HEADERS))"; \
	if [ -n "$$MISSING" ]; then \
		echo "BITCOIN_HEADERS missing: $$MISSING"; \
		exit 1; \
	fi; \
	if [ -n "$$EXTRA" ]; then \
		echo "BITCOIN_HEADERS has non-existent: $$EXTRA"; \
		exit 1; \
	fi

check-whitespace: check-whitespace/bitcoin/Makefile

clean: bitcoin-clean

bitcoin-clean:
	$(RM) $(BITCOIN_OBJS) $(BITCOIN_TEST_PROGRAMS) $(BITCOIN_TEST_OBJS)

include bitcoin/test/Makefile
