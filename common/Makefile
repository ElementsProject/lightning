COMMON_SRC :=					\
	common/close_tx.c			\
	common/derive_basepoints.c		\
	common/funding_tx.c			\
	common/htlc_tx.c			\
	common/initial_channel.c		\
	common/initial_commit_tx.c		\
	common/permute_tx.c			\
	common/type_to_string.c			\
	common/utils.c				\
	common/version.c			\
	common/withdraw_tx.c

COMMON_HEADERS := $(COMMON_SRC:.c=.h) common/overflows.h
COMMON_OBJS := $(COMMON_SRC:.c=.o)

check-makefile: check-common-makefile

check-common-makefile:
	@if [ x"`LC_ALL=C ls common/*.h | grep -v ^gen_`" != x"`echo $(COMMON_HEADERS) | tr ' ' '\n' | LC_ALL=C sort`" ]; then echo COMMON_HEADERS incorrect; exit 1; fi

check-source-bolt: $(COMMON_SRC:%=bolt-check/%) $(COMMON_HEADERS:%=bolt-check/%)
check-whitespace: $(COMMON_SRC:%=check-whitespace/%) $(COMMON_HEADERS:%=check-whitespace/%)

check-source: $(COMMON_SRC:%=check-src-include-order/%)			\
	$(COMMON_HEADERS:%=check-hdr-include-order/%)
