# Note that these actually #include everything they need, except ccan/ and bitcoin/.
# That allows for unit testing of statics, and special effects.
CHANNELD_TEST_SRC := $(wildcard channeld/test/run-*.c)
CHANNELD_TEST_OBJS := $(CHANNELD_TEST_SRC:.c=.o)
CHANNELD_TEST_PROGRAMS := $(CHANNELD_TEST_OBJS:.o=)

ALL_C_SOURCES += $(CHANNELD_TEST_SRC)
ALL_TEST_PROGRAMS += $(CHANNELD_TEST_PROGRAMS)

# run-full_channel.o needs a special version of some common files!
$(filter-out channeld/test/run-full_channel,$(CHANNELD_TEST_PROGRAMS)): libcommon.a

channeld/test/run-full_channel:			\
	$(BITCOIN_OBJS)				\
	wire/towire.o				\
	wire/fromwire.o				\
	common/amount.o				\
	common/autodata.o			\
	common/channel_type.o			\
	common/daemon_conn.o			\
	common/features.o			\
	common/htlc_state.o			\
	common/htlc_trim.o			\
	common/htlc_tx.o				\
	common/initial_commit_tx.o		\
	common/key_derive.o			\
	common/msg_queue.o			\
	common/permute_tx.o			\
	common/pseudorand.o			\
	common/randbytes.o			\
	common/setup.o				\
	common/utils.o

# run-splice_fundee_msat includes channeld.c itself (so we can see statics),
# like the hsmd tests: do not also link channeld.o.  The sibling channeld
# objects, hsmd client objects and libcommon.a satisfy the rest.
channeld/test/run-splice_fundee_msat:			\
	$(filter-out channeld/channeld.o,$(CHANNELD_OBJS))	\
	$(HSMD_CLIENT_OBJS)				\
	$(BITCOIN_OBJS)					\
	wire/towire.o					\
	wire/fromwire.o

$(CHANNELD_TEST_OBJS): $(CHANNELD_HEADERS) $(CHANNELD_SRC) channeld/test/Makefile

check-units: $(CHANNELD_TEST_PROGRAMS:%=unittest/%)
