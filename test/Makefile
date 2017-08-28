TEST_PROGRAMS :=				\
	test/test_protocol

TEST_COMMON_OBJS :=					\
	common/utils.o

$(TEST_PROGRAMS): $(TEST_COMMON_OBJS) $(BITCOIN_OBJS) $(WIRE_OBJS)

ALL_TEST_PROGRAMS += $(TEST_PROGRAMS)
ALL_OBJS += $(TEST_PROGRAMS:=.o)

test-protocol: test/test_protocol
	@set -e; TMP=`mktemp`; for f in test/commits/*.script; do if ! $(VALGRIND) test/test_protocol < $$f > $$TMP; then echo "test/test_protocol < $$f FAILED" >&2; exit 1; fi; diff -u $$TMP $$f.expected; done; rm $$TMP

check: test-protocol
clean: test-clean

test-clean:
	$(RM) $(TEST_PROGRAMS) $(TEST_PROGRAMS:=.o)
